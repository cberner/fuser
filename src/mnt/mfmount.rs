//! macFUSE's FSKit backend, reached through its MFMount framework.
//!
//! FSKit volumes have no FUSE device fd: macFUSE delivers the same FUSE messages over an
//! `MFChannelRef` instead, so a session using this backend receives and sends through the
//! channel rather than read(2)/writev(2). The framework is loaded at runtime, so that fuser
//! still loads with macFUSE releases that do not ship it.

use std::ffi::CStr;
use std::ffi::CString;
use std::ffi::c_char;
use std::ffi::c_void;
use std::io;
use std::io::IoSlice;
use std::ptr::NonNull;
use std::sync::OnceLock;

use nix::errno::Errno;

const FRAMEWORK_PATH: &CStr =
    c"/Library/Filesystems/macfuse.fs/Contents/Frameworks/MFMount.framework/MFMount";

/// The mount option that selects macFUSE's FSKit backend
pub(crate) const FSKIT_BACKEND_OPTION: &str = "backend=fskit";

type MFTypeRef = *mut c_void;

type RetainFn = unsafe extern "C" fn(MFTypeRef) -> MFTypeRef;
type ReleaseFn = unsafe extern "C" fn(MFTypeRef);
type GetBodyBuffersFn = unsafe extern "C" fn(MFTypeRef, *mut *const libc::iovec) -> isize;
type ChannelCreateFn = unsafe extern "C" fn() -> MFTypeRef;
type InterruptFn = unsafe extern "C" fn(MFTypeRef) -> bool;
type WaitForNextMessageFn = unsafe extern "C" fn(MFTypeRef, i32) -> i32;
type CopyNextMessageFn = unsafe extern "C" fn(MFTypeRef) -> MFTypeRef;
type SendMessageFn = unsafe extern "C" fn(MFTypeRef, *const libc::iovec, usize) -> isize;
type ChannelCloseFn = unsafe extern "C" fn(MFTypeRef) -> bool;
type MountFn = unsafe extern "C" fn(MFTypeRef, *const c_char, *const c_char, bool) -> i32;

struct Api {
    retain: RetainFn,
    release: ReleaseFn,
    message_get_body_buffers: GetBodyBuffersFn,
    channel_create: ChannelCreateFn,
    channel_interrupt: InterruptFn,
    channel_wait_for_next_message: WaitForNextMessageFn,
    channel_copy_next_message: CopyNextMessageFn,
    channel_send_message: SendMessageFn,
    channel_close: ChannelCloseFn,
    mount: MountFn,
}

fn api() -> io::Result<&'static Api> {
    static API: OnceLock<Result<Api, String>> = OnceLock::new();
    API.get_or_init(load)
        .as_ref()
        .map_err(|message| io::Error::new(io::ErrorKind::Unsupported, message.clone()))
}

fn load() -> Result<Api, String> {
    // SAFETY: the path is NUL-terminated, and the handle is never closed, so that the
    // resolved function pointers stay valid for the life of the process
    let handle =
        unsafe { libc::dlopen(FRAMEWORK_PATH.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    if handle.is_null() {
        return Err(format!(
            "{FRAMEWORK_PATH:?} could not be loaded ({}); \
             the FSKit backend needs macFUSE 5.3.3 or later",
            dl_error()
        ));
    }
    macro_rules! symbol {
        ($name:literal, $ty:ty) => {{
            let name = CString::new($name).unwrap();
            // SAFETY: handle is a valid dlopen handle and name is NUL-terminated
            let sym = unsafe { libc::dlsym(handle, name.as_ptr()) };
            if sym.is_null() {
                return Err(format!("MFMount has no symbol {}: {}", $name, dl_error()));
            }
            // SAFETY: the signature matches the declaration in MFMount.h
            unsafe { std::mem::transmute::<*mut c_void, $ty>(sym) }
        }};
    }
    Ok(Api {
        retain: symbol!("MFRetain", RetainFn),
        release: symbol!("MFRelease", ReleaseFn),
        message_get_body_buffers: symbol!("MFMessageGetBodyBuffers", GetBodyBuffersFn),
        channel_create: symbol!("MFChannelCreate", ChannelCreateFn),
        channel_interrupt: symbol!("MFChannelInterrupt", InterruptFn),
        channel_wait_for_next_message: symbol!("MFChannelWaitForNextMessage", WaitForNextMessageFn),
        channel_copy_next_message: symbol!("MFChannelCopyNextMessage", CopyNextMessageFn),
        channel_send_message: symbol!("MFChannelSendMessage", SendMessageFn),
        channel_close: symbol!("MFChannelClose", ChannelCloseFn),
        mount: symbol!("MFMount", MountFn),
    })
}

fn dl_error() -> String {
    // SAFETY: dlerror returns NULL or a NUL-terminated string
    let err = unsafe { libc::dlerror() };
    if err.is_null() {
        "unknown error".to_owned()
    } else {
        unsafe { CStr::from_ptr(err) }
            .to_string_lossy()
            .into_owned()
    }
}

/// A mounted volume's channel. It must outlive the mount, and is closed on drop.
#[derive(Debug)]
pub(crate) struct MfChannel {
    channel: NonNull<c_void>,
}

// SAFETY: MFMount channels may be used from several threads at once (MFMount.h)
unsafe impl Send for MfChannel {}
unsafe impl Sync for MfChannel {}

impl MfChannel {
    /// Mount a volume at `mountpoint` using the FSKit backend.
    ///
    /// MFMount() does not return until the volume has answered FUSE_INIT, so it runs on a
    /// thread of its own. This returns once the first request has arrived, or with the
    /// error if the mount failed before then.
    pub(crate) fn mount(mountpoint: &CStr, options: &str) -> io::Result<MfChannel> {
        let api = api()?;
        let options = CString::new(options)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in mount options"))?;
        // SAFETY: MFChannelCreate has no preconditions
        let channel = NonNull::new(unsafe { (api.channel_create)() })
            .ok_or_else(|| io::Error::other("MFChannelCreate() failed"))?;
        let channel = MfChannel { channel };

        // The mount thread holds its own reference, as the session may end before MFMount()
        // returns
        // SAFETY: the channel is valid
        let retained = SendPtr(unsafe { (api.retain)(channel.channel.as_ptr()) });
        let mountpoint = mountpoint.to_owned();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::Builder::new()
            .name("fuser-mfmount".to_owned())
            .spawn(move || {
                let retained = retained;
                log::debug!("MFMount({mountpoint:?}, {options:?})");
                // quiet: report failures through the result rather than dialogs
                // SAFETY: all pointers are valid for the duration of the call
                let result =
                    unsafe { (api.mount)(retained.0, mountpoint.as_ptr(), options.as_ptr(), true) };
                let result = mount_result(result);
                if let Err(err) = &result {
                    log::error!("{err}");
                    // Wake the wait below, or a session waiting for requests
                    // SAFETY: the channel is valid
                    unsafe { (api.channel_interrupt)(retained.0) };
                } else {
                    log::debug!("MFMount() succeeded");
                }
                let _ = tx.send(result);
                // SAFETY: balances the retain above
                unsafe { (api.release)(retained.0) };
            })?;

        loop {
            match rx.try_recv() {
                Ok(result) => return result.map(|()| channel),
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    return Err(io::Error::other("MFMount() thread exited"));
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
            // SAFETY: the channel is valid
            let ready =
                unsafe { (api.channel_wait_for_next_message)(channel.channel.as_ptr(), 100) };
            if ready > 0 {
                return Ok(channel);
            }
            if ready < 0 && Errno::last() != Errno::EINTR {
                return Err(io::Error::last_os_error());
            }
        }
    }

    /// Receive one message into `buffer`, as read(2) does on a FUSE device
    pub(crate) fn receive(&self, buffer: &mut [u8]) -> nix::Result<usize> {
        let api = api().map_err(|_| Errno::ENODEV)?;
        // SAFETY: the channel is valid; the message is released below
        let message = unsafe { (api.channel_copy_next_message)(self.channel.as_ptr()) };
        if message.is_null() {
            return Err(Errno::last());
        }
        let mut iovecs: *const libc::iovec = std::ptr::null();
        // SAFETY: message is valid; the buffers are borrowed from it until it is released
        let count = unsafe { (api.message_get_body_buffers)(message, &mut iovecs) };
        let result = if count <= 0 {
            Err(Errno::last())
        } else {
            // SAFETY: MFMessageGetBodyBuffers returned count valid entries
            let iovecs = unsafe { std::slice::from_raw_parts(iovecs, count as usize) };
            let mut size = 0;
            let mut result = Ok(());
            for iov in iovecs {
                let Some(dest) = buffer.get_mut(size..size + iov.iov_len) else {
                    result = Err(Errno::EMSGSIZE);
                    break;
                };
                // SAFETY: the body buffer holds iov_len readable bytes
                dest.copy_from_slice(unsafe {
                    std::slice::from_raw_parts(iov.iov_base as *const u8, iov.iov_len)
                });
                size += iov.iov_len;
            }
            result.map(|()| size)
        };
        // SAFETY: message was returned by a Copy function and is released once
        unsafe { (api.release)(message) };
        result
    }

    /// Send one message, as writev(2) does on a FUSE device
    pub(crate) fn send(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        let api = api()?;
        // SAFETY: IoSlice is ABI compatible with iovec, and the channel is valid
        let rc = unsafe {
            (api.channel_send_message)(
                self.channel.as_ptr(),
                bufs.as_ptr().cast::<libc::iovec>(),
                bufs.len(),
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(rc as usize)
    }
}

struct SendPtr(MFTypeRef);

// SAFETY: MFMount objects may be used from any thread
unsafe impl Send for SendPtr {}

fn mount_result(result: i32) -> io::Result<()> {
    let message = match result {
        0 => return Ok(()),
        1 => "this version of macOS is not supported by macFUSE's FSKit backend",
        2 => "macFUSE's helper tools could not be installed",
        3 => "macFUSE's file system extension could not be found",
        4 => {
            "macFUSE's file system extension needs to be enabled in System Settings > \
             General > Login Items & Extensions > File System Extensions"
        }
        5 => "the mount point could not be created",
        _ => {
            let err = io::Error::last_os_error();
            return Err(io::Error::new(
                err.kind(),
                format!("MFMount() failed: {err}"),
            ));
        }
    };
    Err(io::Error::other(format!("MFMount() failed: {message}")))
}

impl Drop for MfChannel {
    fn drop(&mut self) {
        if let Ok(api) = api() {
            // SAFETY: the channel is valid, closed once and released once
            unsafe {
                (api.channel_close)(self.channel.as_ptr());
                (api.release)(self.channel.as_ptr());
            }
        }
    }
}

/// Whether `options` select the FSKit backend
pub(crate) fn wants_fskit(options: &[crate::MountOption]) -> bool {
    options
        .iter()
        .any(|o| matches!(o, crate::MountOption::CUSTOM(s) if s == FSKIT_BACKEND_OPTION))
}
