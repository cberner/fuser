use fuser::{Filesystem, MountOption};
use std::env;

struct NullFS;

impl Filesystem for NullFS {}

fn main() {
    env_logger::init();
    let mountpoint = env::args_os().nth(1).unwrap();
    fuser::mount2(NullFS, mountpoint, &[MountOption::AutoUnmount]).unwrap();
}

#[cfg(test)]
mod test {
    use fuser::{Filesystem, RequestMeta, Errno};
    use std::ffi::OsString;

    fn dummy_meta() -> RequestMeta {
        RequestMeta { unique: 0, uid: 1000, gid: 1000, pid: 2000 }
    }

    #[test]
    fn test_unsupported() {
        let mut nullfs = super::NullFS {};
        let req = dummy_meta();

        // Test lookup
        let lookup_result = nullfs.lookup(req, 1, OsString::from("nonexistent"));
        assert!(lookup_result.is_err(), "Lookup should fail for NullFS");
        if let Err(e) = lookup_result {
            assert_eq!(e, Errno::ENOSYS, "Lookup should return ENOSYS");
        }

        // Test getattr
        let getattr_result = nullfs.getattr(req, 1, None);
        assert!(getattr_result.is_err(), "Getattr should fail for NullFS");
        if let Err(e) = getattr_result {
            assert_eq!(e, Errno::ENOSYS, "Getattr should return ENOSYS");
        }

        // Test readdir
        let readdir_result = nullfs.readdir(req, 1, 0, 0, 4096);
        assert!(readdir_result.is_err(), "Readdir should fail for NullFS");
        if let Err(e) = readdir_result {
            assert_eq!(e, Errno::ENOSYS, "Readdir should return ENOSYS");
        }

        // Test open
        let open_result = nullfs.open(req, 1, 0);
        assert!(open_result.is_err(), "Open should fail for NullFS");
        if let Err(e) = open_result {
            assert_eq!(e, Errno::ENOSYS, "Open should return ENOSYS");
        }

        // Test create
        let create_result = nullfs.create(req, 1, OsString::from("testfile"), 0o644, 0, 0);
        assert!(create_result.is_err(), "Create should fail for NullFS");
        if let Err(e) = create_result {
            assert_eq!(e, Errno::ENOSYS, "Create should return ENOSYS");
        }
    }
}
