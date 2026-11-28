//! XDR (RFC 4506), as far as NFSv3 and NFSv4.1 need it: big-endian 32 and 64 bit integers, booleans, and
//! opaque data padded to 4 bytes.

/// Arguments that do not decode: answered with `GARBAGE_ARGS`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Garbage;

pub(crate) type Result<T> = std::result::Result<T, Garbage>;

/// Decodes from a buffer
#[derive(Debug)]
pub(crate) struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self(buf)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        if len > self.0.len() {
            return Err(Garbage);
        }
        let (head, rest) = self.0.split_at(len);
        self.0 = rest;
        Ok(head)
    }

    pub(crate) fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("4 bytes"),
        ))
    }

    pub(crate) fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().expect("8 bytes"),
        ))
    }

    pub(crate) fn bool(&mut self) -> Result<bool> {
        Ok(self.u32()? != 0)
    }

    /// Fixed-length opaque data
    pub(crate) fn fixed(&mut self, len: usize) -> Result<&'a [u8]> {
        let data = self.take(len)?;
        self.take(pad(len))?;
        Ok(data)
    }

    /// Variable-length opaque data, or a string
    pub(crate) fn opaque(&mut self) -> Result<&'a [u8]> {
        let len = self.u32()? as usize;
        self.fixed(len)
    }

    /// What has not been read
    pub(crate) fn rest(&self) -> &'a [u8] {
        self.0
    }
}

/// Encodes onto a buffer
pub(crate) trait Writer {
    fn put_u32(&mut self, value: u32);
    fn put_u64(&mut self, value: u64);
    fn put_bool(&mut self, value: bool);
    /// Fixed-length opaque data
    fn put_fixed(&mut self, data: &[u8]);
    /// Variable-length opaque data, or a string
    fn put_opaque(&mut self, data: &[u8]);
}

impl Writer for Vec<u8> {
    fn put_u32(&mut self, value: u32) {
        self.extend_from_slice(&value.to_be_bytes());
    }

    fn put_u64(&mut self, value: u64) {
        self.extend_from_slice(&value.to_be_bytes());
    }

    fn put_bool(&mut self, value: bool) {
        self.put_u32(value.into());
    }

    fn put_fixed(&mut self, data: &[u8]) {
        self.extend_from_slice(data);
        self.extend_from_slice(&[0; 3][..pad(data.len())]);
    }

    fn put_opaque(&mut self, data: &[u8]) {
        // Callers bound what they send far below 4 GiB
        self.put_u32(data.len() as u32);
        self.put_fixed(data);
    }
}

/// The padding after `len` bytes of opaque data
fn pad(len: usize) -> usize {
    (4 - len % 4) % 4
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn round_trip() {
        let mut buf = Vec::new();
        buf.put_u32(7);
        buf.put_u64(u64::MAX - 1);
        buf.put_bool(true);
        buf.put_opaque(b"hello");
        buf.put_fixed(b"ab");
        buf.put_opaque(b"");
        assert_eq!(buf.len(), 4 + 8 + 4 + (4 + 8) + 4 + 4);
        let mut r = Reader::new(&buf);
        assert_eq!(r.u32(), Ok(7));
        assert_eq!(r.u64(), Ok(u64::MAX - 1));
        assert_eq!(r.bool(), Ok(true));
        assert_eq!(r.opaque(), Ok(&b"hello"[..]));
        assert_eq!(r.fixed(2), Ok(&b"ab"[..]));
        assert_eq!(r.opaque(), Ok(&b""[..]));
        assert_eq!(r.u32(), Err(Garbage));
    }

    #[test]
    fn lengths_beyond_the_data_are_garbage() {
        let mut buf = Vec::new();
        buf.put_u32(100);
        buf.extend_from_slice(b"short");
        assert_eq!(Reader::new(&buf).opaque(), Err(Garbage));
    }
}
