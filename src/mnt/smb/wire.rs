//! Little-endian fields, as SMB 2 and NTLM lay them out, and the UTF-16 their names are in

pub(crate) fn bytes_at(data: &[u8], at: usize, len: usize) -> Option<&[u8]> {
    data.get(at..at.checked_add(len)?)
}

pub(crate) fn u8_at(data: &[u8], at: usize) -> Option<u8> {
    data.get(at).copied()
}

pub(crate) fn u16_at(data: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes_at(data, at, 2)?.try_into().ok()?))
}

pub(crate) fn u32_at(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes_at(data, at, 4)?.try_into().ok()?))
}

pub(crate) fn u64_at(data: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes_at(data, at, 8)?.try_into().ok()?))
}

/// Appends little-endian fields
pub(crate) trait Put {
    fn put_u8(&mut self, value: u8);
    fn put_u16(&mut self, value: u16);
    fn put_u32(&mut self, value: u32);
    fn put_u64(&mut self, value: u64);
    /// Overwrites four bytes at `at`
    fn set_u32(&mut self, at: usize, value: u32);
}

impl Put for Vec<u8> {
    fn put_u8(&mut self, value: u8) {
        self.push(value);
    }

    fn put_u16(&mut self, value: u16) {
        self.extend_from_slice(&value.to_le_bytes());
    }

    fn put_u32(&mut self, value: u32) {
        self.extend_from_slice(&value.to_le_bytes());
    }

    fn put_u64(&mut self, value: u64) {
        self.extend_from_slice(&value.to_le_bytes());
    }

    fn set_u32(&mut self, at: usize, value: u32) {
        self[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
}

pub(crate) fn utf16(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// None for an odd length or unpaired surrogates
pub(crate) fn from_utf16(data: &[u8]) -> Option<String> {
    if data.len() % 2 != 0 {
        return None;
    }
    let units: Vec<u16> = data
        .chunks(2)
        .map(|unit| u16::from_le_bytes([unit[0], unit[1]]))
        .collect();
    String::from_utf16(&units).ok()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn fields() {
        let mut buf = Vec::new();
        buf.put_u8(1);
        buf.put_u16(0x0302);
        buf.put_u32(0x0706_0504);
        buf.put_u64(u64::MAX);
        assert_eq!(&buf[..7], [1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(u16_at(&buf, 1), Some(0x0302));
        assert_eq!(u32_at(&buf, 3), Some(0x0706_0504));
        assert_eq!(u64_at(&buf, 7), Some(u64::MAX));
        assert_eq!(u64_at(&buf, 8), None);
        buf.set_u32(3, 9);
        assert_eq!(u32_at(&buf, 3), Some(9));
        assert_eq!(
            from_utf16(&utf16("dir\\caf\u{e9}")).unwrap(),
            "dir\\caf\u{e9}"
        );
        assert_eq!(from_utf16(b"a"), None);
    }
}
