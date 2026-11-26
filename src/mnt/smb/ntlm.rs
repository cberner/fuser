//! Logon: NTLMv2 (MS-NLMP), in SPNEGO (RFC 4178) as SMB clients wrap it, or bare.
//!
//! Only the one user of the share logs on, with its password; NTLMv1, anonymous and guest
//! logons are refused. Only what SMB 2 signing needs of NTLM is implemented: the session key,
//! and the SPNEGO mechListMIC for clients that negotiate NTLM signing.

use super::crypto::hmac_md5;
use super::crypto::md4;
use super::crypto::md5;
use super::crypto::rc4;
use super::wire::Put;
use super::wire::bytes_at;
use super::wire::from_utf16;
use super::wire::u16_at;
use super::wire::u32_at;
use super::wire::utf16;

const SPNEGO_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
const NTLMSSP_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];
const SIGNATURE: &[u8] = b"NTLMSSP\0";

const NEGOTIATE_UNICODE: u32 = 0x1;
const REQUEST_TARGET: u32 = 0x4;
const NEGOTIATE_SIGN: u32 = 0x10;
const NEGOTIATE_SEAL: u32 = 0x20;
const NEGOTIATE_NTLM: u32 = 0x200;
const NEGOTIATE_ALWAYS_SIGN: u32 = 0x8000;
const TARGET_TYPE_SERVER: u32 = 0x2_0000;
const EXTENDED_SESSION_SECURITY: u32 = 0x8_0000;
const NEGOTIATE_TARGET_INFO: u32 = 0x80_0000;
const NEGOTIATE_VERSION: u32 = 0x200_0000;
const NEGOTIATE_128: u32 = 0x2000_0000;
const NEGOTIATE_KEY_EXCH: u32 = 0x4000_0000;
const NEGOTIATE_56: u32 = 0x8000_0000;
/// What of the client's flags the CHALLENGE takes up. Not SEAL: nothing here is sealed
const ECHOED: u32 = NEGOTIATE_SIGN
    | NEGOTIATE_ALWAYS_SIGN
    | NEGOTIATE_VERSION
    | NEGOTIATE_128
    | NEGOTIATE_KEY_EXCH
    | NEGOTIATE_56;

/// The name the server gives in CHALLENGE
const TARGET: &str = "FUSER";

/// What a logon step comes to
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Step {
    /// Not done yet: answer with STATUS_MORE_PROCESSING_REQUIRED and this token
    Continue(Vec<u8>),
    /// Logged on: answer with this token
    Done {
        session_key: [u8; 16],
        token: Vec<u8>,
    },
}

/// One logon, over the SESSION_SETUP requests it takes
#[derive(Debug, Default)]
pub(crate) struct Logon {
    spnego: bool,
    /// The client's MechTypeList, as it encoded it, for the mechListMIC
    mech_types: Option<Vec<u8>>,
    negotiate: Vec<u8>,
    challenge: Vec<u8>,
    server_challenge: [u8; 8],
}

/// The SPNEGO token of the NEGOTIATE response: NTLM is the one mechanism on offer
pub(crate) fn negotiate_hint() -> Vec<u8> {
    let mech_types = der(0x30, &der(0x06, NTLMSSP_OID));
    let init = der(0x30, &der(0xa0, &mech_types));
    der(0x60, &[der(0x06, SPNEGO_OID), der(0xa0, &init)].concat())
}

impl Logon {
    /// Takes the client's next token. None refuses the logon
    pub(crate) fn step(
        &mut self,
        blob: &[u8],
        user: &str,
        nt_hash: &[u8; 16],
        server_challenge: [u8; 8],
        now: u64,
    ) -> Option<Step> {
        let (token, client_mic) = if blob.starts_with(SIGNATURE) {
            (Some(blob), None)
        } else {
            let spnego = parse_spnego(blob)?;
            self.spnego = true;
            if let Some(mech_types) = spnego.mech_types {
                if !lists_ntlm(mech_types) {
                    return None;
                }
                self.mech_types = Some(mech_types.to_vec());
            }
            // A token for another mechanism the client preferred is not one of ours
            (
                spnego.token.filter(|token| token.starts_with(SIGNATURE)),
                spnego.mic,
            )
        };
        let Some(token) = token else {
            // NTLM was not the client's first choice: select it, for its NEGOTIATE to follow
            return self
                .spnego
                .then(|| Step::Continue(neg_token_resp(1, true, None, None)));
        };
        match u32_at(token, 8)? {
            1 => {
                self.server_challenge = server_challenge;
                self.negotiate = token.to_vec();
                self.challenge = challenge(u32_at(token, 12)?, server_challenge, now);
                Some(Step::Continue(if self.spnego {
                    neg_token_resp(1, true, Some(&self.challenge), None)
                } else {
                    self.challenge.clone()
                }))
            }
            3 if !self.challenge.is_empty() => {
                let auth = self.authenticate(token, user, nt_hash)?;
                let token = if self.spnego {
                    let mic = self
                        .mech_types
                        .as_deref()
                        .filter(|_| auth.flags & NEGOTIATE_SIGN != 0)
                        .filter(|_| client_mic.is_some() || auth.had_mic)
                        .map(|mech_types| mech_list_mic(&auth, mech_types));
                    neg_token_resp(0, false, None, mic.as_deref())
                } else {
                    Vec::new()
                };
                Some(Step::Done {
                    session_key: auth.session_key,
                    token,
                })
            }
            _ => None,
        }
    }

    fn authenticate(&self, msg: &[u8], user: &str, nt_hash: &[u8; 16]) -> Option<Authenticated> {
        let field = |at: usize| {
            let len = u16_at(msg, at)? as usize;
            let offset = u32_at(msg, at + 4)? as usize;
            Some((offset + len, bytes_at(msg, offset, len)?))
        };
        let (nt_end, nt) = field(20)?;
        let (domain_end, domain) = field(28)?;
        let (user_end, name) = field(36)?;
        let (workstation_end, _) = field(44)?;
        let (key_end, encrypted_key) = field(52)?;
        let flags = u32_at(msg, 60)?;
        // NTLMv2 only: a proof and at least the fixed part of its blob
        if flags & NEGOTIATE_UNICODE == 0 || nt.len() < 16 + 28 {
            return None;
        }
        if !from_utf16(name)?.eq_ignore_ascii_case(user) {
            return None;
        }
        let response_key = response_key(nt_hash, name, domain)?;
        let (proof, blob) = nt.split_at(16);
        let expected = hmac_md5(&response_key, &[&self.server_challenge, blob]);
        if !constant_time_eq(proof, &expected) {
            return None;
        }
        let key_exchange_key = hmac_md5(&response_key, &[proof]);
        let unwrapped: Option<[u8; 16]> = (flags & NEGOTIATE_KEY_EXCH != 0)
            .then(|| rc4(&key_exchange_key, encrypted_key).try_into().ok())
            .flatten();
        // MS-NLMP 3.2.5.1.2: the random key only with SIGN or SEAL. macOS unwraps it without
        // either all the same, which only the MIC tells
        let (first, second) = match unwrapped {
            Some(key) if flags & (NEGOTIATE_SIGN | NEGOTIATE_SEAL) != 0 => (key, key_exchange_key),
            Some(key) => (key_exchange_key, key),
            None => (key_exchange_key, key_exchange_key),
        };
        let had_mic = has_mic(&blob[28..]);
        let mut session_key = first;
        if had_mic {
            // The message ends where its last field does; the MIC follows the version
            let end = [nt_end, domain_end, user_end, workstation_end, key_end, 88]
                .into_iter()
                .max()?;
            let mut zeroed = bytes_at(msg, 0, end)?.to_vec();
            let mic = zeroed[72..88].to_vec();
            zeroed[72..88].fill(0);
            let matches = |key: &[u8; 16]| {
                hmac_md5(key, &[&self.negotiate, &self.challenge, &zeroed])[..] == mic[..]
            };
            if matches(&second) && !matches(&first) {
                session_key = second;
            }
        }
        Some(Authenticated {
            session_key,
            flags,
            had_mic,
        })
    }
}

#[derive(Debug)]
struct Authenticated {
    session_key: [u8; 16],
    flags: u32,
    /// The AUTHENTICATE message carried an NTLM MIC
    had_mic: bool,
}

/// The NT hash of a password
pub(crate) fn nt_hash(password: &str) -> [u8; 16] {
    md4(&utf16(password))
}

/// NTLMv2's ResponseKeyNT, from the user and domain as the client encoded them
fn response_key(nt_hash: &[u8; 16], user: &[u8], domain: &[u8]) -> Option<[u8; 16]> {
    let user = utf16(&from_utf16(user)?.to_uppercase());
    Some(hmac_md5(nt_hash, &[&user, domain]))
}

/// Whether the MsvAvFlags of the client's AV pairs say that the message carries a MIC
fn has_mic(mut pairs: &[u8]) -> bool {
    while let (Some(id), Some(len)) = (u16_at(pairs, 0), u16_at(pairs, 2)) {
        let len = len as usize;
        match id {
            0 => break,
            6 => return u32_at(pairs, 4).is_some_and(|flags| flags & 0x2 != 0),
            _ => pairs = pairs.get(4 + len..).unwrap_or_default(),
        }
    }
    false
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn challenge(client_flags: u32, server_challenge: [u8; 8], now: u64) -> Vec<u8> {
    let flags = (client_flags & ECHOED)
        | NEGOTIATE_UNICODE
        | REQUEST_TARGET
        | NEGOTIATE_NTLM
        | TARGET_TYPE_SERVER
        | EXTENDED_SESSION_SECURITY
        | NEGOTIATE_TARGET_INFO;
    let name = utf16(TARGET);
    let mut info = Vec::new();
    // NetBIOS domain and computer names, then a timestamp, which has the client send a MIC
    for (id, value) in [
        (2u16, &name[..]),
        (1, &name[..]),
        (7, &now.to_le_bytes()[..]),
    ] {
        info.put_u16(id);
        info.put_u16(value.len() as u16);
        info.extend_from_slice(value);
    }
    info.put_u32(0);
    let mut msg = SIGNATURE.to_vec();
    msg.put_u32(2);
    let fields_end = 56;
    msg.put_u16(name.len() as u16);
    msg.put_u16(name.len() as u16);
    msg.put_u32(fields_end);
    msg.put_u32(flags);
    msg.extend_from_slice(&server_challenge);
    msg.put_u64(0);
    msg.put_u16(info.len() as u16);
    msg.put_u16(info.len() as u16);
    msg.put_u32(fields_end + name.len() as u32);
    // Version: 10.0, NTLM revision 15
    msg.extend_from_slice(&[10, 0, 0, 0, 0, 0, 0, 15]);
    msg.extend_from_slice(&name);
    msg.extend_from_slice(&info);
    msg
}

/// The server's mechListMIC: an NTLM signature of the client's MechTypeList, as the first
/// message the server signs
fn mech_list_mic(auth: &Authenticated, mech_types: &[u8]) -> Vec<u8> {
    let key = |purpose: &str| {
        md5(&[
            &auth.session_key[..],
            format!("session key to server-to-client {purpose} key magic constant\0").as_bytes(),
        ]
        .concat())
    };
    let sequence = 0u32.to_le_bytes();
    let mut checksum = hmac_md5(&key("signing"), &[&sequence, mech_types])[..8].to_vec();
    if auth.flags & NEGOTIATE_KEY_EXCH != 0 {
        checksum = rc4(&key("sealing"), &checksum);
    }
    [&1u32.to_le_bytes()[..], &checksum, &sequence].concat()
}

/// A DER tag, length and value
fn der(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = value.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes: Vec<u8> = len
            .to_be_bytes()
            .into_iter()
            .skip_while(|b| *b == 0)
            .collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend_from_slice(&bytes);
    }
    out.extend_from_slice(value);
    out
}

/// Splits a DER tag, length and value off `data`: the tag, the value and what follows
fn tlv(data: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = data.split_first()?;
    let (&first, mut rest) = rest.split_first()?;
    let len = if first < 0x80 {
        first as usize
    } else {
        let count = (first & 0x7f) as usize;
        if count == 0 || count > 4 {
            return None;
        }
        let (bytes, after) = rest.split_at_checked(count)?;
        rest = after;
        bytes.iter().fold(0, |len, b| (len << 8) | *b as usize)
    };
    let (value, rest) = rest.split_at_checked(len)?;
    Some((tag, value, rest))
}

#[derive(Debug, Default)]
struct Spnego<'a> {
    mech_types: Option<&'a [u8]>,
    token: Option<&'a [u8]>,
    mic: Option<&'a [u8]>,
}

/// A NegTokenInit, in its GSS-API wrapping, or a NegTokenResp
fn parse_spnego(blob: &[u8]) -> Option<Spnego<'_>> {
    let (tag, body, _) = tlv(blob)?;
    let (init, inner) = match tag {
        0x60 => {
            let (0x06, oid, rest) = tlv(body)? else {
                return None;
            };
            let (0xa0, inner, _) = tlv(rest)? else {
                return None;
            };
            (oid == SPNEGO_OID).then_some((true, inner))?
        }
        0xa1 => (false, body),
        _ => return None,
    };
    let (0x30, mut fields, _) = tlv(inner)? else {
        return None;
    };
    let mut spnego = Spnego::default();
    let octets = |value| match tlv(value)? {
        (0x04, octets, _) => Some(octets),
        _ => None,
    };
    while !fields.is_empty() {
        let (tag, value, rest) = tlv(fields)?;
        fields = rest;
        match tag {
            // In a NegTokenResp, [0] is negState
            0xa0 if init => spnego.mech_types = Some(value),
            0xa2 => spnego.token = Some(octets(value)?),
            0xa3 => spnego.mic = Some(octets(value)?),
            _ => {}
        }
    }
    Some(spnego)
}

fn lists_ntlm(mech_types: &[u8]) -> bool {
    let Some((0x30, mut oids, _)) = tlv(mech_types) else {
        return false;
    };
    while let Some((tag, oid, rest)) = tlv(oids) {
        if tag == 0x06 && oid == NTLMSSP_OID {
            return true;
        }
        oids = rest;
    }
    false
}

/// A NegTokenResp: `state` 0 is accept-completed, 1 accept-incomplete
fn neg_token_resp(state: u8, select: bool, token: Option<&[u8]>, mic: Option<&[u8]>) -> Vec<u8> {
    let mut fields = der(0xa0, &der(0x0a, &[state]));
    if select {
        fields.extend(der(0xa1, &der(0x06, NTLMSSP_OID)));
    }
    if let Some(token) = token {
        fields.extend(der(0xa2, &der(0x04, token)));
    }
    if let Some(mic) = mic {
        fields.extend(der(0xa3, &der(0x04, mic)));
    }
    der(0xa1, &der(0x30, &fields))
}

/// The client side, for tests
#[cfg(test)]
pub(crate) mod client {
    use super::*;

    pub(crate) fn negotiate(flags: u32) -> Vec<u8> {
        let mut msg = SIGNATURE.to_vec();
        msg.put_u32(1);
        msg.put_u32(flags);
        // Empty domain and workstation
        msg.extend_from_slice(&[0; 16]);
        msg
    }

    /// An NTLMv2 AUTHENTICATE for `challenge`, and the session key it sets up
    pub(crate) fn authenticate(
        challenge: &[u8],
        user: &str,
        password: &str,
        flags: u32,
    ) -> (Vec<u8>, [u8; 16]) {
        let server_challenge: [u8; 8] = challenge[24..32].try_into().unwrap();
        let info_len = u16_at(challenge, 40).unwrap() as usize;
        let info_offset = u32_at(challenge, 44).unwrap() as usize;
        let info = &challenge[info_offset..info_offset + info_len];
        let mut blob = vec![1, 1, 0, 0, 0, 0, 0, 0];
        blob.extend_from_slice(&[0; 8]);
        blob.extend_from_slice(&[0xaa; 8]);
        blob.put_u32(0);
        blob.extend_from_slice(info);
        blob.put_u32(0);
        let (user16, domain16) = (utf16(user), utf16("DOMAIN"));
        let key = response_key(&nt_hash(password), &user16, &domain16).unwrap();
        let proof = hmac_md5(&key, &[&server_challenge, &blob]);
        let base = hmac_md5(&key, &[&proof]);
        let random = [0x55; 16];
        let (session_key, encrypted) = if flags & NEGOTIATE_KEY_EXCH != 0 {
            (random, rc4(&base, &random))
        } else {
            (base, Vec::new())
        };
        let nt = [&proof[..], &blob].concat();
        let mut msg = SIGNATURE.to_vec();
        msg.put_u32(3);
        let mut offset = 88u32;
        let mut payload = Vec::new();
        for field in [&[][..], &nt, &domain16, &user16, &[], &encrypted] {
            msg.put_u16(field.len() as u16);
            msg.put_u16(field.len() as u16);
            msg.put_u32(offset);
            offset += field.len() as u32;
            payload.extend_from_slice(field);
        }
        msg.put_u32(flags);
        msg.extend_from_slice(&[0; 8 + 16]);
        msg.extend_from_slice(&payload);
        (msg, session_key)
    }

    /// A NegTokenInit carrying `token`, with NTLM the one mechanism
    pub(crate) fn neg_token_init(token: &[u8]) -> Vec<u8> {
        let mech_types = der(0x30, &der(0x06, NTLMSSP_OID));
        let fields = [der(0xa0, &mech_types), der(0xa2, &der(0x04, token))].concat();
        der(
            0x60,
            &[der(0x06, SPNEGO_OID), der(0xa0, &der(0x30, &fields))].concat(),
        )
    }

    pub(crate) fn neg_token_resp_token(token: &[u8]) -> Vec<u8> {
        neg_token_resp(1, false, Some(token), None)
    }

    /// The token a NegTokenResp carries
    pub(crate) fn response_token(blob: &[u8]) -> Option<Vec<u8>> {
        parse_spnego(blob)?.token.map(<[u8]>::to_vec)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const USER: &str = "fuser";
    const PASSWORD: &str = "secret";

    fn logon(spnego: bool, password: &str, flags: u32) -> (Option<Step>, [u8; 16]) {
        let mut logon = Logon::default();
        let hash = nt_hash(PASSWORD);
        let negotiate = client::negotiate(flags);
        let first = if spnego {
            client::neg_token_init(&negotiate)
        } else {
            negotiate
        };
        let Some(Step::Continue(reply)) = logon.step(&first, USER, &hash, [7; 8], 0) else {
            panic!("no challenge");
        };
        let challenge = if spnego {
            client::response_token(&reply).unwrap()
        } else {
            reply
        };
        assert!(challenge.starts_with(SIGNATURE));
        let (auth, key) = client::authenticate(&challenge, "FUSER", password, flags);
        let second = if spnego {
            client::neg_token_resp_token(&auth)
        } else {
            auth
        };
        (logon.step(&second, USER, &hash, [7; 8], 0), key)
    }

    #[test]
    fn ms_nlmp_ntlmv2_example() {
        // MS-NLMP 4.2.4: user "User", domain "Domain", password "Password"
        let key = response_key(&nt_hash("Password"), &utf16("User"), &utf16("Domain")).unwrap();
        assert_eq!(
            key,
            *b"\x0c\x86\x8a\x40\x3b\xfd\x7a\x93\xa3\x00\x1e\xf2\x2e\xf0\x2e\x3f"
        );
        let mut blob = vec![1, 1, 0, 0, 0, 0, 0, 0];
        blob.extend_from_slice(&[0; 8]);
        blob.extend_from_slice(&[0xaa; 8]);
        blob.extend_from_slice(&[0; 4]);
        for (id, name) in [(2u16, "Domain"), (1, "Server")] {
            blob.put_u16(id);
            blob.put_u16(12);
            blob.extend_from_slice(&utf16(name));
        }
        blob.extend_from_slice(&[0; 8]);
        let challenge = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let proof = hmac_md5(&key, &[&challenge, &blob]);
        assert_eq!(
            proof,
            *b"\x68\xcd\x0a\xb8\x51\xe5\x1c\x96\xaa\xbc\x92\x7b\xeb\xef\x6a\x1c"
        );
        assert_eq!(
            hmac_md5(&key, &[&proof]),
            *b"\x8d\xe4\x0c\xca\xdb\xc1\x4a\x82\xf1\x5c\xb0\xad\x0d\xe9\x5c\xa3"
        );
    }

    #[test]
    fn logons() {
        let flags = NEGOTIATE_UNICODE | EXTENDED_SESSION_SECURITY | NEGOTIATE_KEY_EXCH;
        for spnego in [true, false] {
            let (step, key) = logon(spnego, PASSWORD, flags);
            let Some(Step::Done { session_key, token }) = step else {
                panic!("not logged on");
            };
            // macOS's way: KEY_EXCH without SIGN, which only a MIC would settle. With none,
            // the key is the exchange key
            assert_ne!(session_key, key);
            assert_eq!(token.is_empty(), !spnego);
            assert_eq!(logon(spnego, "wrong", flags).0, None);
        }
        let (step, key) = logon(true, PASSWORD, flags | NEGOTIATE_SIGN);
        assert!(matches!(step, Some(Step::Done { session_key, .. }) if session_key == key));
    }

    #[test]
    fn spnego_tokens() {
        let hint = negotiate_hint();
        let spnego = parse_spnego(&hint).unwrap();
        assert!(lists_ntlm(spnego.mech_types.unwrap()));
        let resp = neg_token_resp(1, true, Some(b"token"), Some(b"mic"));
        let spnego = parse_spnego(&resp).unwrap();
        assert_eq!(spnego.token, Some(&b"token"[..]));
        assert_eq!(spnego.mic, Some(&b"mic"[..]));
        let long = vec![7u8; 300];
        assert_eq!(tlv(&der(0x04, &long)).unwrap().1, &long[..]);
        assert!(parse_spnego(b"\x60\x05garbage").is_none());
    }
}
