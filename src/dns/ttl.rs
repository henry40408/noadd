//! Locating and rewriting the TTL fields of a DNS response in place.
//!
//! A cached response is served many times, each time with its TTLs reduced by
//! however long it has been cached. Doing that by parsing the message and
//! re-encoding it costs a full round trip through the record types for what is
//! a handful of four-byte writes, so the offsets of those four-byte fields are
//! found once — when the response is cached — and reused for every hit after.
//!
//! Rewriting in place also means a served response is the upstream's own bytes
//! with its TTLs adjusted, rather than a re-encoding of them: name compression
//! and record order survive exactly as the upstream wrote them.

/// Fixed DNS header: ID, flags, and the four section counts.
const HEADER_LEN: usize = 12;
/// TYPE and CLASS, which sit between the owner name and the TTL.
const TYPE_AND_CLASS_LEN: usize = 4;
const TTL_LEN: usize = 4;
const RDLENGTH_LEN: usize = 2;

/// EDNS(0) OPT. Its TTL field is not a TTL — it carries the extended RCODE,
/// the EDNS version and the DO flag ([RFC 6891 §6.1.3]), so decrementing it
/// would corrupt the response's DNSSEC signalling.
///
/// [RFC 6891 §6.1.3]: https://www.rfc-editor.org/rfc/rfc6891#section-6.1.3
const TYPE_OPT: u16 = 41;
/// TSIG, whose TTL must be transmitted as 0 ([RFC 8945 §4.2]).
///
/// [RFC 8945 §4.2]: https://www.rfc-editor.org/rfc/rfc8945#section-4.2
const TYPE_TSIG: u16 = 250;

/// Byte offsets of every TTL field in `response` that may be decremented.
///
/// Empty when the message cannot be walked, which leaves the response served
/// with its original TTLs — the same outcome the parse-based path produced for
/// a message it could not read.
pub fn ttl_offsets(response: &[u8]) -> Box<[u32]> {
    scan(response).unwrap_or_default()
}

/// Reduce every TTL at `offsets` by `elapsed_secs`, reading the original value
/// from the buffer itself.
///
/// Floored at 1 rather than 0: a zero TTL tells a client not to cache the
/// answer at all, so it would re-query on the very next lookup.
pub fn apply_elapsed(bytes: &mut [u8], offsets: &[u32], elapsed_secs: u32) {
    if elapsed_secs == 0 {
        return;
    }
    for &offset in offsets {
        let start = offset as usize;
        let Some(end) = start.checked_add(TTL_LEN) else {
            continue;
        };
        let Some(field) = bytes.get_mut(start..end) else {
            continue;
        };
        let original = u32::from_be_bytes([field[0], field[1], field[2], field[3]]);
        let remaining = original.saturating_sub(elapsed_secs).max(1);
        field.copy_from_slice(&remaining.to_be_bytes());
    }
}

/// Reduce every TTL in a response by `elapsed_secs`, scanning it first.
///
/// For a response served repeatedly, prefer [`ttl_offsets`] once plus
/// [`apply_elapsed`] per hit; this is for callers holding bytes they will
/// patch a single time.
pub fn decrement_ttl(response: &[u8], elapsed_secs: u32) -> Vec<u8> {
    let offsets = ttl_offsets(response);
    let mut bytes = response.to_vec();
    apply_elapsed(&mut bytes, &offsets, elapsed_secs);
    bytes
}

/// Advance past the domain name starting at `pos`, returning the offset of the
/// byte after it.
///
/// The name is skipped, not decoded: a compression pointer ends the name where
/// it appears, so nothing here has to follow it or guard against a pointer
/// loop.
fn skip_name(buf: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *buf.get(pos)?;
        match len & 0xC0 {
            0x00 => {
                pos += 1;
                if len == 0 {
                    return Some(pos);
                }
                pos = pos.checked_add(usize::from(len))?;
            }
            0xC0 => {
                // Two-byte pointer; the second byte must exist to be a name.
                buf.get(pos + 1)?;
                return Some(pos + 2);
            }
            // 0x40 and 0x80 are reserved label types (RFC 6891 §3).
            _ => return None,
        }
    }
}

fn scan(buf: &[u8]) -> Option<Box<[u32]>> {
    let counts = buf.get(..HEADER_LEN)?;
    let section_count = |at: usize| usize::from(u16::from_be_bytes([counts[at], counts[at + 1]]));
    let questions = section_count(4);
    let records = section_count(6) + section_count(8) + section_count(10);

    let mut pos = HEADER_LEN;
    for _ in 0..questions {
        pos = skip_name(buf, pos)?;
        // QTYPE + QCLASS, same width as a record's TYPE + CLASS.
        pos = pos.checked_add(TYPE_AND_CLASS_LEN)?;
    }

    let mut offsets = Vec::with_capacity(records);
    for _ in 0..records {
        pos = skip_name(buf, pos)?;
        let record_type = u16::from_be_bytes([*buf.get(pos)?, *buf.get(pos + 1)?]);
        let ttl_at = pos.checked_add(TYPE_AND_CLASS_LEN)?;
        let rdlength_at = ttl_at.checked_add(TTL_LEN)?;
        let rdlength = usize::from(u16::from_be_bytes([
            *buf.get(rdlength_at)?,
            *buf.get(rdlength_at + 1)?,
        ]));

        if record_type != TYPE_OPT && record_type != TYPE_TSIG {
            offsets.push(u32::try_from(ttl_at).ok()?);
        }

        pos = rdlength_at
            .checked_add(RDLENGTH_LEN)?
            .checked_add(rdlength)?;
        if pos > buf.len() {
            return None;
        }
    }

    Some(offsets.into_boxed_slice())
}
