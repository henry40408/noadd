//! Coverage for the wire-format TTL walk in `noadd::dns::ttl`.
//!
//! The walk replaced a parse-and-re-encode round trip, so most of what is here
//! checks that it decrements exactly what the parser used to and nothing else.
//! The pseudo-TTL fields are the sharp edge: OPT's four bytes carry the
//! extended RCODE, the EDNS version and the DO flag, and decrementing them
//! would corrupt a response's DNSSEC signalling without failing to parse.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME, SOA, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;

use noadd::dns::ttl::{apply_elapsed, decrement_ttl, ttl_offsets};

fn name(s: &str) -> Name {
    Name::from_str(s).unwrap()
}

fn response(id: u16, qname: &str, qtype: RecordType) -> Message {
    let mut msg = Message::new(id, MessageType::Response, OpCode::Query);
    msg.metadata.response_code = ResponseCode::NoError;
    msg.metadata.recursion_desired = true;
    msg.metadata.recursion_available = true;
    let mut q = Query::new();
    q.set_name(name(qname));
    q.set_query_type(qtype);
    msg.add_query(q);
    msg
}

/// Every TTL hickory can see, in the order the sections are written.
fn ttls(bytes: &[u8]) -> Vec<u32> {
    let msg = Message::from_bytes(bytes).unwrap();
    msg.answers
        .iter()
        .chain(msg.authorities.iter())
        .chain(msg.additionals.iter())
        .map(|r| r.ttl)
        .collect()
}

#[test]
fn every_section_is_decremented() {
    let mut msg = response(0x0001, "example.com.", RecordType::A);
    msg.add_answer(Record::from_rdata(
        name("example.com."),
        300,
        RData::A(A(Ipv4Addr::new(203, 0, 113, 1))),
    ));
    msg.add_authority(Record::from_rdata(
        name("example.com."),
        600,
        RData::NS(hickory_proto::rr::rdata::NS(name("ns1.example.com."))),
    ));
    msg.add_additional(Record::from_rdata(
        name("ns1.example.com."),
        900,
        RData::A(A(Ipv4Addr::new(203, 0, 113, 2))),
    ));
    let bytes = msg.to_vec().unwrap();

    assert_eq!(ttls(&bytes), vec![300, 600, 900]);
    assert_eq!(
        ttls(&decrement_ttl(&bytes, 100)),
        vec![200, 500, 800],
        "answer, authority and additional records all carry real TTLs"
    );
}

#[test]
fn a_compressed_owner_name_is_walked_past() {
    let mut msg = response(0x0002, "example.com.", RecordType::A);
    for octet in [1, 2, 3] {
        msg.add_answer(Record::from_rdata(
            name("example.com."),
            300,
            RData::A(A(Ipv4Addr::new(203, 0, 113, octet))),
        ));
    }
    let bytes = msg.to_vec().unwrap();

    assert!(
        bytes
            .windows(2)
            .any(|w| w[0] & 0xC0 == 0xC0 && w[0] >= 0xC0),
        "fixture must actually contain a compression pointer, or this test \
         proves nothing about the pointer branch"
    );
    assert_eq!(ttls(&decrement_ttl(&bytes, 60)), vec![240, 240, 240]);
}

#[test]
fn a_cname_chain_is_walked_past() {
    let mut msg = response(0x0003, "www.example.com.", RecordType::A);
    msg.add_answer(Record::from_rdata(
        name("www.example.com."),
        3600,
        RData::CNAME(CNAME(name("target.example.net."))),
    ));
    msg.add_answer(Record::from_rdata(
        name("target.example.net."),
        120,
        RData::A(A(Ipv4Addr::new(198, 51, 100, 7))),
    ));
    let bytes = msg.to_vec().unwrap();

    assert_eq!(
        ttls(&decrement_ttl(&bytes, 60)),
        vec![3540, 60],
        "a record whose owner differs from the question must still be found"
    );
}

#[test]
fn a_negative_answer_decrements_its_soa() {
    let mut msg = response(0x0004, "nope.example.com.", RecordType::A);
    msg.metadata.response_code = ResponseCode::NXDomain;
    msg.add_authority(Record::from_rdata(
        name("example.com."),
        3600,
        RData::SOA(SOA::new(
            name("ns1.example.com."),
            name("hostmaster.example.com."),
            20_260_101,
            7200,
            3600,
            1_209_600,
            300,
        )),
    ));
    let bytes = msg.to_vec().unwrap();

    assert_eq!(ttls(&decrement_ttl(&bytes, 600)), vec![3000]);
}

#[test]
fn a_long_txt_record_is_walked_past() {
    let mut msg = response(0x0005, "example.com.", RecordType::TXT);
    msg.add_answer(Record::from_rdata(
        name("example.com."),
        300,
        RData::TXT(TXT::new(vec![
            "v=spf1 include:_spf.example.com include:_spf2.example.com ~all".to_string(),
            "x".repeat(255),
        ])),
    ));
    msg.add_answer(Record::from_rdata(
        name("example.com."),
        300,
        RData::AAAA(AAAA(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))),
    ));
    let bytes = msg.to_vec().unwrap();

    assert_eq!(
        ttls(&decrement_ttl(&bytes, 1)),
        vec![299, 299],
        "the record after a large RDATA must still be located"
    );
}

/// OPT's TTL field is not a TTL. Decrementing it would silently flip the DO
/// bit and rewrite the extended RCODE.
#[test]
fn an_opt_pseudo_ttl_is_left_alone() {
    let mut msg = response(0x0006, "example.com.", RecordType::A);
    msg.add_answer(Record::from_rdata(
        name("example.com."),
        300,
        RData::A(A(Ipv4Addr::new(203, 0, 113, 1))),
    ));
    let mut edns = Edns::new();
    edns.set_version(0)
        .set_max_payload(1232)
        .set_dnssec_ok(true);
    msg.edns = Some(edns);
    let bytes = msg.to_vec().unwrap();

    let before = Message::from_bytes(&bytes).unwrap();
    let before_edns = before.edns.clone().expect("fixture must carry an OPT");
    assert!(before_edns.flags().dnssec_ok);

    let patched = decrement_ttl(&bytes, 250);
    let after = Message::from_bytes(&patched).unwrap();
    let after_edns = after.edns.expect("OPT must survive the patch");

    assert_eq!(ttls(&patched), vec![50], "the real record still decrements");
    assert_eq!(
        after_edns.flags().dnssec_ok,
        before_edns.flags().dnssec_ok,
        "the DO bit lives in OPT's TTL field and must not be decremented"
    );
    assert_eq!(after_edns.version(), before_edns.version());
    assert_eq!(after_edns.rcode_high(), before_edns.rcode_high());
    assert_eq!(
        ttl_offsets(&bytes).len(),
        1,
        "only the A record's TTL is decrementable"
    );
}

/// TSIG's TTL must be transmitted as 0 (RFC 8945 §4.2), so it is not ours to
/// decrement either. Built by hand: what matters to the walk is the TYPE and
/// RDLENGTH, not whether the RDATA is a well-formed signature.
#[test]
fn a_tsig_pseudo_ttl_is_left_alone() {
    let mut msg = response(0x0007, "example.com.", RecordType::A);
    msg.add_answer(Record::from_rdata(
        name("example.com."),
        300,
        RData::A(A(Ipv4Addr::new(203, 0, 113, 1))),
    ));
    let mut bytes = msg.to_vec().unwrap();

    // One additional record: root owner name, TYPE 250 (TSIG), CLASS ANY,
    // TTL 0, empty RDATA.
    let tsig_ttl_at = bytes.len() + 5;
    bytes.extend_from_slice(&[0x00, 0x00, 250, 0x00, 255]);
    bytes.extend_from_slice(&0u32.to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes[11] = 1; // ARCOUNT

    let offsets = ttl_offsets(&bytes);
    assert_eq!(offsets.len(), 1, "TSIG's TTL is not decrementable");
    assert_ne!(offsets[0] as usize, tsig_ttl_at);

    let patched = decrement_ttl(&bytes, 500);
    assert_eq!(
        &patched[tsig_ttl_at..tsig_ttl_at + 4],
        &[0, 0, 0, 0],
        "a TSIG TTL of 0 must not be clamped up to 1"
    );
}

#[test]
fn offsets_point_at_the_ttl_the_parser_reads() {
    let mut msg = response(0x0008, "example.com.", RecordType::A);
    for (octet, ttl) in [(1u8, 300u32), (2, 600)] {
        msg.add_answer(Record::from_rdata(
            name("example.com."),
            ttl,
            RData::A(A(Ipv4Addr::new(203, 0, 113, octet))),
        ));
    }
    let bytes = msg.to_vec().unwrap();

    let at_offsets: Vec<u32> = ttl_offsets(&bytes)
        .iter()
        .map(|&o| {
            let at = o as usize;
            u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap())
        })
        .collect();

    assert_eq!(at_offsets, ttls(&bytes));
}

#[test]
fn patching_rewrites_only_the_ttl_bytes() {
    let mut msg = response(0x0009, "example.com.", RecordType::A);
    msg.add_answer(Record::from_rdata(
        name("example.com."),
        300,
        RData::A(A(Ipv4Addr::new(203, 0, 113, 1))),
    ));
    msg.metadata.authoritative = true;
    let original = msg.to_vec().unwrap();

    let patched = decrement_ttl(&original, 100);
    assert_eq!(
        patched.len(),
        original.len(),
        "an in-place rewrite must not change the message length"
    );

    let offsets = ttl_offsets(&original);
    let differing: Vec<usize> = (0..original.len())
        .filter(|&i| original[i] != patched[i])
        .collect();
    let ttl_bytes: Vec<usize> = offsets
        .iter()
        .flat_map(|&o| (o as usize)..(o as usize + 4))
        .collect();

    assert!(
        differing.iter().all(|i| ttl_bytes.contains(i)),
        "bytes outside the TTL fields changed: {differing:?}"
    );
}

/// A record type the walk has never heard of must not stop it: TYPE and
/// RDLENGTH are all it reads, and the payload is opaque.
///
/// Built by appending to an encoded message rather than through hickory, whose
/// decoder rejects the `RData::Unknown` its own encoder produces — and a record
/// type this crate cannot represent is exactly the case worth covering.
#[test]
fn an_unknown_record_type_is_walked_past() {
    let mut msg = response(0x000A, "example.com.", RecordType::A);
    msg.add_answer(Record::from_rdata(
        name("example.com."),
        300,
        RData::A(A(Ipv4Addr::new(203, 0, 113, 1))),
    ));
    let mut bytes = msg.to_vec().unwrap();

    // Owner name as a compression pointer to the question at offset 12, TYPE 65
    // (HTTPS), CLASS IN, then 40 bytes of RDATA the walk never looks at.
    let unknown_ttl_at = bytes.len() + 6;
    bytes.extend_from_slice(&[0xC0, 0x0C, 0x00, 65, 0x00, 0x01]);
    bytes.extend_from_slice(&600u32.to_be_bytes());
    bytes.extend_from_slice(&40u16.to_be_bytes());
    bytes.extend_from_slice(&[0xDE; 40]);

    // A second A record after it, which is only reachable if the walk got the
    // unknown record's length right.
    let trailing_ttl_at = bytes.len() + 6;
    bytes.extend_from_slice(&[0xC0, 0x0C, 0x00, 1, 0x00, 0x01]);
    bytes.extend_from_slice(&450u32.to_be_bytes());
    bytes.extend_from_slice(&4u16.to_be_bytes());
    bytes.extend_from_slice(&[203, 0, 113, 9]);

    bytes[7] = 3; // ANCOUNT

    let offsets = ttl_offsets(&bytes);
    assert_eq!(offsets.len(), 3, "all three records must be found");
    assert_eq!(offsets[1] as usize, unknown_ttl_at);
    assert_eq!(offsets[2] as usize, trailing_ttl_at);

    let patched = decrement_ttl(&bytes, 50);
    let at = |b: &[u8], i: usize| u32::from_be_bytes(b[i..i + 4].try_into().unwrap());
    assert_eq!(at(&patched, offsets[0] as usize), 250);
    assert_eq!(at(&patched, unknown_ttl_at), 550);
    assert_eq!(at(&patched, trailing_ttl_at), 400);
}

#[test]
fn a_message_that_cannot_be_walked_is_served_unchanged() {
    let mut msg = response(0x000B, "example.com.", RecordType::A);
    msg.add_answer(Record::from_rdata(
        name("example.com."),
        300,
        RData::A(A(Ipv4Addr::new(203, 0, 113, 1))),
    ));
    let good = msg.to_vec().unwrap();

    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", Vec::new()),
        ("header only, truncated", good[..8].to_vec()),
        ("record cut short", good[..good.len() - 3].to_vec()),
        ("rdlength past the end", {
            let mut b = good.clone();
            let len = b.len();
            b[len - 5] = 0xFF;
            b
        }),
        ("reserved label type", {
            let mut b = good.clone();
            b[12] = 0x80;
            b
        }),
        ("answer count larger than the message", {
            let mut b = good.clone();
            b[7] = 0xFF;
            b
        }),
    ];

    for (what, bytes) in cases {
        assert!(
            ttl_offsets(&bytes).is_empty(),
            "{what}: an unwalkable message must yield no offsets"
        );
        assert_eq!(
            decrement_ttl(&bytes, 100),
            bytes,
            "{what}: an unwalkable message must be served byte-for-byte"
        );
    }
}

#[test]
fn a_bogus_offset_does_not_panic() {
    let bytes = vec![0u8; 20];
    let mut patched = bytes.clone();
    apply_elapsed(&mut patched, &[18, 4096, u32::MAX], 10);
    assert_eq!(
        patched, bytes,
        "offsets that do not fit a four-byte field are skipped, not clamped"
    );
}
