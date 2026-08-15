//! One real DNS query, for the one scenario that needs noadd to have answered.
//!
//! The onboarding banner clears itself once the appliance has served traffic,
//! and the only honest way to prove that is to make it serve some. A resolver
//! crate would be a dependency for twelve bytes of header, so the packet is
//! built by hand exactly as `steps/onboarding.steps.js` built it.

use anyhow::Result;
use tokio::net::UdpSocket;

/// Sends a standard A query for `name` to the DNS listener on `port`.
///
/// No response is read: noadd logs every query it handles and the logger
/// flushes about once a second, which the assertion that follows polls
/// through. Whether an upstream answers is beside the point.
///
/// # Errors
///
/// Fails when the socket cannot be opened or the datagram cannot be sent.
pub async fn send_query(port: u16, name: &str) -> Result<()> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    socket
        .send_to(&query_packet(name), ("127.0.0.1", port))
        .await?;
    Ok(())
}

/// A minimal A-record query: one question, recursion desired, no EDNS.
fn query_packet(name: &str) -> Vec<u8> {
    let mut packet = Vec::with_capacity(32 + name.len());
    // A fixed transaction id is fine — nothing here reads the reply, and two
    // queries in flight at once never happens.
    packet.extend_from_slice(&0x1234_u16.to_be_bytes()); // transaction id
    packet.extend_from_slice(&0x0100_u16.to_be_bytes()); // standard query, RD=1
    packet.extend_from_slice(&1_u16.to_be_bytes()); // QDCOUNT
    packet.extend_from_slice(&[0; 6]); // ANCOUNT / NSCOUNT / ARCOUNT

    for label in name.split('.') {
        packet.push(u8::try_from(label.len()).unwrap_or(0));
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0); // root terminator

    packet.extend_from_slice(&1_u16.to_be_bytes()); // QTYPE = A
    packet.extend_from_slice(&1_u16.to_be_bytes()); // QCLASS = IN
    packet
}
