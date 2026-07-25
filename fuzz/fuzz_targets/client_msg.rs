//! The bytes an agent parses — the sharpest surface in the project.
//!
//! `host-agent` decodes these in a process that can type at a root console on the hypervisor, and
//! anything that reaches the TLS layer can send them: enrolment deliberately accepts a certificate
//! it has never seen before, so "authenticated" does not mean "trusted" at this point in the
//! handshake. A panic here is a remote crash; an unbounded allocation is a remote OOM.
//!
//! Run with a memory limit, because the interesting failure is an allocation, not a segfault:
//!
//!   cargo fuzz run client_msg -- -rss_limit_mb=512

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The length prefix is checked against MAX_MSG before we get here, so a body larger than that
    // is not reachable on the wire and would only teach the fuzzer to waste its time.
    if data.len() > protocol::MAX_MSG {
        return;
    }
    let _ = protocol::decode::<protocol::ClientMsg>(data);
});
