// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

mod common;

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use ldk_node::config::ElectrumSyncConfig;
use ldk_node::Builder;

use crate::common::{random_config, setup_bitcoind_and_electrsd, setup_builder};

/// A TCP proxy that can make its established connections go silent without closing them.
///
/// A stalled connection stays open and keeps accepting (and hence acknowledging) whatever is
/// written to it, but nothing is forwarded in either direction anymore. This is what a peer looks
/// like when a load balancer or the server itself hangs: neither a FIN/RST nor a TCP
/// retransmission timeout will ever wake up a reader waiting for a response. Connections that are
/// established after the stall work normally.
struct StallProxy {
	addr: SocketAddr,
	// Connections only forward data while they belong to the current generation.
	generation: Arc<AtomicUsize>,
}

impl StallProxy {
	fn new(upstream_addr: String) -> Self {
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let addr = listener.local_addr().unwrap();
		let generation = Arc::new(AtomicUsize::new(0));

		let accept_generation = Arc::clone(&generation);
		thread::spawn(move || {
			for downstream in listener.incoming() {
				let downstream = downstream.unwrap();
				let upstream = TcpStream::connect(&upstream_addr).unwrap();
				let conn_generation = accept_generation.load(Ordering::SeqCst);

				for (from, to) in [(&downstream, &upstream), (&upstream, &downstream)] {
					let (from, to) = (from.try_clone().unwrap(), to.try_clone().unwrap());
					let generation = Arc::clone(&accept_generation);
					thread::spawn(move || forward(from, to, conn_generation, generation));
				}
			}
		});

		Self { addr, generation }
	}

	/// Makes all currently established connections go silent.
	fn stall_connections(&self) {
		self.generation.fetch_add(1, Ordering::SeqCst);
	}
}

fn forward(
	mut from: TcpStream, mut to: TcpStream, conn_generation: usize, generation: Arc<AtomicUsize>,
) {
	let mut buf = [0u8; 4096];
	loop {
		match from.read(&mut buf) {
			Ok(0) | Err(_) => break,
			Ok(len) => {
				// Once stalled, we keep reading but drop everything on the floor.
				if generation.load(Ordering::SeqCst) != conn_generation {
					continue;
				}
				if to.write_all(&buf[..len]).is_err() {
					break;
				}
			},
		}
	}
	let _ = to.shutdown(Shutdown::Both);
}

// If the Electrum server stops responding without closing the connection, any read on a socket
// without a timeout blocks forever. As a transaction sync holds on to the sync lock while reading,
// such a blocked read would make every following sync of the Lightning wallet time out until the
// node is restarted. So here we assert that the node recovers on its own.
#[test]
fn electrum_sync_recovers_from_stalled_connection() {
	let (_bitcoind, electrsd) = setup_bitcoind_and_electrsd();
	let proxy = StallProxy::new(electrsd.electrum_url.clone());

	let config = random_config(true);
	setup_builder!(builder, config.node_config);
	let sync_config = ElectrumSyncConfig { background_sync_config: None };
	builder.set_chain_source_electrum(format!("tcp://{}", proxy.addr), Some(sync_config));
	let node = builder.build().unwrap();
	node.start().unwrap();

	node.sync_wallets().unwrap();

	proxy.stall_connections();

	// The first syncs are expected to fail as they still use the stalled connections, but they
	// need to error out and reconnect rather than wait for a response forever.
	let recovery_timeout = Duration::from_secs(60);
	let stalled_at = Instant::now();
	loop {
		match node.sync_wallets() {
			Ok(()) => break,
			Err(e) => {
				println!("Sync failed {}s after stall: {}", stalled_at.elapsed().as_secs(), e);
				if stalled_at.elapsed() > recovery_timeout {
					// Dropping the node would wait for the blocked read, i.e., forever.
					std::mem::forget(node);
					panic!("Node did not recover from stalled Electrum connections: {}", e);
				}
				thread::sleep(Duration::from_secs(1));
			},
		}
	}

	node.stop().unwrap();
}
