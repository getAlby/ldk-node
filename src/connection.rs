// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use std::collections::hash_map::{self, HashMap};
use std::net::ToSocketAddrs;
use std::ops::Deref;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bitcoin::secp256k1::PublicKey;
use lightning::ln::msgs::SocketAddress;
use lightning::sign::{EntropySource, RandomBytes};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::logger::{log_error, log_info, LdkLogger};
use crate::types::PeerManager;
use crate::Error;

const TOR_CONNECT_OUTBOUND_TIMEOUT: u64 = 30;

pub(crate) struct ConnectionManager<L: Deref + Clone + Sync + Send>
where
	L::Target: LdkLogger,
{
	pending_connections:
		Mutex<HashMap<PublicKey, Vec<tokio::sync::oneshot::Sender<Result<(), Error>>>>>,
	peer_manager: Arc<PeerManager>,
	tor_proxy_addr: Option<core::net::SocketAddr>,
	tor_proxy_rng: Arc<RandomBytes>,
	logger: L,
}

impl<L: Deref + Clone + Sync + Send> ConnectionManager<L>
where
	L::Target: LdkLogger,
{
	pub(crate) fn new(
		peer_manager: Arc<PeerManager>, tor_proxy_addr: Option<core::net::SocketAddr>,
		ephemeral_random_data: [u8; 32], logger: L,
	) -> Self {
		let pending_connections = Mutex::new(HashMap::new());
		let tor_proxy_rng = Arc::new(RandomBytes::new(ephemeral_random_data));

		Self { pending_connections, peer_manager, tor_proxy_addr, tor_proxy_rng, logger }
	}

	pub(crate) async fn connect_peer_if_necessary(
		&self, node_id: PublicKey, addr: SocketAddress,
	) -> Result<(), Error> {
		if self.peer_manager.peer_by_node_id(&node_id).is_some() {
			return Ok(());
		}

		self.do_connect_peer(node_id, addr).await
	}

	pub(crate) async fn do_connect_peer(
		&self, node_id: PublicKey, addr: SocketAddress,
	) -> Result<(), Error> {
		// First, we check if there is already an outbound connection in flight, if so, we just
		// await on the corresponding watch channel. The task driving the connection future will
		// send us the result..
		let pending_ready_receiver_opt = self.register_or_subscribe_pending_connection(&node_id);
		if let Some(pending_connection_ready_receiver) = pending_ready_receiver_opt {
			return pending_connection_ready_receiver.await.map_err(|e| {
				debug_assert!(false, "Failed to receive connection result: {:?}", e);
				log_error!(self.logger, "Failed to receive connection result: {:?}", e);
				Error::ConnectionFailed
			})?;
		}

		log_info!(self.logger, "Connecting to peer: {}@{}", node_id, addr);

		let res = if let SocketAddress::OnionV2(old_onion_addr) = addr {
			log_error!(
				self.logger,
				"Failed to resolve network address {:?}: Resolution of OnionV2 addresses is currently unsupported.",
				old_onion_addr
			);
			self.propagate_result_to_subscribers(&node_id, Err(Error::InvalidSocketAddress));
			return Err(Error::InvalidSocketAddress);
		} else if let SocketAddress::OnionV3 { .. } = addr {
			let proxy_addr = self.tor_proxy_addr.ok_or_else(|| {
				log_error!(
					self.logger,
					"Failed to resolve network address {:?}: Tor proxy address is unset.",
					addr
				);
				self.propagate_result_to_subscribers(&node_id, Err(Error::InvalidSocketAddress));
				Error::InvalidSocketAddress
			})?;
			let rng = self.tor_proxy_rng.clone();
			let pm = Arc::clone(&self.peer_manager);
			let addr_clone = addr.clone();
			let connection_future = async move {
				let connect_fut = async {
					tor_socks5_connect(addr_clone.clone(), proxy_addr, &*rng)
						.await
						.and_then(|s| {
							s.into_std()
								.map_err(|e| format!("Failed to convert tokio TcpStream to std: {}", e))
						})
				};
				match tokio::time::timeout(
					Duration::from_secs(TOR_CONNECT_OUTBOUND_TIMEOUT),
					connect_fut,
				)
				.await
				{
					Ok(Ok(stream)) => {
						Some(lightning_net_tokio::setup_outbound(pm, node_id, stream))
					},
					Ok(Err(_)) => None,
					Err(_) => None,
				}
			};
			self.await_connection(connection_future, node_id, addr).await
		} else {
			let socket_addr = addr
				.to_socket_addrs()
				.map_err(|e| {
					log_error!(self.logger, "Failed to resolve network address {}: {}", addr, e);
					self.propagate_result_to_subscribers(
						&node_id,
						Err(Error::InvalidSocketAddress),
					);
					Error::InvalidSocketAddress
				})?
				.next()
				.ok_or_else(|| {
					log_error!(self.logger, "Failed to resolve network address {}", addr);
					self.propagate_result_to_subscribers(
						&node_id,
						Err(Error::InvalidSocketAddress),
					);
					Error::InvalidSocketAddress
				})?;
			let connection_future = lightning_net_tokio::connect_outbound(
				Arc::clone(&self.peer_manager),
				node_id,
				socket_addr,
			);
			self.await_connection(connection_future, node_id, addr).await
		};

		self.propagate_result_to_subscribers(&node_id, res);

		res
	}

	async fn await_connection<F, CF>(
		&self, connection_future: F, node_id: PublicKey, addr: SocketAddress,
	) -> Result<(), Error>
	where
		F: std::future::Future<Output = Option<CF>>,
		CF: std::future::Future<Output = ()>,
	{
		match connection_future.await {
			Some(connection_closed_future) => {
				let mut connection_closed_future = Box::pin(connection_closed_future);
				loop {
					tokio::select! {
						_ = &mut connection_closed_future => {
							log_info!(self.logger, "Peer connection closed: {}@{}", node_id, addr);
							break Err(Error::ConnectionFailed);
						},
						_ = tokio::time::sleep(Duration::from_millis(10)) => {},
					};

					match self.peer_manager.peer_by_node_id(&node_id) {
						Some(_) => break Ok(()),
						None => continue,
					}
				}
			},
			None => {
				log_error!(self.logger, "Failed to connect to peer: {}@{}", node_id, addr);
				Err(Error::ConnectionFailed)
			},
		}
	}

	fn register_or_subscribe_pending_connection(
		&self, node_id: &PublicKey,
	) -> Option<tokio::sync::oneshot::Receiver<Result<(), Error>>> {
		let mut pending_connections_lock = self.pending_connections.lock().unwrap();
		match pending_connections_lock.entry(*node_id) {
			hash_map::Entry::Occupied(mut entry) => {
				let (tx, rx) = tokio::sync::oneshot::channel();
				entry.get_mut().push(tx);
				Some(rx)
			},
			hash_map::Entry::Vacant(entry) => {
				entry.insert(Vec::new());
				None
			},
		}
	}

	fn propagate_result_to_subscribers(&self, node_id: &PublicKey, res: Result<(), Error>) {
		// Send the result to any other tasks that might be waiting on it by now.
		let mut pending_connections_lock = self.pending_connections.lock().unwrap();
		if let Some(connection_ready_senders) = pending_connections_lock.remove(node_id) {
			for sender in connection_ready_senders {
				let _ = sender.send(res).map_err(|e| {
					debug_assert!(
						false,
						"Failed to send connection result to subscribers: {:?}",
						e
					);
					log_error!(
						self.logger,
						"Failed to send connection result to subscribers: {:?}",
						e
					);
				});
			}
		}
	}
}

/// Connect to a peer's SocketAddress through a Tor SOCKS5 proxy.
/// Uses Tor stream isolation via username/password auth (RFC 1929 + Tor extensions).
async fn tor_socks5_connect<ES: Deref>(
	addr: SocketAddress, tor_proxy_addr: core::net::SocketAddr, entropy_source: ES,
) -> Result<TcpStream, String>
where
	ES::Target: EntropySource,
{
	use std::io::Write;

	// SOCKS5 constants (RFC 1928 / RFC 1929)
	const VERSION: u8 = 5;
	const NMETHODS: u8 = 1;
	const USERNAME_PASSWORD_AUTH: u8 = 2;
	const METHOD_SELECT_REPLY_LEN: usize = 2;
	const USERNAME_PASSWORD_VERSION: u8 = 1;
	const USERNAME_PASSWORD_REPLY_LEN: usize = 2;
	const CMD_CONNECT: u8 = 1;
	const RSV: u8 = 0;
	const ATYP_DOMAINNAME: u8 = 3;
	const ATYP_IPV4: u8 = 1;
	const ATYP_IPV6: u8 = 4;
	const SUCCESS: u8 = 0;

	// Tor extensions for stream isolation
	const USERNAME: &[u8] = b"<torS0X>0";
	const USERNAME_LEN: usize = USERNAME.len();
	const PASSWORD_ENTROPY_LEN: usize = 32;
	const PASSWORD_LEN: usize = PASSWORD_ENTROPY_LEN * 2; // hex-encoded

	const IPV4_ADDR_LEN: usize = 4;
	const IPV6_ADDR_LEN: usize = 16;
	const HOSTNAME_MAX_LEN: usize = u8::MAX as usize;

	const USERNAME_PASSWORD_REQUEST_LEN: usize =
		1 + 1 + USERNAME_LEN + 1 + PASSWORD_LEN;
	const SOCKS5_REQUEST_MAX_LEN: usize =
		1 + 1 + 1 + 1 + 1 + HOSTNAME_MAX_LEN + 2;
	const SOCKS5_REPLY_HEADER_LEN: usize = 4; // VER + REP + RSV + ATYP

	// Step 1: Connect to the SOCKS5 proxy
	let mut tcp_stream = TcpStream::connect(&tor_proxy_addr).await.map_err(|e| format!("SOCKS5 TCP connect to proxy {} failed: {}", tor_proxy_addr, e))?;

	// Step 2: Method selection — request username/password auth
	let method_selection_request = [VERSION, NMETHODS, USERNAME_PASSWORD_AUTH];
	tcp_stream.write_all(&method_selection_request).await.map_err(|e| format!("SOCKS5 method selection write failed: {}", e))?;

	let mut method_selection_reply = [0u8; METHOD_SELECT_REPLY_LEN];
	tcp_stream.read_exact(&mut method_selection_reply).await.map_err(|e| format!("SOCKS5 method selection read failed: {}", e))?;
	if method_selection_reply != [VERSION, USERNAME_PASSWORD_AUTH] {
		return Err(format!("SOCKS5 method selection failed: got {:?}, expected [{}, {}]", method_selection_reply, VERSION, USERNAME_PASSWORD_AUTH));
	}

	// Step 3: Authenticate with random password for Tor stream isolation
	let password: [u8; PASSWORD_ENTROPY_LEN] = entropy_source.get_secure_random_bytes();
	let mut username_password_request = [0u8; USERNAME_PASSWORD_REQUEST_LEN];
	{
		let mut stream = &mut username_password_request[..];
		stream.write_all(&[USERNAME_PASSWORD_VERSION, USERNAME_LEN as u8]).unwrap();
		stream.write_all(USERNAME).unwrap();
		stream.write_all(&[PASSWORD_LEN as u8]).unwrap();
		for byte in password {
			write!(stream, "{:02x}", byte).unwrap();
		}
	}
	tcp_stream.write_all(&username_password_request).await.map_err(|e| format!("SOCKS5 auth write failed: {}", e))?;

	let mut auth_reply = [0u8; USERNAME_PASSWORD_REPLY_LEN];
	tcp_stream.read_exact(&mut auth_reply).await.map_err(|e| format!("SOCKS5 auth read failed: {}", e))?;
	if auth_reply[1] != SUCCESS {
		return Err(format!("SOCKS5 auth failed: reply {:?}", auth_reply));
	}

	// Step 4: Send CONNECT request for the target address
	let mut socks5_request = [0u8; SOCKS5_REQUEST_MAX_LEN];
	let request_len = {
		let mut stream = &mut socks5_request[..];
		stream.write_all(&[VERSION, CMD_CONNECT, RSV]).unwrap();

		match &addr {
			SocketAddress::OnionV3 { ed25519_pubkey, checksum, version, port } => {
				// Encode as domain name (base32 .onion hostname)
				// OnionV3 address = base32(pubkey[32] || checksum[2] || version[1]) + ".onion"
				let mut raw = Vec::with_capacity(35);
				raw.extend_from_slice(ed25519_pubkey);
				raw.push((checksum >> 8) as u8);
				raw.push(*checksum as u8);
				raw.push(*version);
				let encoded = base32_encode_lowercase(&raw);
				let mut onion_host = encoded.into_bytes();
				onion_host.extend_from_slice(b".onion");

				stream.write_all(&[ATYP_DOMAINNAME, onion_host.len() as u8]).unwrap();
				stream.write_all(&onion_host).unwrap();
				stream.write_all(&port.to_be_bytes()).unwrap();
			},
			SocketAddress::TcpIpV4 { addr: ip, port } => {
				stream.write_all(&[ATYP_IPV4]).unwrap();
				stream.write_all(ip).unwrap();
				stream.write_all(&port.to_be_bytes()).unwrap();
			},
			SocketAddress::TcpIpV6 { addr: ip, port } => {
				stream.write_all(&[ATYP_IPV6]).unwrap();
				stream.write_all(ip).unwrap();
				stream.write_all(&port.to_be_bytes()).unwrap();
			},
			SocketAddress::Hostname { hostname, port } => {
				let host_str = hostname.to_string();
				let host_bytes = host_str.as_bytes();
				stream.write_all(&[ATYP_DOMAINNAME, host_bytes.len() as u8]).unwrap();
				stream.write_all(host_bytes).unwrap();
				stream.write_all(&port.to_be_bytes()).unwrap();
			},
			_ => return Err(format!("SOCKS5 unsupported address type: {:?}", addr)),
		}

		SOCKS5_REQUEST_MAX_LEN - stream.len()
	};

	tcp_stream.write_all(&socks5_request[..request_len]).await.map_err(|e| format!("SOCKS5 CONNECT write failed: {}", e))?;

	// Step 5: Read SOCKS5 reply
	let mut reply_header = [0u8; SOCKS5_REPLY_HEADER_LEN];
	tcp_stream.read_exact(&mut reply_header).await.map_err(|e| format!("SOCKS5 reply read failed: {}", e))?;

	if reply_header[1] != SUCCESS {
		let error_desc = match reply_header[1] {
			1 => "general failure",
			2 => "connection not allowed",
			3 => "network unreachable",
			4 => "host unreachable",
			5 => "connection refused",
			6 => "TTL expired",
			7 => "command not supported",
			8 => "address type not supported",
			_ => "unknown",
		};
		return Err(format!("SOCKS5 CONNECT failed: {} (code {})", error_desc, reply_header[1]));
	}

	// Consume the bound address from the reply
	let addr_len = match reply_header[3] {
		ATYP_IPV4 => IPV4_ADDR_LEN + 2,
		ATYP_IPV6 => IPV6_ADDR_LEN + 2,
		ATYP_DOMAINNAME => {
			let mut len_buf = [0u8; 1];
			tcp_stream.read_exact(&mut len_buf).await.map_err(|e| format!("SOCKS5 domain len read failed: {}", e))?;
			len_buf[0] as usize + 2
		},
		_ => return Err(format!("SOCKS5 unknown bound address type: {}", reply_header[3])),
	};
	let mut addr_buf = vec![0u8; addr_len];
	tcp_stream.read_exact(&mut addr_buf).await.map_err(|e| format!("SOCKS5 bound addr read failed: {}", e))?;

	Ok(tcp_stream)
}

/// RFC 4648 base32 encoding (lowercase, no padding) for onion v3 address derivation.
fn base32_encode_lowercase(data: &[u8]) -> String {
	const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
	let mut result = String::with_capacity((data.len() * 8 + 4) / 5);
	let mut buffer: u64 = 0;
	let mut bits_left = 0;

	for &byte in data {
		buffer = (buffer << 8) | byte as u64;
		bits_left += 8;
		while bits_left >= 5 {
			bits_left -= 5;
			result.push(ALPHABET[((buffer >> bits_left) & 0x1f) as usize] as char);
		}
	}

	if bits_left > 0 {
		buffer <<= 5 - bits_left;
		result.push(ALPHABET[(buffer & 0x1f) as usize] as char);
	}

	result
}
