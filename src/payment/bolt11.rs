// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Holds a payment handler allowing to create and pay [BOLT 11] invoices.
//!
//! [BOLT 11]: https://github.com/lightning/bolts/blob/master/11-payment-encoding.md

use std::str::FromStr;
use std::sync::{Arc, RwLock};

use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::Hash;
use lightning::ln::channelmanager::{
	Bolt11InvoiceParameters, Bolt11PaymentError, PaymentId, RecipientOnionFields, Retry,
	RetryableSendFailure,
};
use lightning::routing::router::{
	PaymentParameters, Route, RouteHint, RouteHintHop, RouteParameters, RouteParametersConfig,
	Router as LdkRouter,
};
use lightning_invoice::{
	Bolt11Invoice as LdkBolt11Invoice, Bolt11InvoiceDescription as LdkBolt11InvoiceDescription,
	DEFAULT_MIN_FINAL_CLTV_EXPIRY_DELTA,
};
use lightning_types::payment::{PaymentHash, PaymentPreimage};
use lightning_types::routing::RoutingFees;

use crate::config::{Config, LDK_PAYMENT_RETRY_TIMEOUT};
use crate::connection::ConnectionManager;
use crate::data_store::DataStoreUpdateResult;
use crate::error::Error;
use crate::ffi::{maybe_deref, maybe_try_convert_enum, maybe_wrap};
use crate::liquidity::LiquiditySource;
use crate::logger::{log_error, log_info, LdkLogger, Logger};
use crate::payment::store::{
	LSPFeeLimits, PaymentDetails, PaymentDetailsUpdate, PaymentDirection, PaymentKind,
	PaymentStatus,
};
use crate::peer_store::{PeerInfo, PeerStore};
use crate::runtime::Runtime;
use crate::types::{
	ChannelManager, CircularRouteHop, CircularRoutePath, CircularRouteQuote, PaymentStore, Router,
};
use crate::UserChannelId;

fn circular_path_uses_exact_channels(
	path: &lightning::routing::router::Path, first_hop_node_id: bitcoin::secp256k1::PublicKey,
	first_hop_scid: u64, synthetic_payee: bitcoin::secp256k1::PublicKey, last_hop_scid: u64,
) -> bool {
	let first_matches = path.hops.first().map_or(false, |hop| {
		hop.pubkey == first_hop_node_id && hop.short_channel_id == first_hop_scid
	});
	let last_matches = path.hops.last().map_or(false, |hop| {
		hop.pubkey == synthetic_payee && hop.short_channel_id == last_hop_scid
	});
	first_matches && last_matches
}

/// Convert the synthetic pathfinding destination into the real local recipient while preserving
/// the exact reviewed first- and last-hop channels. Clearing `route_params` is intentional:
/// `send_payment_with_route` reconstructs fixed-route parameters from the real final hop and uses
/// zero automatic retries, so no synthetic payee identity survives into payment construction.
fn finalize_circular_route(
	mut route: Route, first_hop_node_id: bitcoin::secp256k1::PublicKey, first_hop_scid: u64,
	synthetic_payee: bitcoin::secp256k1::PublicKey, last_hop_scid: u64,
	local_node_id: bitcoin::secp256k1::PublicKey,
) -> Result<Route, Error> {
	if route.paths.is_empty()
		|| route.paths.iter().any(|path| {
			path.blinded_tail.is_some()
				|| !circular_path_uses_exact_channels(
					path,
					first_hop_node_id,
					first_hop_scid,
					synthetic_payee,
					last_hop_scid,
				)
		}) {
		return Err(Error::PaymentSendingFailed);
	}

	for path in &mut route.paths {
		let last_hop = path.hops.last_mut().ok_or(Error::PaymentSendingFailed)?;
		last_hop.pubkey = local_node_id;
	}
	// The original parameters name the synthetic payee and must never be used by a real send.
	route.route_params = None;

	Ok(route)
}

#[cfg(not(feature = "uniffi"))]
type Bolt11Invoice = LdkBolt11Invoice;
#[cfg(feature = "uniffi")]
type Bolt11Invoice = Arc<crate::ffi::Bolt11Invoice>;

#[cfg(not(feature = "uniffi"))]
type Bolt11InvoiceDescription = LdkBolt11InvoiceDescription;
#[cfg(feature = "uniffi")]
type Bolt11InvoiceDescription = crate::ffi::Bolt11InvoiceDescription;

/// A payment handler allowing to create and pay [BOLT 11] invoices.
///
/// Should be retrieved by calling [`Node::bolt11_payment`].
///
/// [BOLT 11]: https://github.com/lightning/bolts/blob/master/11-payment-encoding.md
/// [`Node::bolt11_payment`]: crate::Node::bolt11_payment
pub struct Bolt11Payment {
	runtime: Arc<Runtime>,
	channel_manager: Arc<ChannelManager>,
	router: Arc<Router>,
	connection_manager: Arc<ConnectionManager<Arc<Logger>>>,
	liquidity_source: Option<Arc<LiquiditySource<Arc<Logger>>>>,
	payment_store: Arc<PaymentStore>,
	peer_store: Arc<PeerStore<Arc<Logger>>>,
	config: Arc<Config>,
	is_running: Arc<RwLock<bool>>,
	logger: Arc<Logger>,
}

impl Bolt11Payment {
	pub(crate) fn new(
		runtime: Arc<Runtime>, channel_manager: Arc<ChannelManager>, router: Arc<Router>,
		connection_manager: Arc<ConnectionManager<Arc<Logger>>>,
		liquidity_source: Option<Arc<LiquiditySource<Arc<Logger>>>>,
		payment_store: Arc<PaymentStore>, peer_store: Arc<PeerStore<Arc<Logger>>>,
		config: Arc<Config>, is_running: Arc<RwLock<bool>>, logger: Arc<Logger>,
	) -> Self {
		Self {
			runtime,
			channel_manager,
			router,
			connection_manager,
			liquidity_source,
			payment_store,
			peer_store,
			config,
			is_running,
			logger,
		}
	}

	/// Find a circular route pinned to exact local first- and last-hop channels without sending
	/// anything.
	///
	/// LDK intentionally rejects ordinary route searches whose payer and payee are the same node.
	/// To make this a pure pathfinding operation, this method searches toward an unreachable
	/// synthetic payee behind the selected inbound channel, then replaces that synthetic terminal
	/// identity with the local node in the returned quote. The selected inbound SCID still comes
	/// from the exact local channel and every path is validated before it is returned.
	///
	/// This method does not create an invoice, send a probe or HTLC, or write to the payment store.
	pub fn quote_circular_route(
		&self, amount_msat: u64, first_hop_user_channel_id: &UserChannelId,
		last_hop_user_channel_id: &UserChannelId, route_parameters: Option<RouteParametersConfig>,
	) -> Result<CircularRouteQuote, Error> {
		if !*self.is_running.read().unwrap() {
			return Err(Error::NotRunning);
		}
		if amount_msat == 0 {
			return Err(Error::InvalidAmount);
		}
		if first_hop_user_channel_id == last_hop_user_channel_id {
			log_error!(self.logger, "Circular route requires two distinct local channels.");
			return Err(Error::InvalidChannelId);
		}

		let usable_channels = self.channel_manager.list_usable_channels();
		let first_hop = usable_channels
			.iter()
			.find(|channel| channel.user_channel_id == first_hop_user_channel_id.0)
			.ok_or_else(|| {
				log_error!(
					self.logger,
					"Selected circular-route first-hop channel {} is not usable.",
					first_hop_user_channel_id
				);
				Error::InvalidChannelId
			})?;
		let first_hop_scid = first_hop.get_outbound_payment_scid().ok_or_else(|| {
			log_error!(self.logger, "Selected circular-route first hop has no outbound SCID.");
			Error::InvalidChannelId
		})?;

		let channels = self.channel_manager.list_channels();
		let last_hop = channels
			.iter()
			.find(|channel| channel.user_channel_id == last_hop_user_channel_id.0)
			.ok_or_else(|| {
				log_error!(
					self.logger,
					"Selected circular-route last-hop channel {} was not found.",
					last_hop_user_channel_id
				);
				Error::InvalidChannelId
			})?;
		if !last_hop.is_usable {
			log_error!(
				self.logger,
				"Selected circular-route last-hop channel {} is not usable.",
				last_hop_user_channel_id
			);
			return Err(Error::InvalidChannelId);
		}
		if last_hop.inbound_capacity_msat < amount_msat {
			log_error!(
				self.logger,
				"Selected circular-route last-hop channel {} has insufficient inbound capacity.",
				last_hop_user_channel_id
			);
			return Err(Error::InsufficientFunds);
		}
		let last_hop_scid = last_hop.get_inbound_payment_scid().ok_or_else(|| {
			log_error!(self.logger, "Selected circular-route last hop has no inbound SCID.");
			Error::InvalidChannelId
		})?;
		let forwarding_info = last_hop.counterparty.forwarding_info.as_ref().ok_or_else(|| {
			log_error!(
				self.logger,
				"Selected circular-route last hop has no counterparty forwarding policy."
			);
			Error::InvalidChannelId
		})?;

		// This is secp256k1's generator public key (private key 1). It is intentionally unusable as
		// a real destination here. Exact final-hop validation below ensures pathfinding can only use
		// it behind the selected local inbound channel.
		let synthetic_payee = bitcoin::secp256k1::PublicKey::from_str(
			"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
		)
		.expect("hard-coded synthetic payee public key is valid");
		if synthetic_payee == self.channel_manager.get_our_node_id() {
			log_error!(self.logger, "Synthetic circular-route payee collides with local node ID.");
			return Err(Error::InvalidNodeId);
		}

		let route_hint = RouteHint(vec![RouteHintHop {
			src_node_id: last_hop.counterparty.node_id,
			short_channel_id: last_hop_scid,
			fees: RoutingFees {
				base_msat: forwarding_info.fee_base_msat,
				proportional_millionths: forwarding_info.fee_proportional_millionths,
			},
			cltv_expiry_delta: forwarding_info.cltv_expiry_delta,
			htlc_minimum_msat: last_hop.inbound_htlc_minimum_msat,
			htlc_maximum_msat: last_hop.inbound_htlc_maximum_msat,
		}]);
		let route_parameters =
			route_parameters.or(self.config.route_parameters).unwrap_or_default();
		let mut payment_params = PaymentParameters::from_node_id(
			synthetic_payee,
			DEFAULT_MIN_FINAL_CLTV_EXPIRY_DELTA as u32,
		)
		.with_route_hints(vec![route_hint])
		.expect("clear payment parameters accept clear route hints");
		payment_params.max_total_cltv_expiry_delta = route_parameters.max_total_cltv_expiry_delta;
		payment_params.max_path_count = route_parameters.max_path_count;
		payment_params.max_channel_saturation_power_of_half =
			route_parameters.max_channel_saturation_power_of_half;
		let mut route_params =
			RouteParameters::from_payment_params_and_value(payment_params, amount_msat);
		route_params.max_total_routing_fee_msat = route_parameters.max_total_routing_fee_msat;

		let mut quote_material = Vec::with_capacity(16 + 16 + 8);
		quote_material.extend_from_slice(&first_hop.user_channel_id.to_be_bytes());
		quote_material.extend_from_slice(&last_hop.user_channel_id.to_be_bytes());
		quote_material.extend_from_slice(&amount_msat.to_be_bytes());
		let quote_hash = Sha256::hash(&quote_material).to_byte_array();
		let first_hops = [first_hop];
		let route = self
			.router
			.find_route_with_id(
				&self.channel_manager.get_our_node_id(),
				&route_params,
				Some(&first_hops),
				self.channel_manager.compute_inflight_htlcs(),
				PaymentHash(quote_hash),
				PaymentId(quote_hash),
			)
			.map_err(|e| {
				log_error!(
					self.logger,
					"Failed to quote circular route from channel {} to channel {}: {}",
					first_hop_user_channel_id,
					last_hop_user_channel_id,
					e
				);
				Error::PaymentSendingFailed
			})?;

		let our_node_id = self.channel_manager.get_our_node_id();
		let route = finalize_circular_route(
			route,
			first_hop.counterparty.node_id,
			first_hop_scid,
			synthetic_payee,
			last_hop_scid,
			our_node_id,
		)
		.map_err(|e| {
			log_error!(
				self.logger,
				"Refused circular route that did not exclusively use the selected first and last hops."
			);
			e
		})?;
		let paths = route
			.paths
			.iter()
			.map(|path| CircularRoutePath {
				hops: path
					.hops
					.iter()
					.map(|hop| CircularRouteHop {
						node_id: hop.pubkey,
						short_channel_id: hop.short_channel_id,
						fee_msat: hop.fee_msat,
						cltv_expiry_delta: hop.cltv_expiry_delta,
					})
					.collect(),
				amount_msat: path.final_value_msat(),
				fee_msat: path.fee_msat(),
			})
			.collect();

		Ok(CircularRouteQuote {
			amount_msat,
			total_routing_fee_msat: route.get_total_fees(),
			first_hop_user_channel_id: *first_hop_user_channel_id,
			first_hop_short_channel_id: first_hop_scid,
			last_hop_user_channel_id: *last_hop_user_channel_id,
			last_hop_short_channel_id: last_hop_scid,
			paths,
		})
	}

	/// Send a fixed-amount invoice using exactly one local channel as the first hop.
	///
	/// Route construction receives only the selected channel. The resulting route is verified before
	/// it is handed to [`ChannelManager::send_payment_with_route`], which disables automatic retries.
	/// A failed attempt therefore never falls back to another local channel.
	pub fn send_with_first_hop(
		&self, invoice: &Bolt11Invoice, first_hop_user_channel_id: &UserChannelId,
		route_parameters: Option<RouteParametersConfig>,
	) -> Result<PaymentId, Error> {
		if !*self.is_running.read().unwrap() {
			return Err(Error::NotRunning);
		}

		let invoice = maybe_deref(invoice);
		let amount_msat = invoice.amount_milli_satoshis().ok_or_else(|| {
			log_error!(self.logger, "Pinned first-hop payments require a fixed-amount invoice.");
			Error::InvalidInvoice
		})?;
		let payment_hash = PaymentHash(invoice.payment_hash().to_byte_array());
		let payment_id = PaymentId(invoice.payment_hash().to_byte_array());

		if let Some(payment) = self.payment_store.get(&payment_id) {
			if payment.status == PaymentStatus::Pending
				|| payment.status == PaymentStatus::Succeeded
			{
				log_error!(self.logger, "Payment error: an invoice must not be paid twice.");
				return Err(Error::DuplicatePayment);
			}
		}

		let usable_channels = self.channel_manager.list_usable_channels();
		let selected_channel = usable_channels
			.iter()
			.find(|channel| channel.user_channel_id == first_hop_user_channel_id.0)
			.ok_or_else(|| {
				log_error!(
					self.logger,
					"Selected first-hop channel {} is not usable.",
					first_hop_user_channel_id
				);
				Error::InvalidChannelId
			})?;

		let route_parameters =
			route_parameters.or(self.config.route_parameters).unwrap_or_default();
		let payment_params = PaymentParameters::from_bolt11_invoice(invoice);
		let mut route_params =
			RouteParameters::from_payment_params_and_value(payment_params, amount_msat);
		route_params.max_total_routing_fee_msat = route_parameters.max_total_routing_fee_msat;
		route_params.payment_params.max_total_cltv_expiry_delta =
			route_parameters.max_total_cltv_expiry_delta;
		route_params.payment_params.max_path_count = route_parameters.max_path_count;
		route_params.payment_params.max_channel_saturation_power_of_half =
			route_parameters.max_channel_saturation_power_of_half;

		let first_hops = [selected_channel];
		let route = self
			.router
			.find_route_with_id(
				&self.channel_manager.get_our_node_id(),
				&route_params,
				Some(&first_hops),
				self.channel_manager.compute_inflight_htlcs(),
				payment_hash,
				payment_id,
			)
			.map_err(|e| {
				log_error!(
					self.logger,
					"Failed to find a route through selected first-hop channel {}: {}",
					first_hop_user_channel_id,
					e
				);
				Error::PaymentSendingFailed
			})?;

		let route_uses_only_selected_first_hop = !route.paths.is_empty()
			&& route.paths.iter().all(|path| {
				path.hops.first().map_or(false, |first_hop| {
					first_hop.pubkey == selected_channel.counterparty.node_id
						&& (selected_channel.short_channel_id == Some(first_hop.short_channel_id)
							|| selected_channel.outbound_scid_alias
								== Some(first_hop.short_channel_id))
				})
			});
		if !route_uses_only_selected_first_hop {
			log_error!(
				self.logger,
				"Refused route that did not exclusively use selected first-hop channel {}.",
				first_hop_user_channel_id
			);
			return Err(Error::PaymentSendingFailed);
		}

		let mut recipient_onion = RecipientOnionFields::secret_only(*invoice.payment_secret());
		recipient_onion.payment_metadata = invoice.payment_metadata().cloned();

		self.channel_manager
			.send_payment_with_route(route, payment_hash, recipient_onion, payment_id)
			.map_err(|e| {
				log_error!(
					self.logger,
					"Failed to send payment through selected first-hop channel {}: {:?}",
					first_hop_user_channel_id,
					e
				);
				match e {
					RetryableSendFailure::DuplicatePayment => Error::DuplicatePayment,
					_ => Error::PaymentSendingFailed,
				}
			})?;

		let kind = PaymentKind::Bolt11 {
			hash: payment_hash,
			preimage: None,
			secret: Some(*invoice.payment_secret()),
			bolt11_invoice: Some(invoice.to_string()),
		};
		let payment = PaymentDetails::new(
			payment_id,
			kind,
			Some(amount_msat),
			None,
			PaymentDirection::Outbound,
			PaymentStatus::Pending,
		);
		self.payment_store.insert(payment)?;

		log_info!(
			self.logger,
			"Initiated sending {}msat through selected first-hop channel {}",
			amount_msat,
			first_hop_user_channel_id
		);
		Ok(payment_id)
	}

	/// Send a payment given an invoice.
	///
	/// If `route_parameters` are provided they will override the default as well as the
	/// node-wide parameters configured via [`Config::route_parameters`] on a per-field basis.
	pub fn send(
		&self, invoice: &Bolt11Invoice, route_parameters: Option<RouteParametersConfig>,
	) -> Result<PaymentId, Error> {
		if !*self.is_running.read().unwrap() {
			return Err(Error::NotRunning);
		}

		let invoice = maybe_deref(invoice);
		let payment_hash = PaymentHash(invoice.payment_hash().to_byte_array());
		let payment_id = PaymentId(invoice.payment_hash().to_byte_array());
		if let Some(payment) = self.payment_store.get(&payment_id) {
			if payment.status == PaymentStatus::Pending
				|| payment.status == PaymentStatus::Succeeded
			{
				log_error!(self.logger, "Payment error: an invoice must not be paid twice.");
				return Err(Error::DuplicatePayment);
			}
		}

		let route_parameters =
			route_parameters.or(self.config.route_parameters).unwrap_or_default();
		let retry_strategy = Retry::Timeout(LDK_PAYMENT_RETRY_TIMEOUT);
		let payment_secret = Some(*invoice.payment_secret());

		match self.channel_manager.pay_for_bolt11_invoice(
			invoice,
			payment_id,
			None,
			route_parameters,
			retry_strategy,
		) {
			Ok(()) => {
				let payee_pubkey = invoice.recover_payee_pub_key();
				let amt_msat = invoice.amount_milli_satoshis().unwrap();
				log_info!(self.logger, "Initiated sending {}msat to {}", amt_msat, payee_pubkey);

				let kind = PaymentKind::Bolt11 {
					hash: payment_hash,
					preimage: None,
					secret: payment_secret,
					bolt11_invoice: Some(invoice.to_string()),
				};
				let payment = PaymentDetails::new(
					payment_id,
					kind,
					invoice.amount_milli_satoshis(),
					None,
					PaymentDirection::Outbound,
					PaymentStatus::Pending,
				);

				self.payment_store.insert(payment)?;

				Ok(payment_id)
			},
			Err(Bolt11PaymentError::InvalidAmount) => {
				log_error!(self.logger,
					"Failed to send payment due to the given invoice being \"zero-amount\". Please use send_using_amount instead."
				);
				return Err(Error::InvalidInvoice);
			},
			Err(Bolt11PaymentError::SendingFailed(e)) => {
				log_error!(self.logger, "Failed to send payment: {:?}", e);
				match e {
					RetryableSendFailure::DuplicatePayment => Err(Error::DuplicatePayment),
					_ => {
						let kind = PaymentKind::Bolt11 {
							hash: payment_hash,
							preimage: None,
							secret: payment_secret,
							bolt11_invoice: Some(invoice.to_string()),
						};
						let payment = PaymentDetails::new(
							payment_id,
							kind,
							invoice.amount_milli_satoshis(),
							None,
							PaymentDirection::Outbound,
							PaymentStatus::Failed,
						);

						self.payment_store.insert(payment)?;
						Err(Error::PaymentSendingFailed)
					},
				}
			},
		}
	}

	/// Send a payment given an invoice and an amount in millisatoshis.
	///
	/// This will fail if the amount given is less than the value required by the given invoice.
	///
	/// This can be used to pay a so-called "zero-amount" invoice, i.e., an invoice that leaves the
	/// amount paid to be determined by the user.
	///
	/// If `route_parameters` are provided they will override the default as well as the
	/// node-wide parameters configured via [`Config::route_parameters`] on a per-field basis.
	pub fn send_using_amount(
		&self, invoice: &Bolt11Invoice, amount_msat: u64,
		route_parameters: Option<RouteParametersConfig>,
	) -> Result<PaymentId, Error> {
		if !*self.is_running.read().unwrap() {
			return Err(Error::NotRunning);
		}

		let invoice = maybe_deref(invoice);
		if let Some(invoice_amount_msat) = invoice.amount_milli_satoshis() {
			if amount_msat < invoice_amount_msat {
				log_error!(
					self.logger,
					"Failed to pay as the given amount needs to be at least the invoice amount: required {}msat, gave {}msat.", invoice_amount_msat, amount_msat);
				return Err(Error::InvalidAmount);
			}
		}

		let payment_hash = PaymentHash(invoice.payment_hash().to_byte_array());
		let payment_id = PaymentId(invoice.payment_hash().to_byte_array());
		if let Some(payment) = self.payment_store.get(&payment_id) {
			if payment.status == PaymentStatus::Pending
				|| payment.status == PaymentStatus::Succeeded
			{
				log_error!(self.logger, "Payment error: an invoice must not be paid twice.");
				return Err(Error::DuplicatePayment);
			}
		}

		let route_parameters =
			route_parameters.or(self.config.route_parameters).unwrap_or_default();
		let retry_strategy = Retry::Timeout(LDK_PAYMENT_RETRY_TIMEOUT);
		let payment_secret = Some(*invoice.payment_secret());

		match self.channel_manager.pay_for_bolt11_invoice(
			invoice,
			payment_id,
			Some(amount_msat),
			route_parameters,
			retry_strategy,
		) {
			Ok(()) => {
				let payee_pubkey = invoice.recover_payee_pub_key();
				log_info!(
					self.logger,
					"Initiated sending {} msat to {}",
					amount_msat,
					payee_pubkey
				);

				let kind = PaymentKind::Bolt11 {
					hash: payment_hash,
					preimage: None,
					bolt11_invoice: Some(invoice.to_string()),
					secret: payment_secret,
				};

				let payment = PaymentDetails::new(
					payment_id,
					kind,
					Some(amount_msat),
					None,
					PaymentDirection::Outbound,
					PaymentStatus::Pending,
				);

				self.payment_store.insert(payment)?;

				Ok(payment_id)
			},
			Err(Bolt11PaymentError::InvalidAmount) => {
				log_error!(
					self.logger,
					"Failed to send payment due to amount given being insufficient."
				);
				return Err(Error::InvalidInvoice);
			},
			Err(Bolt11PaymentError::SendingFailed(e)) => {
				log_error!(self.logger, "Failed to send payment: {:?}", e);
				match e {
					RetryableSendFailure::DuplicatePayment => Err(Error::DuplicatePayment),
					_ => {
						let kind = PaymentKind::Bolt11 {
							hash: payment_hash,
							preimage: None,
							secret: payment_secret,
							bolt11_invoice: Some(invoice.to_string()),
						};
						let payment = PaymentDetails::new(
							payment_id,
							kind,
							Some(amount_msat),
							None,
							PaymentDirection::Outbound,
							PaymentStatus::Failed,
						);

						self.payment_store.insert(payment)?;
						Err(Error::PaymentSendingFailed)
					},
				}
			},
		}
	}

	/// Allows to attempt manually claiming payments with the given preimage that have previously
	/// been registered via [`receive_for_hash`] or [`receive_variable_amount_for_hash`].
	///
	/// This should be called in reponse to a [`PaymentClaimable`] event as soon as the preimage is
	/// available.
	///
	/// Will check that the payment is known, and that the given preimage and claimable amount
	/// match our expectations before attempting to claim the payment, and will return an error
	/// otherwise.
	///
	/// When claiming the payment has succeeded, a [`PaymentReceived`] event will be emitted.
	///
	/// [`receive_for_hash`]: Self::receive_for_hash
	/// [`receive_variable_amount_for_hash`]: Self::receive_variable_amount_for_hash
	/// [`PaymentClaimable`]: crate::Event::PaymentClaimable
	/// [`PaymentReceived`]: crate::Event::PaymentReceived
	pub fn claim_for_hash(
		&self, payment_hash: PaymentHash, claimable_amount_msat: u64, preimage: PaymentPreimage,
	) -> Result<(), Error> {
		let payment_id = PaymentId(payment_hash.0);

		let expected_payment_hash = PaymentHash(Sha256::hash(&preimage.0).to_byte_array());

		if expected_payment_hash != payment_hash {
			log_error!(
				self.logger,
				"Failed to manually claim payment as the given preimage doesn't match the hash {}",
				payment_hash
			);
			return Err(Error::InvalidPaymentPreimage);
		}

		if let Some(details) = self.payment_store.get(&payment_id) {
			// For payments requested via `receive*_via_jit_channel_for_hash()`
			// `skimmed_fee_msat` held by LSP must be taken into account.
			let skimmed_fee_msat = match details.kind {
				PaymentKind::Bolt11Jit {
					counterparty_skimmed_fee_msat: Some(skimmed_fee_msat),
					..
				} => skimmed_fee_msat,
				_ => 0,
			};
			if let Some(invoice_amount_msat) = details.amount_msat {
				if claimable_amount_msat < invoice_amount_msat.saturating_sub(skimmed_fee_msat) {
					log_error!(
						self.logger,
						"Failed to manually claim payment {} as the claimable amount is less than expected",
						payment_id
					);
					return Err(Error::InvalidAmount);
				}
			}
		} else {
			log_error!(
				self.logger,
				"Failed to manually claim unknown payment with hash: {}",
				payment_hash
			);
			return Err(Error::InvalidPaymentHash);
		}

		self.channel_manager.claim_funds(preimage);
		Ok(())
	}

	/// Allows to manually fail payments with the given hash that have previously
	/// been registered via [`receive_for_hash`] or [`receive_variable_amount_for_hash`].
	///
	/// This should be called in reponse to a [`PaymentClaimable`] event if the payment needs to be
	/// failed back, e.g., if the correct preimage can't be retrieved in time before the claim
	/// deadline has been reached.
	///
	/// Will check that the payment is known before failing the payment, and will return an error
	/// otherwise.
	///
	/// [`receive_for_hash`]: Self::receive_for_hash
	/// [`receive_variable_amount_for_hash`]: Self::receive_variable_amount_for_hash
	/// [`PaymentClaimable`]: crate::Event::PaymentClaimable
	pub fn fail_for_hash(&self, payment_hash: PaymentHash) -> Result<(), Error> {
		let payment_id = PaymentId(payment_hash.0);

		let update = PaymentDetailsUpdate {
			status: Some(PaymentStatus::Failed),
			..PaymentDetailsUpdate::new(payment_id)
		};

		match self.payment_store.update(&update) {
			Ok(DataStoreUpdateResult::Updated) | Ok(DataStoreUpdateResult::Unchanged) => (),
			Ok(DataStoreUpdateResult::NotFound) => {
				log_error!(
					self.logger,
					"Failed to manually fail unknown payment with hash {}",
					payment_hash,
				);
				return Err(Error::InvalidPaymentHash);
			},
			Err(e) => {
				log_error!(
					self.logger,
					"Failed to manually fail payment with hash {}: {}",
					payment_hash,
					e
				);
				return Err(e);
			},
		}

		self.channel_manager.fail_htlc_backwards(&payment_hash);
		Ok(())
	}

	/// Returns a payable invoice that can be used to request and receive a payment of the amount
	/// given.
	///
	/// The inbound payment will be automatically claimed upon arrival.
	pub fn receive(
		&self, amount_msat: u64, description: &Bolt11InvoiceDescription, expiry_secs: u32,
	) -> Result<Bolt11Invoice, Error> {
		let description = maybe_try_convert_enum(description)?;
		let invoice =
			self.receive_inner(Some(amount_msat), &description, expiry_secs, None, None)?;
		Ok(maybe_wrap(invoice))
	}

	/// Returns a payable invoice that can be used to request a payment of the amount
	/// given for the given payment hash.
	///
	/// We will register the given payment hash and emit a [`PaymentClaimable`] event once
	/// the inbound payment arrives.
	///
	/// **Note:** users *MUST* handle this event and claim the payment manually via
	/// [`claim_for_hash`] as soon as they have obtained access to the preimage of the given
	/// payment hash. If they're unable to obtain the preimage, they *MUST* immediately fail the payment via
	/// [`fail_for_hash`].
	///
	/// [`PaymentClaimable`]: crate::Event::PaymentClaimable
	/// [`claim_for_hash`]: Self::claim_for_hash
	/// [`fail_for_hash`]: Self::fail_for_hash
	pub fn receive_for_hash(
		&self, amount_msat: u64, description: &Bolt11InvoiceDescription, expiry_secs: u32,
		payment_hash: PaymentHash,
	) -> Result<Bolt11Invoice, Error> {
		let description = maybe_try_convert_enum(description)?;
		let invoice = self.receive_inner(
			Some(amount_msat),
			&description,
			expiry_secs,
			Some(payment_hash),
			None,
		)?;
		Ok(maybe_wrap(invoice))
	}

	/// Returns a payable invoice that can be used to request a payment of the amount
	/// given for the given payment hash.
	///
	/// We will register the given payment hash and emit a [`PaymentClaimable`] event once
	/// the inbound payment arrives.
	///
	/// `min_cltv_expiry_delta` sets the minimum CLTV delta to use for the final hop.
	///
	/// **Note:** users *MUST* handle this event and claim the payment manually via
	/// [`claim_for_hash`] as soon as they have obtained access to the preimage of the given
	/// payment hash. If they're unable to obtain the preimage, they *MUST* immediately fail the payment via
	/// [`fail_for_hash`].
	///
	/// [`PaymentClaimable`]: crate::Event::PaymentClaimable
	/// [`claim_for_hash`]: Self::claim_for_hash
	/// [`fail_for_hash`]: Self::fail_for_hash
	pub fn receive_for_hash_with_min_cltv_expiry_delta(
		&self, amount_msat: u64, description: &Bolt11InvoiceDescription, expiry_secs: u32,
		payment_hash: PaymentHash, min_cltv_expiry_delta: u16,
	) -> Result<Bolt11Invoice, Error> {
		let description = maybe_try_convert_enum(description)?;
		let invoice = self.receive_inner(
			Some(amount_msat),
			&description,
			expiry_secs,
			Some(payment_hash),
			Some(min_cltv_expiry_delta),
		)?;
		Ok(maybe_wrap(invoice))
	}

	/// Returns a payable invoice that can be used to request and receive a payment for which the
	/// amount is to be determined by the user, also known as a "zero-amount" invoice.
	///
	/// The inbound payment will be automatically claimed upon arrival.
	pub fn receive_variable_amount(
		&self, description: &Bolt11InvoiceDescription, expiry_secs: u32,
	) -> Result<Bolt11Invoice, Error> {
		let description = maybe_try_convert_enum(description)?;
		let invoice = self.receive_inner(None, &description, expiry_secs, None, None)?;
		Ok(maybe_wrap(invoice))
	}

	/// Returns a payable invoice that can be used to request a payment for the given payment hash
	/// and the amount to be determined by the user, also known as a "zero-amount" invoice.
	///
	/// We will register the given payment hash and emit a [`PaymentClaimable`] event once
	/// the inbound payment arrives.
	///
	/// **Note:** users *MUST* handle this event and claim the payment manually via
	/// [`claim_for_hash`] as soon as they have obtained access to the preimage of the given
	/// payment hash. If they're unable to obtain the preimage, they *MUST* immediately fail the payment via
	/// [`fail_for_hash`].
	///
	/// [`PaymentClaimable`]: crate::Event::PaymentClaimable
	/// [`claim_for_hash`]: Self::claim_for_hash
	/// [`fail_for_hash`]: Self::fail_for_hash
	pub fn receive_variable_amount_for_hash(
		&self, description: &Bolt11InvoiceDescription, expiry_secs: u32, payment_hash: PaymentHash,
	) -> Result<Bolt11Invoice, Error> {
		let description = maybe_try_convert_enum(description)?;
		let invoice =
			self.receive_inner(None, &description, expiry_secs, Some(payment_hash), None)?;
		Ok(maybe_wrap(invoice))
	}

	/// Returns a payable invoice that can be used to request a payment for the given payment hash
	/// and the amount to be determined by the user, also known as a "zero-amount" invoice.
	///
	/// We will register the given payment hash and emit a [`PaymentClaimable`] event once
	/// the inbound payment arrives.
	///
	/// `min_cltv_expiry_delta` sets the minimum CLTV delta to use for the final hop.
	///
	/// **Note:** users *MUST* handle this event and claim the payment manually via
	/// [`claim_for_hash`] as soon as they have obtained access to the preimage of the given
	/// payment hash. If they're unable to obtain the preimage, they *MUST* immediately fail the payment via
	/// [`fail_for_hash`].
	///
	/// [`PaymentClaimable`]: crate::Event::PaymentClaimable
	/// [`claim_for_hash`]: Self::claim_for_hash
	/// [`fail_for_hash`]: Self::fail_for_hash
	pub fn receive_variable_amount_for_hash_with_min_cltv_expiry_delta(
		&self, description: &Bolt11InvoiceDescription, expiry_secs: u32, payment_hash: PaymentHash,
		min_cltv_expiry_delta: u16,
	) -> Result<Bolt11Invoice, Error> {
		let description = maybe_try_convert_enum(description)?;
		let invoice = self.receive_inner(
			None,
			&description,
			expiry_secs,
			Some(payment_hash),
			Some(min_cltv_expiry_delta),
		)?;
		Ok(maybe_wrap(invoice))
	}

	pub(crate) fn receive_inner(
		&self, amount_msat: Option<u64>, invoice_description: &LdkBolt11InvoiceDescription,
		expiry_secs: u32, manual_claim_payment_hash: Option<PaymentHash>,
		min_cltv_expiry_delta: Option<u16>,
	) -> Result<LdkBolt11Invoice, Error> {
		let invoice = {
			let invoice_params = Bolt11InvoiceParameters {
				amount_msats: amount_msat,
				description: invoice_description.clone(),
				invoice_expiry_delta_secs: Some(expiry_secs),
				min_final_cltv_expiry_delta: min_cltv_expiry_delta,
				payment_hash: manual_claim_payment_hash,
				..Default::default()
			};

			match self.channel_manager.create_bolt11_invoice(invoice_params) {
				Ok(inv) => {
					log_info!(self.logger, "Invoice created: {}", inv);
					inv
				},
				Err(e) => {
					log_error!(self.logger, "Failed to create invoice: {}", e);
					return Err(Error::InvoiceCreationFailed);
				},
			}
		};

		let payment_hash = PaymentHash(invoice.payment_hash().to_byte_array());
		let payment_secret = invoice.payment_secret();
		let id = PaymentId(payment_hash.0);
		let preimage = if manual_claim_payment_hash.is_none() {
			// If the user hasn't registered a custom payment hash, we're positive ChannelManager
			// will know the preimage at this point.
			let res = self
				.channel_manager
				.get_payment_preimage(payment_hash, payment_secret.clone())
				.ok();
			debug_assert!(res.is_some(), "We just let ChannelManager create an inbound payment, it can't have forgotten the preimage by now.");
			res
		} else {
			None
		};
		let kind = PaymentKind::Bolt11 {
			hash: payment_hash,
			preimage,
			secret: Some(payment_secret.clone()),
			bolt11_invoice: Some(invoice.to_string()),
		};
		let payment = PaymentDetails::new(
			id,
			kind,
			amount_msat,
			None,
			PaymentDirection::Inbound,
			PaymentStatus::Pending,
		);

		self.payment_store.insert(payment)?;

		Ok(invoice)
	}

	/// Returns a payable invoice that can be used to request a payment of the amount given and
	/// receive it via a newly created just-in-time (JIT) channel.
	///
	/// When the returned invoice is paid, the configured [LSPS2]-compliant LSP will open a channel
	/// to us, supplying just-in-time inbound liquidity.
	///
	/// If set, `max_total_lsp_fee_limit_msat` will limit how much fee we allow the LSP to take for opening the
	/// channel to us. We'll use its cheapest offer otherwise.
	///
	/// [LSPS2]: https://github.com/BitcoinAndLightningLayerSpecs/lsp/blob/main/LSPS2/README.md
	pub fn receive_via_jit_channel(
		&self, amount_msat: u64, description: &Bolt11InvoiceDescription, expiry_secs: u32,
		max_total_lsp_fee_limit_msat: Option<u64>,
	) -> Result<Bolt11Invoice, Error> {
		let description = maybe_try_convert_enum(description)?;
		let invoice = self.receive_via_jit_channel_inner(
			Some(amount_msat),
			&description,
			expiry_secs,
			max_total_lsp_fee_limit_msat,
			None,
			None,
		)?;
		Ok(maybe_wrap(invoice))
	}

	/// Returns a payable invoice that can be used to request a payment of the amount given and
	/// receive it via a newly created just-in-time (JIT) channel.
	///
	/// When the returned invoice is paid, the configured [LSPS2]-compliant LSP will open a channel
	/// to us, supplying just-in-time inbound liquidity.
	///
	/// If set, `max_total_lsp_fee_limit_msat` will limit how much fee we allow the LSP to take for opening the
	/// channel to us. We'll use its cheapest offer otherwise.
	///
	/// We will register the given payment hash and emit a [`PaymentClaimable`] event once
	/// the inbound payment arrives. The check that [`counterparty_skimmed_fee_msat`] is within the limits
	/// is performed *before* emitting the event.
	///
	/// **Note:** users *MUST* handle this event and claim the payment manually via
	/// [`claim_for_hash`] as soon as they have obtained access to the preimage of the given
	/// payment hash. If they're unable to obtain the preimage, they *MUST* immediately fail the payment via
	/// [`fail_for_hash`].
	///
	/// [LSPS2]: https://github.com/BitcoinAndLightningLayerSpecs/lsp/blob/main/LSPS2/README.md
	/// [`PaymentClaimable`]: crate::Event::PaymentClaimable
	/// [`claim_for_hash`]: Self::claim_for_hash
	/// [`fail_for_hash`]: Self::fail_for_hash
	/// [`counterparty_skimmed_fee_msat`]: crate::payment::PaymentKind::Bolt11Jit::counterparty_skimmed_fee_msat
	pub fn receive_via_jit_channel_for_hash(
		&self, amount_msat: u64, description: &Bolt11InvoiceDescription, expiry_secs: u32,
		max_total_lsp_fee_limit_msat: Option<u64>, payment_hash: PaymentHash,
	) -> Result<Bolt11Invoice, Error> {
		let description = maybe_try_convert_enum(description)?;
		let invoice = self.receive_via_jit_channel_inner(
			Some(amount_msat),
			&description,
			expiry_secs,
			max_total_lsp_fee_limit_msat,
			None,
			Some(payment_hash),
		)?;
		Ok(maybe_wrap(invoice))
	}

	/// Returns a payable invoice that can be used to request a variable amount payment (also known
	/// as "zero-amount" invoice) and receive it via a newly created just-in-time (JIT) channel.
	///
	/// When the returned invoice is paid, the configured [LSPS2]-compliant LSP will open a channel
	/// to us, supplying just-in-time inbound liquidity.
	///
	/// If set, `max_proportional_lsp_fee_limit_ppm_msat` will limit how much proportional fee, in
	/// parts-per-million millisatoshis, we allow the LSP to take for opening the channel to us.
	/// We'll use its cheapest offer otherwise.
	///
	/// [LSPS2]: https://github.com/BitcoinAndLightningLayerSpecs/lsp/blob/main/LSPS2/README.md
	pub fn receive_variable_amount_via_jit_channel(
		&self, description: &Bolt11InvoiceDescription, expiry_secs: u32,
		max_proportional_lsp_fee_limit_ppm_msat: Option<u64>,
	) -> Result<Bolt11Invoice, Error> {
		let description = maybe_try_convert_enum(description)?;
		let invoice = self.receive_via_jit_channel_inner(
			None,
			&description,
			expiry_secs,
			None,
			max_proportional_lsp_fee_limit_ppm_msat,
			None,
		)?;
		Ok(maybe_wrap(invoice))
	}

	/// Returns a payable invoice that can be used to request a variable amount payment (also known
	/// as "zero-amount" invoice) and receive it via a newly created just-in-time (JIT) channel.
	///
	/// When the returned invoice is paid, the configured [LSPS2]-compliant LSP will open a channel
	/// to us, supplying just-in-time inbound liquidity.
	///
	/// If set, `max_proportional_lsp_fee_limit_ppm_msat` will limit how much proportional fee, in
	/// parts-per-million millisatoshis, we allow the LSP to take for opening the channel to us.
	/// We'll use its cheapest offer otherwise.
	///
	/// We will register the given payment hash and emit a [`PaymentClaimable`] event once
	/// the inbound payment arrives. The check that [`counterparty_skimmed_fee_msat`] is within the limits
	/// is performed *before* emitting the event.
	///
	/// **Note:** users *MUST* handle this event and claim the payment manually via
	/// [`claim_for_hash`] as soon as they have obtained access to the preimage of the given
	/// payment hash. If they're unable to obtain the preimage, they *MUST* immediately fail the payment via
	/// [`fail_for_hash`].
	///
	/// [LSPS2]: https://github.com/BitcoinAndLightningLayerSpecs/lsp/blob/main/LSPS2/README.md
	/// [`PaymentClaimable`]: crate::Event::PaymentClaimable
	/// [`claim_for_hash`]: Self::claim_for_hash
	/// [`fail_for_hash`]: Self::fail_for_hash
	/// [`counterparty_skimmed_fee_msat`]: crate::payment::PaymentKind::Bolt11Jit::counterparty_skimmed_fee_msat
	pub fn receive_variable_amount_via_jit_channel_for_hash(
		&self, description: &Bolt11InvoiceDescription, expiry_secs: u32,
		max_proportional_lsp_fee_limit_ppm_msat: Option<u64>, payment_hash: PaymentHash,
	) -> Result<Bolt11Invoice, Error> {
		let description = maybe_try_convert_enum(description)?;
		let invoice = self.receive_via_jit_channel_inner(
			None,
			&description,
			expiry_secs,
			None,
			max_proportional_lsp_fee_limit_ppm_msat,
			Some(payment_hash),
		)?;
		Ok(maybe_wrap(invoice))
	}

	fn receive_via_jit_channel_inner(
		&self, amount_msat: Option<u64>, description: &LdkBolt11InvoiceDescription,
		expiry_secs: u32, max_total_lsp_fee_limit_msat: Option<u64>,
		max_proportional_lsp_fee_limit_ppm_msat: Option<u64>, payment_hash: Option<PaymentHash>,
	) -> Result<LdkBolt11Invoice, Error> {
		let liquidity_source =
			self.liquidity_source.as_ref().ok_or(Error::LiquiditySourceUnavailable)?;

		let (node_id, address) =
			liquidity_source.get_lsps2_lsp_details().ok_or(Error::LiquiditySourceUnavailable)?;

		let peer_info = PeerInfo { node_id, address };

		let con_node_id = peer_info.node_id;
		let con_addr = peer_info.address.clone();
		let con_cm = Arc::clone(&self.connection_manager);

		// We need to use our main runtime here as a local runtime might not be around to poll
		// connection futures going forward.
		self.runtime.block_on(async move {
			con_cm.connect_peer_if_necessary(con_node_id, con_addr).await
		})?;

		log_info!(self.logger, "Connected to LSP {}@{}. ", peer_info.node_id, peer_info.address);

		let liquidity_source = Arc::clone(&liquidity_source);
		let (invoice, lsp_total_opening_fee, lsp_prop_opening_fee) =
			self.runtime.block_on(async move {
				if let Some(amount_msat) = amount_msat {
					liquidity_source
						.lsps2_receive_to_jit_channel(
							amount_msat,
							description,
							expiry_secs,
							max_total_lsp_fee_limit_msat,
							payment_hash,
						)
						.await
						.map(|(invoice, total_fee)| (invoice, Some(total_fee), None))
				} else {
					liquidity_source
						.lsps2_receive_variable_amount_to_jit_channel(
							description,
							expiry_secs,
							max_proportional_lsp_fee_limit_ppm_msat,
							payment_hash,
						)
						.await
						.map(|(invoice, prop_fee)| (invoice, None, Some(prop_fee)))
				}
			})?;

		// Register payment in payment store.
		let payment_hash = PaymentHash(invoice.payment_hash().to_byte_array());
		let payment_secret = invoice.payment_secret();
		let lsp_fee_limits = LSPFeeLimits {
			max_total_opening_fee_msat: lsp_total_opening_fee,
			max_proportional_opening_fee_ppm_msat: lsp_prop_opening_fee,
		};
		let id = PaymentId(payment_hash.0);
		let preimage =
			self.channel_manager.get_payment_preimage(payment_hash, payment_secret.clone()).ok();
		let kind = PaymentKind::Bolt11Jit {
			hash: payment_hash,
			preimage,
			secret: Some(payment_secret.clone()),
			counterparty_skimmed_fee_msat: None,
			lsp_fee_limits,
		};
		let payment = PaymentDetails::new(
			id,
			kind,
			amount_msat,
			None,
			PaymentDirection::Inbound,
			PaymentStatus::Pending,
		);

		self.payment_store.insert(payment)?;

		// Persist LSP peer to make sure we reconnect on restart.
		self.peer_store.add_peer(peer_info)?;

		Ok(invoice)
	}

	/// Sends payment probes over all paths of a route that would be used to pay the given invoice.
	///
	/// This may be used to send "pre-flight" probes, i.e., to train our scorer before conducting
	/// the actual payment. Note this is only useful if there likely is sufficient time for the
	/// probe to settle before sending out the actual payment, e.g., when waiting for user
	/// confirmation in a wallet UI.
	///
	/// Otherwise, there is a chance the probe could take up some liquidity needed to complete the
	/// actual payment. Users should therefore be cautious and might avoid sending probes if
	/// liquidity is scarce and/or they don't expect the probe to return before they send the
	/// payment. To mitigate this issue, channels with available liquidity less than the required
	/// amount times [`Config::probing_liquidity_limit_multiplier`] won't be used to send
	/// pre-flight probes.
	///
	/// If `route_parameters` are provided they will override the default as well as the
	/// node-wide parameters configured via [`Config::route_parameters`] on a per-field basis.
	pub fn send_probes(
		&self, invoice: &Bolt11Invoice, route_parameters: Option<RouteParametersConfig>,
	) -> Result<(), Error> {
		if !*self.is_running.read().unwrap() {
			return Err(Error::NotRunning);
		}

		let invoice = maybe_deref(invoice);
		let payment_params = PaymentParameters::from_bolt11_invoice(invoice);

		let amount_msat = invoice.amount_milli_satoshis().ok_or_else(|| {
			log_error!(self.logger, "Failed to send probes due to the given invoice being \"zero-amount\". Please use send_probes_using_amount instead.");
			Error::InvalidInvoice
		})?;

		let mut route_params =
			RouteParameters::from_payment_params_and_value(payment_params, amount_msat);

		if let Some(RouteParametersConfig {
			max_total_routing_fee_msat,
			max_total_cltv_expiry_delta,
			max_path_count,
			max_channel_saturation_power_of_half,
		}) = route_parameters.as_ref().or(self.config.route_parameters.as_ref())
		{
			route_params.max_total_routing_fee_msat = *max_total_routing_fee_msat;
			route_params.payment_params.max_total_cltv_expiry_delta = *max_total_cltv_expiry_delta;
			route_params.payment_params.max_path_count = *max_path_count;
			route_params.payment_params.max_channel_saturation_power_of_half =
				*max_channel_saturation_power_of_half;
		}

		let liquidity_limit_multiplier = Some(self.config.probing_liquidity_limit_multiplier);

		self.channel_manager
			.send_preflight_probes(route_params, liquidity_limit_multiplier)
			.map_err(|e| {
				log_error!(self.logger, "Failed to send payment probes: {:?}", e);
				Error::ProbeSendingFailed
			})?;

		Ok(())
	}

	/// Sends payment probes over all paths of a route that would be used to pay the given
	/// zero-value invoice using the given amount.
	///
	/// This can be used to send pre-flight probes for a so-called "zero-amount" invoice, i.e., an
	/// invoice that leaves the amount paid to be determined by the user.
	///
	/// If `route_parameters` are provided they will override the default as well as the
	/// node-wide parameters configured via [`Config::route_parameters`] on a per-field basis.
	///
	/// See [`Self::send_probes`] for more information.
	pub fn send_probes_using_amount(
		&self, invoice: &Bolt11Invoice, amount_msat: u64,
		route_parameters: Option<RouteParametersConfig>,
	) -> Result<(), Error> {
		if !*self.is_running.read().unwrap() {
			return Err(Error::NotRunning);
		}

		let invoice = maybe_deref(invoice);
		let payment_params = PaymentParameters::from_bolt11_invoice(invoice);

		if let Some(invoice_amount_msat) = invoice.amount_milli_satoshis() {
			if amount_msat < invoice_amount_msat {
				log_error!(
					self.logger,
					"Failed to send probes as the given amount needs to be at least the invoice amount: required {}msat, gave {}msat.",
					invoice_amount_msat,
					amount_msat
				);
				return Err(Error::InvalidAmount);
			}
		}

		let mut route_params =
			RouteParameters::from_payment_params_and_value(payment_params, amount_msat);

		if let Some(RouteParametersConfig {
			max_total_routing_fee_msat,
			max_total_cltv_expiry_delta,
			max_path_count,
			max_channel_saturation_power_of_half,
		}) = route_parameters.as_ref().or(self.config.route_parameters.as_ref())
		{
			route_params.max_total_routing_fee_msat = *max_total_routing_fee_msat;
			route_params.payment_params.max_total_cltv_expiry_delta = *max_total_cltv_expiry_delta;
			route_params.payment_params.max_path_count = *max_path_count;
			route_params.payment_params.max_channel_saturation_power_of_half =
				*max_channel_saturation_power_of_half;
		}

		let liquidity_limit_multiplier = Some(self.config.probing_liquidity_limit_multiplier);

		self.channel_manager
			.send_preflight_probes(route_params, liquidity_limit_multiplier)
			.map_err(|e| {
				log_error!(self.logger, "Failed to send payment probes: {:?}", e);
				Error::ProbeSendingFailed
			})?;

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use lightning::routing::router::{Path, RouteHop};
	use lightning::types::features::{ChannelFeatures, NodeFeatures};

	fn route_hop(pubkey: bitcoin::secp256k1::PublicKey, short_channel_id: u64) -> RouteHop {
		RouteHop {
			pubkey,
			node_features: NodeFeatures::empty(),
			short_channel_id,
			channel_features: ChannelFeatures::empty(),
			fee_msat: 0,
			cltv_expiry_delta: 18,
			maybe_announced_channel: true,
		}
	}

	#[test]
	fn circular_path_validation_requires_both_exact_channel_scids() {
		let first_node = bitcoin::secp256k1::PublicKey::from_str(
			"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
		)
		.unwrap();
		let synthetic_payee = bitcoin::secp256k1::PublicKey::from_str(
			"02c6047f9441ed7d6d3045406e95c07cd85a294d1b04c8fe6c9a5c3315b95c709e",
		)
		.unwrap();
		let path = Path {
			hops: vec![route_hop(first_node, 41), route_hop(synthetic_payee, 99)],
			blinded_tail: None,
		};

		assert!(circular_path_uses_exact_channels(&path, first_node, 41, synthetic_payee, 99));
		assert!(!circular_path_uses_exact_channels(&path, first_node, 42, synthetic_payee, 99));
		assert!(!circular_path_uses_exact_channels(&path, first_node, 41, synthetic_payee, 100));
	}

	#[test]
	fn finalizing_circular_route_replaces_only_synthetic_terminal() {
		let first_node = bitcoin::secp256k1::PublicKey::from_str(
			"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
		)
		.unwrap();
		let synthetic_payee = bitcoin::secp256k1::PublicKey::from_str(
			"02c6047f9441ed7d6d3045406e95c07cd85a294d1b04c8fe6c9a5c3315b95c709e",
		)
		.unwrap();
		let local_node = bitcoin::secp256k1::PublicKey::from_str(
			"02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
		)
		.unwrap();
		let route_params = RouteParameters::from_payment_params_and_value(
			PaymentParameters::from_node_id(synthetic_payee, 18),
			20_000_000,
		);
		let route = Route {
			paths: vec![Path {
				hops: vec![route_hop(first_node, 41), route_hop(synthetic_payee, 99)],
				blinded_tail: None,
			}],
			route_params: Some(route_params),
		};

		let finalized =
			finalize_circular_route(route, first_node, 41, synthetic_payee, 99, local_node)
				.unwrap();

		assert_eq!(finalized.paths[0].hops[0].pubkey, first_node);
		assert_eq!(finalized.paths[0].hops[0].short_channel_id, 41);
		assert_eq!(finalized.paths[0].hops[1].pubkey, local_node);
		assert_eq!(finalized.paths[0].hops[1].short_channel_id, 99);
		assert!(finalized.route_params.is_none());
	}

	#[test]
	fn finalizing_circular_route_rejects_any_channel_mismatch() {
		let first_node = bitcoin::secp256k1::PublicKey::from_str(
			"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
		)
		.unwrap();
		let synthetic_payee = bitcoin::secp256k1::PublicKey::from_str(
			"02c6047f9441ed7d6d3045406e95c07cd85a294d1b04c8fe6c9a5c3315b95c709e",
		)
		.unwrap();
		let local_node = bitcoin::secp256k1::PublicKey::from_str(
			"02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
		)
		.unwrap();
		let route = Route {
			paths: vec![Path {
				hops: vec![route_hop(first_node, 42), route_hop(synthetic_payee, 99)],
				blinded_tail: None,
			}],
			route_params: None,
		};

		assert!(finalize_circular_route(route, first_node, 41, synthetic_payee, 99, local_node)
			.is_err());
	}
}
