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
use std::sync::{Arc, Mutex, RwLock};

use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::Hash;
use lightning::ln::channelmanager::{
	Bolt11InvoiceParameters, Bolt11PaymentError, PaymentId, RecentPaymentDetails,
	RecipientOnionFields, Retry, RetryableSendFailure,
};
use lightning::routing::router::{
	PaymentParameters, Route, RouteHint, RouteHintHop, RouteParameters, RouteParametersConfig,
	Router as LdkRouter,
};
use lightning::util::ser::{Readable, Writeable};
use lightning_invoice::{
	Bolt11Invoice as LdkBolt11Invoice, Bolt11InvoiceDescription as LdkBolt11InvoiceDescription,
	DEFAULT_MIN_FINAL_CLTV_EXPIRY_DELTA,
};
use lightning_types::payment::{PaymentHash, PaymentPreimage, PaymentSecret};
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
	ChannelManager, CircularRouteHop, CircularRoutePath, CircularRouteQuote, PaymentStore,
	PreparedCircularPayment, Router,
};
use crate::UserChannelId;

#[derive(Clone, Copy)]
pub(crate) struct CircularPaymentContext {
	pub(crate) operation_id: PaymentId,
	pub(crate) outbound_payment_id: PaymentId,
	pub(crate) first_hop_user_channel_id: UserChannelId,
	pub(crate) last_hop_user_channel_id: UserChannelId,
	pub(crate) max_routing_fee_msat: u64,
}

pub(crate) fn derive_circular_outbound_payment_id(operation_id: PaymentId) -> PaymentId {
	let mut material = b"ldk-node circular outbound payment id v1".to_vec();
	material.extend_from_slice(&operation_id.0);
	PaymentId(Sha256::hash(&material).to_byte_array())
}

pub(crate) fn circular_operation_is_prepared(
	payment_store: &PaymentStore, operation_id: PaymentId,
) -> bool {
	!payment_store
		.list_filter(|payment| {
			matches!(
				payment.kind,
				PaymentKind::Bolt11 { circular_operation_id: Some(existing), .. }
					if existing == operation_id
			)
		})
		.is_empty()
}

pub(crate) fn prepared_circular_payment_details(
	bolt11_invoice: String, payment_hash: PaymentHash, payment_preimage: PaymentPreimage,
	payment_secret: PaymentSecret, amount_msat: u64, context: CircularPaymentContext,
) -> PaymentDetails {
	PaymentDetails::new(
		PaymentId(payment_hash.0),
		PaymentKind::Bolt11 {
			hash: payment_hash,
			preimage: Some(payment_preimage),
			secret: Some(payment_secret),
			bolt11_invoice: Some(bolt11_invoice),
			required_receiving_channel_id: Some(context.last_hop_user_channel_id),
			required_sending_channel_id: Some(context.first_hop_user_channel_id),
			circular_operation_id: Some(context.operation_id),
			circular_outbound_payment_id: Some(context.outbound_payment_id),
			circular_max_routing_fee_msat: Some(context.max_routing_fee_msat),
		},
		Some(amount_msat),
		None,
		PaymentDirection::Inbound,
		PaymentStatus::Pending,
	)
}

pub(crate) fn recover_prepared_circular_payment(
	payment_store: &PaymentStore, operation_id: PaymentId, amount_msat: u64,
	first_hop_user_channel_id: UserChannelId, first_hop_short_channel_id: u64,
	last_hop_user_channel_id: UserChannelId, last_hop_short_channel_id: u64,
	max_routing_fee_msat: u64,
) -> Result<Option<PreparedCircularPayment>, Error> {
	let operation_matches = payment_store.list_filter(|payment| {
		matches!(
			payment.kind,
			PaymentKind::Bolt11 { circular_operation_id: Some(existing), .. }
				if existing == operation_id
		)
	});
	if operation_matches.is_empty() {
		return Ok(None);
	}
	let prepared_matches: Vec<_> = operation_matches
		.iter()
		.filter(|payment| payment.direction == PaymentDirection::Inbound)
		.collect();
	if prepared_matches.len() != 1 {
		return Err(Error::InvalidPaymentId);
	}
	let prepared = prepared_matches[0];
	let outbound_payment_id = derive_circular_outbound_payment_id(operation_id);
	let (payment_hash, payment_preimage, payment_secret, bolt11_invoice) = match &prepared.kind {
		PaymentKind::Bolt11 {
			hash,
			preimage: Some(preimage),
			secret: Some(secret),
			bolt11_invoice: Some(invoice),
			required_receiving_channel_id: Some(receiving_channel_id),
			required_sending_channel_id: Some(sending_channel_id),
			circular_operation_id: Some(stored_operation_id),
			circular_outbound_payment_id: Some(stored_outbound_payment_id),
			circular_max_routing_fee_msat: Some(stored_max_routing_fee_msat),
		} if *stored_operation_id == operation_id
			&& *stored_outbound_payment_id == outbound_payment_id
			&& *sending_channel_id == first_hop_user_channel_id
			&& *receiving_channel_id == last_hop_user_channel_id
			&& *stored_max_routing_fee_msat == max_routing_fee_msat =>
		{
			(*hash, *preimage, *secret, invoice.clone())
		},
		_ => return Err(Error::InvalidPaymentId),
	};
	if prepared.id != PaymentId(payment_hash.0)
		|| prepared.amount_msat != Some(amount_msat)
		|| prepared.fee_paid_msat.is_some()
		|| PaymentHash(Sha256::hash(&payment_preimage.0).to_byte_array()) != payment_hash
	{
		return Err(Error::InvalidPaymentId);
	}
	match prepared.status {
		PaymentStatus::Failed => return Err(Error::PaymentSendingFailed),
		PaymentStatus::Pending | PaymentStatus::Succeeded => {},
	}
	let invoice = LdkBolt11Invoice::from_str(&bolt11_invoice).map_err(|_| Error::InvalidInvoice)?;
	if PaymentHash(invoice.payment_hash().to_byte_array()) != payment_hash
		|| invoice.amount_milli_satoshis() != Some(amount_msat)
		|| *invoice.payment_secret() != payment_secret
	{
		return Err(Error::InvalidInvoice);
	}

	Ok(Some(PreparedCircularPayment {
		bolt11_invoice,
		payment_hash,
		operation_id,
		outbound_payment_id,
		amount_msat,
		max_routing_fee_msat,
		first_hop_user_channel_id,
		first_hop_short_channel_id,
		last_hop_user_channel_id,
		last_hop_short_channel_id,
	}))
}

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

fn decode_and_validate_circular_quote_route(quote: &CircularRouteQuote) -> Result<Route, Error> {
	let mut route_bytes = &quote.route_bytes[..];
	let route = Route::read(&mut route_bytes).map_err(|_| Error::PaymentSendingFailed)?;
	if !route_bytes.is_empty()
		|| route.route_params.is_some()
		|| route.get_total_amount() != quote.amount_msat
		|| route.get_total_fees() != quote.total_routing_fee_msat
		|| route.paths.len() != quote.paths.len()
	{
		return Err(Error::PaymentSendingFailed);
	}

	for (route_path, quoted_path) in route.paths.iter().zip(quote.paths.iter()) {
		if route_path.blinded_tail.is_some()
			|| route_path.final_value_msat() != quoted_path.amount_msat
			|| route_path.fee_msat() != quoted_path.fee_msat
			|| route_path.hops.len() != quoted_path.hops.len()
		{
			return Err(Error::PaymentSendingFailed);
		}
		for (route_hop, quoted_hop) in route_path.hops.iter().zip(quoted_path.hops.iter()) {
			if route_hop.pubkey != quoted_hop.node_id
				|| route_hop.short_channel_id != quoted_hop.short_channel_id
				|| route_hop.fee_msat != quoted_hop.fee_msat
				|| route_hop.cltv_expiry_delta != quoted_hop.cltv_expiry_delta
			{
				return Err(Error::PaymentSendingFailed);
			}
		}
	}

	Ok(route)
}

#[derive(Clone)]
pub(crate) struct PreparedCircularExecution {
	pub(crate) route: Route,
	pub(crate) payment_hash: PaymentHash,
	pub(crate) payment_secret: PaymentSecret,
	pub(crate) payment_metadata: Option<Vec<u8>>,
	pub(crate) outbound_payment_id: PaymentId,
	pub(crate) outbound_payment: PaymentDetails,
}

fn existing_pending_outbound_matches(existing: &PaymentDetails, expected: &PaymentDetails) -> bool {
	existing.id == expected.id
		&& existing.kind == expected.kind
		&& existing.amount_msat == expected.amount_msat
		&& existing.fee_paid_msat.is_none()
		&& existing.direction == PaymentDirection::Outbound
		&& existing.status == PaymentStatus::Pending
}

pub(crate) fn submit_prepared_circular_execution<F>(
	payment_store: &PaymentStore, execution: PreparedCircularExecution, send: F,
) -> Result<PaymentId, Error>
where
	F: FnOnce(
		Route,
		PaymentHash,
		RecipientOnionFields,
		PaymentId,
	) -> Result<(), RetryableSendFailure>,
{
	if !payment_store.insert_if_absent(execution.outbound_payment.clone())? {
		let existing =
			payment_store.get(&execution.outbound_payment_id).ok_or(Error::PersistenceFailed)?;
		if !existing_pending_outbound_matches(&existing, &execution.outbound_payment) {
			return Err(Error::DuplicatePayment);
		}
	}
	let mut recipient_onion = RecipientOnionFields::secret_only(execution.payment_secret);
	recipient_onion.payment_metadata = execution.payment_metadata;
	if let Err(e) = send(
		execution.route,
		execution.payment_hash,
		recipient_onion,
		execution.outbound_payment_id,
	) {
		if e != RetryableSendFailure::DuplicatePayment {
			let inbound_update = PaymentDetailsUpdate {
				status: Some(PaymentStatus::Failed),
				..PaymentDetailsUpdate::new(PaymentId(execution.payment_hash.0))
			};
			let outbound_update = PaymentDetailsUpdate {
				status: Some(PaymentStatus::Failed),
				..PaymentDetailsUpdate::new(execution.outbound_payment_id)
			};
			let inbound_result = payment_store.update(&inbound_update);
			let outbound_result = payment_store.update(&outbound_update);
			if inbound_result.is_err() || outbound_result.is_err() {
				return Err(Error::PersistenceFailed);
			}
		}
		if e == RetryableSendFailure::DuplicatePayment {
			return Ok(execution.outbound_payment_id);
		}
		return Err(Error::PaymentSendingFailed);
	}

	Ok(execution.outbound_payment_id)
}

pub(crate) fn build_prepared_circular_execution(
	payment_store: &PaymentStore, operation_id: PaymentId, quote: &CircularRouteQuote,
	first_hop_node_id: bitcoin::secp256k1::PublicKey, first_hop_scid: u64,
	first_hop_outbound_capacity_msat: u64, last_hop_node_id: bitcoin::secp256k1::PublicKey,
	last_hop_scid: u64, last_hop_inbound_capacity_msat: u64,
	local_node_id: bitcoin::secp256k1::PublicKey,
) -> Result<PreparedCircularExecution, Error> {
	if quote.amount_msat == 0 {
		return Err(Error::InvalidAmount);
	}
	if quote.first_hop_user_channel_id == quote.last_hop_user_channel_id
		|| quote.first_hop_short_channel_id != first_hop_scid
		|| quote.last_hop_short_channel_id != last_hop_scid
	{
		return Err(Error::InvalidChannelId);
	}
	let max_total_debit_msat =
		quote.amount_msat.checked_add(quote.total_routing_fee_msat).ok_or(Error::InvalidAmount)?;
	if max_total_debit_msat > first_hop_outbound_capacity_msat
		|| quote.amount_msat > last_hop_inbound_capacity_msat
	{
		return Err(Error::InsufficientFunds);
	}

	let prepared_matches = payment_store.list_filter(|payment| {
		payment.direction == PaymentDirection::Inbound
			&& matches!(
			payment.kind,
			PaymentKind::Bolt11 { circular_operation_id: Some(existing), .. }
				if existing == operation_id
			)
	});
	if prepared_matches.is_empty() {
		return Err(Error::InvalidPaymentId);
	}
	if prepared_matches.len() != 1 {
		return Err(Error::DuplicatePayment);
	}
	let prepared = &prepared_matches[0];
	if prepared.direction != PaymentDirection::Inbound
		|| prepared.status != PaymentStatus::Pending
		|| prepared.amount_msat != Some(quote.amount_msat)
	{
		return Err(Error::InvalidPaymentId);
	}

	let (
		payment_hash,
		payment_preimage,
		payment_secret,
		bolt11_invoice,
		required_receiving_channel_id,
		required_sending_channel_id,
		outbound_payment_id,
		max_routing_fee_msat,
	) = match &prepared.kind {
		PaymentKind::Bolt11 {
			hash,
			preimage: Some(preimage),
			secret: Some(secret),
			bolt11_invoice: Some(invoice),
			required_receiving_channel_id: Some(receiving_channel_id),
			required_sending_channel_id: Some(sending_channel_id),
			circular_operation_id: Some(stored_operation_id),
			circular_outbound_payment_id: Some(outbound_payment_id),
			circular_max_routing_fee_msat: Some(max_routing_fee_msat),
		} if *stored_operation_id == operation_id => (
			*hash,
			*preimage,
			*secret,
			invoice.clone(),
			*receiving_channel_id,
			*sending_channel_id,
			*outbound_payment_id,
			*max_routing_fee_msat,
		),
		_ => return Err(Error::InvalidPaymentId),
	};

	if prepared.id != PaymentId(payment_hash.0)
		|| PaymentHash(Sha256::hash(&payment_preimage.0).to_byte_array()) != payment_hash
		|| required_sending_channel_id != quote.first_hop_user_channel_id
		|| required_receiving_channel_id != quote.last_hop_user_channel_id
		|| outbound_payment_id != derive_circular_outbound_payment_id(operation_id)
		|| quote.total_routing_fee_msat > max_routing_fee_msat
	{
		return Err(Error::InvalidPaymentId);
	}

	let invoice = LdkBolt11Invoice::from_str(&bolt11_invoice).map_err(|_| Error::InvalidInvoice)?;
	if invoice.is_expired()
		|| PaymentHash(invoice.payment_hash().to_byte_array()) != payment_hash
		|| invoice.amount_milli_satoshis() != Some(quote.amount_msat)
		|| *invoice.payment_secret() != payment_secret
	{
		return Err(Error::InvalidInvoice);
	}

	let route = decode_and_validate_circular_quote_route(quote)?;
	if route.paths.is_empty()
		|| route.paths.iter().any(|path| {
			path.hops.len() < 2
				|| path.hops.first().map_or(true, |hop| {
					hop.pubkey != first_hop_node_id || hop.short_channel_id != first_hop_scid
				}) || path.hops[path.hops.len() - 2].pubkey != last_hop_node_id
				|| path.hops.last().map_or(true, |hop| {
					hop.pubkey != local_node_id || hop.short_channel_id != last_hop_scid
				})
		}) {
		return Err(Error::PaymentSendingFailed);
	}

	let outbound_payment = PaymentDetails::new(
		outbound_payment_id,
		PaymentKind::Bolt11 {
			hash: payment_hash,
			preimage: None,
			secret: Some(payment_secret),
			bolt11_invoice: Some(bolt11_invoice),
			required_receiving_channel_id: Some(required_receiving_channel_id),
			required_sending_channel_id: Some(required_sending_channel_id),
			circular_operation_id: Some(operation_id),
			circular_outbound_payment_id: Some(outbound_payment_id),
			circular_max_routing_fee_msat: Some(max_routing_fee_msat),
		},
		Some(quote.amount_msat),
		None,
		PaymentDirection::Outbound,
		PaymentStatus::Pending,
	);
	if let Some(existing) = payment_store.get(&outbound_payment_id) {
		if !existing_pending_outbound_matches(&existing, &outbound_payment) {
			return Err(Error::InvalidPaymentId);
		}
	}

	Ok(PreparedCircularExecution {
		route,
		payment_hash,
		payment_secret,
		payment_metadata: invoice.payment_metadata().cloned(),
		outbound_payment_id,
		outbound_payment,
	})
}

pub(crate) fn recover_existing_circular_payment(
	payment_store: &PaymentStore, operation_id: PaymentId, quote: &CircularRouteQuote,
	recent_payments: &[RecentPaymentDetails],
) -> Result<Option<PaymentId>, Error> {
	let outbound_payment_id = derive_circular_outbound_payment_id(operation_id);
	let Some(outbound) = payment_store.get(&outbound_payment_id) else {
		return Ok(None);
	};
	let prepared_matches = payment_store.list_filter(|payment| {
		payment.direction == PaymentDirection::Inbound
			&& matches!(
			payment.kind,
			PaymentKind::Bolt11 { circular_operation_id: Some(existing), .. }
				if existing == operation_id
			)
	});
	if prepared_matches.len() != 1 {
		return Err(Error::InvalidPaymentId);
	}
	let prepared = &prepared_matches[0];
	let (payment_hash, payment_preimage, payment_secret, bolt11_invoice, max_routing_fee_msat) =
		match &prepared.kind {
			PaymentKind::Bolt11 {
				hash,
				preimage: Some(preimage),
				secret: Some(secret),
				bolt11_invoice: Some(invoice),
				required_receiving_channel_id: Some(receiving_channel_id),
				required_sending_channel_id: Some(sending_channel_id),
				circular_operation_id: Some(stored_operation_id),
				circular_outbound_payment_id: Some(stored_outbound_payment_id),
				circular_max_routing_fee_msat: Some(max_routing_fee_msat),
			} if *stored_operation_id == operation_id
				&& *stored_outbound_payment_id == outbound_payment_id
				&& *sending_channel_id == quote.first_hop_user_channel_id
				&& *receiving_channel_id == quote.last_hop_user_channel_id =>
			{
				(*hash, *preimage, *secret, invoice, *max_routing_fee_msat)
			},
			_ => return Err(Error::InvalidPaymentId),
		};
	if prepared.id != PaymentId(payment_hash.0)
		|| prepared.direction != PaymentDirection::Inbound
		|| prepared.amount_msat != Some(quote.amount_msat)
		|| PaymentHash(Sha256::hash(&payment_preimage.0).to_byte_array()) != payment_hash
		|| quote.total_routing_fee_msat > max_routing_fee_msat
	{
		return Err(Error::InvalidPaymentId);
	}
	let invoice = LdkBolt11Invoice::from_str(bolt11_invoice).map_err(|_| Error::InvalidInvoice)?;
	if PaymentHash(invoice.payment_hash().to_byte_array()) != payment_hash
		|| invoice.amount_milli_satoshis() != Some(quote.amount_msat)
		|| *invoice.payment_secret() != payment_secret
	{
		return Err(Error::InvalidInvoice);
	}
	match &outbound.kind {
		PaymentKind::Bolt11 {
			hash,
			preimage,
			secret: Some(secret),
			bolt11_invoice: Some(outbound_invoice),
			required_receiving_channel_id: Some(receiving_channel_id),
			required_sending_channel_id: Some(sending_channel_id),
			circular_operation_id: Some(stored_operation_id),
			circular_outbound_payment_id: Some(stored_outbound_payment_id),
			circular_max_routing_fee_msat: Some(stored_max_routing_fee_msat),
		} if *hash == payment_hash
			&& preimage.map_or(true, |existing| existing == payment_preimage)
			&& *secret == payment_secret
			&& outbound_invoice == bolt11_invoice
			&& *receiving_channel_id == quote.last_hop_user_channel_id
			&& *sending_channel_id == quote.first_hop_user_channel_id
			&& *stored_operation_id == operation_id
			&& *stored_outbound_payment_id == outbound_payment_id
			&& *stored_max_routing_fee_msat == max_routing_fee_msat => {},
		_ => return Err(Error::InvalidPaymentId),
	}
	if outbound.id != outbound_payment_id
		|| outbound.direction != PaymentDirection::Outbound
		|| outbound.amount_msat != Some(quote.amount_msat)
	{
		return Err(Error::InvalidPaymentId);
	}
	match outbound.status {
		PaymentStatus::Succeeded => {
			if prepared.status == PaymentStatus::Failed {
				return Err(Error::InvalidPaymentId);
			}
			return Ok(Some(outbound_payment_id));
		},
		PaymentStatus::Failed => return Err(Error::PaymentSendingFailed),
		PaymentStatus::Pending => {
			if prepared.status != PaymentStatus::Pending || outbound.fee_paid_msat.is_some() {
				return Err(Error::InvalidPaymentId);
			}
		},
	}

	for payment in recent_payments {
		match payment {
			RecentPaymentDetails::Pending {
				payment_id,
				payment_hash: tracked_hash,
				total_msat,
			} if *payment_id == outbound_payment_id => {
				if *tracked_hash != payment_hash || *total_msat != quote.amount_msat {
					return Err(Error::InvalidPaymentId);
				}
				return Ok(Some(outbound_payment_id));
			},
			RecentPaymentDetails::Fulfilled { payment_id, payment_hash: tracked_hash }
				if *payment_id == outbound_payment_id =>
			{
				if tracked_hash.map_or(true, |hash| hash != payment_hash) {
					return Err(Error::InvalidPaymentId);
				}
				return Ok(Some(outbound_payment_id));
			},
			RecentPaymentDetails::Abandoned { payment_id, payment_hash: tracked_hash }
				if *payment_id == outbound_payment_id =>
			{
				if *tracked_hash != payment_hash {
					return Err(Error::InvalidPaymentId);
				}
				return Err(Error::PaymentSendingFailed);
			},
			RecentPaymentDetails::AwaitingInvoice { payment_id }
				if *payment_id == outbound_payment_id =>
			{
				return Err(Error::InvalidPaymentId);
			},
			_ => {},
		}
	}
	Ok(None)
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
	circular_payment_lock: Arc<Mutex<()>>,
	logger: Arc<Logger>,
}

impl Bolt11Payment {
	pub(crate) fn new(
		runtime: Arc<Runtime>, channel_manager: Arc<ChannelManager>, router: Arc<Router>,
		connection_manager: Arc<ConnectionManager<Arc<Logger>>>,
		liquidity_source: Option<Arc<LiquiditySource<Arc<Logger>>>>,
		payment_store: Arc<PaymentStore>, peer_store: Arc<PeerStore<Arc<Logger>>>,
		config: Arc<Config>, is_running: Arc<RwLock<bool>>, circular_payment_lock: Arc<Mutex<()>>,
		logger: Arc<Logger>,
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
			circular_payment_lock,
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
		let route_bytes = route.encode();

		Ok(CircularRouteQuote {
			amount_msat,
			total_routing_fee_msat: route.get_total_fees(),
			first_hop_user_channel_id: *first_hop_user_channel_id,
			first_hop_short_channel_id: first_hop_scid,
			last_hop_user_channel_id: *last_hop_user_channel_id,
			last_hop_short_channel_id: last_hop_scid,
			paths,
			route_bytes,
		})
	}

	/// Create and durably record the inbound leg of a circular payment without sending anything.
	///
	/// The returned invoice is bound to the exact amount, both selected local channels, the routing
	/// fee limit, and a caller-supplied operation ID. The preimage is persisted but not returned.
	/// A distinct outbound payment ID is reserved deterministically for later execution.
	pub fn prepare_circular_payment(
		&self, amount_msat: u64, description: &Bolt11InvoiceDescription, expiry_secs: u32,
		operation_id: &PaymentId, first_hop_user_channel_id: &UserChannelId,
		last_hop_user_channel_id: &UserChannelId, max_routing_fee_msat: u64,
	) -> Result<PreparedCircularPayment, Error> {
		if !*self.is_running.read().unwrap() {
			return Err(Error::NotRunning);
		}
		if amount_msat == 0 {
			return Err(Error::InvalidAmount);
		}
		if first_hop_user_channel_id == last_hop_user_channel_id {
			return Err(Error::InvalidChannelId);
		}
		let max_total_debit_msat =
			amount_msat.checked_add(max_routing_fee_msat).ok_or(Error::InvalidAmount)?;
		let _preparation_guard = self.circular_payment_lock.lock().unwrap();

		let outbound_payment_id = derive_circular_outbound_payment_id(*operation_id);
		if outbound_payment_id == *operation_id {
			return Err(Error::InvalidPaymentId);
		}

		let usable_channels = self.channel_manager.list_usable_channels();
		let first_hop = usable_channels
			.iter()
			.find(|channel| channel.user_channel_id == first_hop_user_channel_id.0)
			.ok_or(Error::InvalidChannelId)?;
		if first_hop.outbound_capacity_msat < max_total_debit_msat {
			return Err(Error::InsufficientFunds);
		}
		let first_hop_short_channel_id =
			first_hop.get_outbound_payment_scid().ok_or(Error::InvalidChannelId)?;

		let channels = self.channel_manager.list_channels();
		let last_hop = channels
			.iter()
			.find(|channel| channel.user_channel_id == last_hop_user_channel_id.0)
			.ok_or(Error::InvalidChannelId)?;
		if !last_hop.is_usable {
			return Err(Error::InvalidChannelId);
		}
		if last_hop.inbound_capacity_msat < amount_msat {
			return Err(Error::InsufficientFunds);
		}
		let last_hop_short_channel_id =
			last_hop.get_inbound_payment_scid().ok_or(Error::InvalidChannelId)?;
		if let Some(prepared) = recover_prepared_circular_payment(
			&self.payment_store,
			*operation_id,
			amount_msat,
			*first_hop_user_channel_id,
			first_hop_short_channel_id,
			*last_hop_user_channel_id,
			last_hop_short_channel_id,
			max_routing_fee_msat,
		)? {
			log_info!(
				self.logger,
				"Recovered existing prepared circular payment {} without creating another invoice.",
				operation_id,
			);
			return Ok(prepared);
		}
		if self.payment_store.get(&outbound_payment_id).is_some() {
			return Err(Error::DuplicatePayment);
		}

		let circular_context = CircularPaymentContext {
			operation_id: *operation_id,
			outbound_payment_id,
			first_hop_user_channel_id: *first_hop_user_channel_id,
			last_hop_user_channel_id: *last_hop_user_channel_id,
			max_routing_fee_msat,
		};
		let description = maybe_try_convert_enum(description)?;
		let invoice = self.receive_inner(
			Some(amount_msat),
			&description,
			expiry_secs,
			None,
			None,
			Some(circular_context),
		)?;
		let payment_hash = PaymentHash(invoice.payment_hash().to_byte_array());

		Ok(PreparedCircularPayment {
			bolt11_invoice: invoice.to_string(),
			payment_hash,
			operation_id: *operation_id,
			outbound_payment_id,
			amount_msat,
			max_routing_fee_msat,
			first_hop_user_channel_id: *first_hop_user_channel_id,
			first_hop_short_channel_id,
			last_hop_user_channel_id: *last_hop_user_channel_id,
			last_hop_short_channel_id,
		})
	}

	/// Submit a previously prepared circular payment using only its fully reviewed route.
	///
	/// The complete deterministic execution and restart matrix is covered by the native and UniFFI
	/// test suites. Callers must still gate this behind their own durable, single-use reviewed-quote
	/// acquisition before exposing any value-moving entrypoint.
	pub fn send_prepared_circular_payment(
		&self, operation_id: &PaymentId, quote: &CircularRouteQuote,
	) -> Result<PaymentId, Error> {
		if !*self.is_running.read().unwrap() {
			return Err(Error::NotRunning);
		}
		let _execution_guard = self.circular_payment_lock.lock().unwrap();
		if let Some(outbound_payment_id) = recover_existing_circular_payment(
			&self.payment_store,
			*operation_id,
			quote,
			&self.channel_manager.list_recent_payments(),
		)? {
			log_info!(
				self.logger,
				"Recovered existing prepared circular payment {} without creating another payment.",
				operation_id,
			);
			return Ok(outbound_payment_id);
		}

		let usable_channels = self.channel_manager.list_usable_channels();
		let first_hop = usable_channels
			.iter()
			.find(|channel| channel.user_channel_id == quote.first_hop_user_channel_id.0)
			.ok_or(Error::InvalidChannelId)?;
		let first_hop_scid =
			first_hop.get_outbound_payment_scid().ok_or(Error::InvalidChannelId)?;

		let channels = self.channel_manager.list_channels();
		let last_hop = channels
			.iter()
			.find(|channel| channel.user_channel_id == quote.last_hop_user_channel_id.0)
			.ok_or(Error::InvalidChannelId)?;
		if !last_hop.is_usable {
			return Err(Error::InvalidChannelId);
		}
		let last_hop_scid = last_hop.get_inbound_payment_scid().ok_or(Error::InvalidChannelId)?;

		let execution = build_prepared_circular_execution(
			&self.payment_store,
			*operation_id,
			quote,
			first_hop.counterparty.node_id,
			first_hop_scid,
			first_hop.outbound_capacity_msat,
			last_hop.counterparty.node_id,
			last_hop_scid,
			last_hop.inbound_capacity_msat,
			self.channel_manager.get_our_node_id(),
		)?;

		let outbound_payment_id = execution.outbound_payment_id;
		submit_prepared_circular_execution(
			&self.payment_store,
			execution,
			|route, hash, onion, id| {
				self.channel_manager.send_payment_with_route(route, hash, onion, id)
			},
		)?;

		log_info!(
			self.logger,
			"Initiated prepared circular payment {} for {}msat with a maximum routing fee of {}msat.",
			operation_id,
			quote.amount_msat,
			quote.total_routing_fee_msat,
		);
		Ok(outbound_payment_id)
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

		// Persist the exact payment constraint before handing any HTLC to ChannelManager. If this
		// write fails, no value-moving call is made.
		let kind = PaymentKind::Bolt11 {
			hash: payment_hash,
			preimage: None,
			secret: Some(*invoice.payment_secret()),
			bolt11_invoice: Some(invoice.to_string()),
			required_receiving_channel_id: None,
			required_sending_channel_id: None,
			circular_operation_id: None,
			circular_outbound_payment_id: None,
			circular_max_routing_fee_msat: None,
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

		if let Err(e) = self.channel_manager.send_payment_with_route(
			route,
			payment_hash,
			recipient_onion,
			payment_id,
		) {
			// DuplicatePayment can mean ChannelManager recovered an already in-flight attempt after
			// restart. Preserve Pending in that case so recovery evidence is not overwritten.
			if e != RetryableSendFailure::DuplicatePayment {
				let update = PaymentDetailsUpdate {
					status: Some(PaymentStatus::Failed),
					..PaymentDetailsUpdate::new(payment_id)
				};
				self.payment_store.update(&update)?;
			}
			return Err({
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
			});
		}

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
					required_receiving_channel_id: None,
					required_sending_channel_id: None,
					circular_operation_id: None,
					circular_outbound_payment_id: None,
					circular_max_routing_fee_msat: None,
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
							required_receiving_channel_id: None,
							required_sending_channel_id: None,
							circular_operation_id: None,
							circular_outbound_payment_id: None,
							circular_max_routing_fee_msat: None,
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
					required_receiving_channel_id: None,
					required_sending_channel_id: None,
					circular_operation_id: None,
					circular_outbound_payment_id: None,
					circular_max_routing_fee_msat: None,
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
							required_receiving_channel_id: None,
							required_sending_channel_id: None,
							circular_operation_id: None,
							circular_outbound_payment_id: None,
							circular_max_routing_fee_msat: None,
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
			self.receive_inner(Some(amount_msat), &description, expiry_secs, None, None, None)?;
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
			None,
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
		let invoice = self.receive_inner(None, &description, expiry_secs, None, None, None)?;
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
			self.receive_inner(None, &description, expiry_secs, Some(payment_hash), None, None)?;
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
			None,
		)?;
		Ok(maybe_wrap(invoice))
	}

	pub(crate) fn receive_inner(
		&self, amount_msat: Option<u64>, invoice_description: &LdkBolt11InvoiceDescription,
		expiry_secs: u32, manual_claim_payment_hash: Option<PaymentHash>,
		min_cltv_expiry_delta: Option<u16>, circular_context: Option<CircularPaymentContext>,
	) -> Result<LdkBolt11Invoice, Error> {
		if circular_context.is_some()
			&& (amount_msat.is_none() || manual_claim_payment_hash.is_some())
		{
			return Err(Error::InvalidAmount);
		}
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
				Ok(inv) => inv,
				Err(e) => {
					log_error!(self.logger, "Failed to create invoice: {}", e);
					return Err(Error::InvoiceCreationFailed);
				},
			}
		};

		let payment_hash = PaymentHash(invoice.payment_hash().to_byte_array());
		let payment_secret = invoice.payment_secret();
		let id = PaymentId(payment_hash.0);
		if circular_context
			.map(|context| {
				context.operation_id == context.outbound_payment_id
					|| context.outbound_payment_id == id
			})
			.unwrap_or(false)
		{
			return Err(Error::InvalidPaymentId);
		}
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
		if circular_context.is_some() && preimage.is_none() {
			log_error!(self.logger, "Failed to persist prepared circular payment preimage.");
			return Err(Error::PersistenceFailed);
		}
		if circular_context.is_some() && self.payment_store.get(&id).is_some() {
			return Err(Error::DuplicatePayment);
		}
		let payment = match circular_context {
			Some(context) => prepared_circular_payment_details(
				invoice.to_string(),
				payment_hash,
				preimage.ok_or(Error::PersistenceFailed)?,
				payment_secret.clone(),
				amount_msat.ok_or(Error::InvalidAmount)?,
				context,
			),
			None => PaymentDetails::new(
				id,
				PaymentKind::Bolt11 {
					hash: payment_hash,
					preimage,
					secret: Some(payment_secret.clone()),
					bolt11_invoice: Some(invoice.to_string()),
					required_receiving_channel_id: None,
					required_sending_channel_id: None,
					circular_operation_id: None,
					circular_outbound_payment_id: None,
					circular_max_routing_fee_msat: None,
				},
				amount_msat,
				None,
				PaymentDirection::Inbound,
				PaymentStatus::Pending,
			),
		};

		self.payment_store.insert(payment)?;
		log_info!(self.logger, "Invoice created for payment hash {}.", payment_hash);

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
	fn circular_outbound_payment_id_is_deterministic_and_domain_separated() {
		let operation_id = PaymentId([7u8; 32]);
		let outbound_payment_id = derive_circular_outbound_payment_id(operation_id);

		assert_eq!(outbound_payment_id, derive_circular_outbound_payment_id(operation_id));
		assert_ne!(outbound_payment_id, operation_id);
		assert_ne!(outbound_payment_id, PaymentId([0u8; 32]));
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
	fn serialized_circular_route_preserves_features_and_must_match_quote() {
		let first_node = bitcoin::secp256k1::PublicKey::from_str(
			"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
		)
		.unwrap();
		let local_node = bitcoin::secp256k1::PublicKey::from_str(
			"02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
		)
		.unwrap();
		let mut first_hop = route_hop(first_node, 41);
		first_hop.node_features = NodeFeatures::from_le_bytes(vec![0b10]);
		first_hop.channel_features = ChannelFeatures::from_le_bytes(vec![0b01]);
		first_hop.fee_msat = 1_000;
		let mut last_hop = route_hop(local_node, 99);
		last_hop.node_features = NodeFeatures::from_le_bytes(vec![0b100]);
		last_hop.channel_features = ChannelFeatures::from_le_bytes(vec![0b1000]);
		last_hop.fee_msat = 20_000_000;
		let route = Route {
			paths: vec![Path { hops: vec![first_hop, last_hop], blinded_tail: None }],
			route_params: None,
		};
		let quote = CircularRouteQuote {
			amount_msat: 20_000_000,
			total_routing_fee_msat: 1_000,
			first_hop_user_channel_id: UserChannelId(11),
			first_hop_short_channel_id: 41,
			last_hop_user_channel_id: UserChannelId(12),
			last_hop_short_channel_id: 99,
			paths: vec![CircularRoutePath {
				hops: vec![
					CircularRouteHop {
						node_id: first_node,
						short_channel_id: 41,
						fee_msat: 1_000,
						cltv_expiry_delta: 18,
					},
					CircularRouteHop {
						node_id: local_node,
						short_channel_id: 99,
						fee_msat: 20_000_000,
						cltv_expiry_delta: 18,
					},
				],
				amount_msat: 20_000_000,
				fee_msat: 1_000,
			}],
			route_bytes: route.encode(),
		};

		assert_eq!(decode_and_validate_circular_quote_route(&quote).unwrap(), route);

		let mut mismatched_summary = quote.clone();
		mismatched_summary.paths[0].hops[0].short_channel_id = 42;
		assert_eq!(
			decode_and_validate_circular_quote_route(&mismatched_summary),
			Err(Error::PaymentSendingFailed)
		);

		let mut trailing_bytes = quote;
		trailing_bytes.route_bytes.push(0);
		assert_eq!(
			decode_and_validate_circular_quote_route(&trailing_bytes),
			Err(Error::PaymentSendingFailed)
		);
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
