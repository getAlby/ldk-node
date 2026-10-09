// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use core::future::Future;
use core::task::{Poll, Waker};
use std::collections::VecDeque;
use std::ops::Deref;
use std::sync::{Arc, Mutex};

use bitcoin::blockdata::locktime::absolute::LockTime;
use bitcoin::hashes::Hash as _;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{Amount, OutPoint};
use lightning::events::bump_transaction::BumpTransactionEvent;
use lightning::events::{
	ClosureReason, Event as LdkEvent, PaymentFailureReason, PaymentPurpose, ReplayEvent,
};
use lightning::ln::channelmanager::{FailureCode, PaymentId};
use lightning::ln::types::ChannelId;
use lightning::routing::gossip::NodeId;
use lightning::util::config::{
	ChannelConfigOverrides, ChannelConfigUpdate, ChannelHandshakeConfigUpdate,
};
use lightning::util::errors::APIError;
use lightning::util::persist::KVStore;
use lightning::util::ser::{Readable, ReadableArgs, Writeable, Writer};
use lightning::{impl_writeable_tlv_based, impl_writeable_tlv_based_enum};
use lightning_liquidity::lsps2::utils::compute_opening_fee;
use lightning_types::payment::{PaymentHash, PaymentPreimage};
use rand::{rng, Rng};

use crate::config::{may_announce_channel, Config};
use crate::connection::ConnectionManager;
use crate::data_store::DataStoreUpdateResult;
use crate::fee_estimator::ConfirmationTarget;
use crate::io::{
	EVENT_QUEUE_PERSISTENCE_KEY, EVENT_QUEUE_PERSISTENCE_PRIMARY_NAMESPACE,
	EVENT_QUEUE_PERSISTENCE_SECONDARY_NAMESPACE,
};
use crate::liquidity::LiquiditySource;
use crate::logger::{log_debug, log_error, log_info, log_trace, LdkLogger, Logger};
use crate::payment::asynchronous::om_mailbox::OnionMessageMailbox;
use crate::payment::asynchronous::static_invoice_store::StaticInvoiceStore;
use crate::payment::store::{
	CircularPaymentFailureReason, PaymentDetails, PaymentDetailsUpdate, PaymentDirection,
	PaymentKind, PaymentStatus,
};
use crate::runtime::Runtime;
use crate::types::{
	CustomTlvRecord, DynStore, OnionMessenger, PaymentStore, Sweeper, TlvEntry, Wallet,
};
use crate::{
	hex_utils, BumpTransactionEventHandler, ChannelManager, Error, Graph, PeerInfo, PeerStore,
	UserChannelId,
};

/// Identifies one local channel over which a claimable payment part arrived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivingChannel {
	/// The protocol-level channel identifier.
	pub channel_id: ChannelId,
	/// The stable user channel identifier, when LDK can associate one with the HTLC.
	pub user_channel_id: Option<UserChannelId>,
}

impl_writeable_tlv_based!(ReceivingChannel, {
	(0, channel_id, required),
	(2, user_channel_id, option),
});

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChannelConstrainedClaimDecision {
	NotConstrained,
	Claim(PaymentPreimage),
	Fail(CircularPaymentFailureReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChannelConstrainedClaimOutcome {
	NotConstrained,
	Claimed,
	Failed,
}

trait ChannelConstrainedClaimActions {
	fn claim(&self, preimage: PaymentPreimage);
	fn fail(&self, payment_hash: &PaymentHash);
}

impl ChannelConstrainedClaimActions for ChannelManager {
	fn claim(&self, preimage: PaymentPreimage) {
		self.claim_funds(preimage);
	}

	fn fail(&self, payment_hash: &PaymentHash) {
		self.fail_htlc_backwards(payment_hash);
	}
}

fn apply_channel_constrained_claim_decision<A: ChannelConstrainedClaimActions>(
	actions: &A, payment_hash: &PaymentHash, decision: ChannelConstrainedClaimDecision,
) -> ChannelConstrainedClaimOutcome {
	match decision {
		ChannelConstrainedClaimDecision::NotConstrained => {
			ChannelConstrainedClaimOutcome::NotConstrained
		},
		ChannelConstrainedClaimDecision::Claim(preimage) => {
			actions.claim(preimage);
			ChannelConstrainedClaimOutcome::Claimed
		},
		ChannelConstrainedClaimDecision::Fail(_) => {
			actions.fail(payment_hash);
			ChannelConstrainedClaimOutcome::Failed
		},
	}
}

fn handle_channel_constrained_claim<A: ChannelConstrainedClaimActions>(
	actions: &A, payment_store: &PaymentStore, payment_id: PaymentId, payment_hash: &PaymentHash,
	decision: ChannelConstrainedClaimDecision, receiving_channel_ids: &[(ChannelId, Option<u128>)],
) -> Result<ChannelConstrainedClaimOutcome, Error> {
	let failure_reason = match decision {
		ChannelConstrainedClaimDecision::Fail(reason) => Some(reason),
		_ => None,
	};
	let outcome = apply_channel_constrained_claim_decision(actions, payment_hash, decision);
	if outcome == ChannelConstrainedClaimOutcome::Failed {
		let observed_receiving_channel_ids = receiving_channel_ids
			.iter()
			.filter_map(|(_, user_channel_id)| user_channel_id.map(UserChannelId))
			.collect();
		let unidentified_count = receiving_channel_ids
			.iter()
			.filter(|(_, user_channel_id)| user_channel_id.is_none())
			.count()
			.try_into()
			.unwrap_or(u32::MAX);
		let update = PaymentDetailsUpdate {
			status: Some(PaymentStatus::Failed),
			circular_failure_reason: Some(failure_reason),
			circular_observed_receiving_channel_ids: Some(observed_receiving_channel_ids),
			circular_unidentified_receiving_channel_count: Some(unidentified_count),
			..PaymentDetailsUpdate::new(payment_id)
		};
		payment_store.update(&update)?;
	}
	Ok(outcome)
}

fn payment_claimed_store_update(
	payment_id: PaymentId, purpose: PaymentPurpose, amount_msat: u64,
) -> PaymentDetailsUpdate {
	match purpose {
		PaymentPurpose::Bolt11InvoicePayment { payment_preimage, payment_secret, .. }
		| PaymentPurpose::Bolt12OfferPayment { payment_preimage, payment_secret, .. }
		| PaymentPurpose::Bolt12RefundPayment { payment_preimage, payment_secret, .. } => {
			PaymentDetailsUpdate {
				preimage: Some(payment_preimage),
				secret: Some(Some(payment_secret)),
				amount_msat: Some(Some(amount_msat)),
				status: Some(PaymentStatus::Succeeded),
				..PaymentDetailsUpdate::new(payment_id)
			}
		},
		PaymentPurpose::SpontaneousPayment(preimage) => PaymentDetailsUpdate {
			preimage: Some(Some(preimage)),
			amount_msat: Some(Some(amount_msat)),
			status: Some(PaymentStatus::Succeeded),
			..PaymentDetailsUpdate::new(payment_id)
		},
	}
}

fn payment_sent_store_update(
	payment_id: PaymentId, payment_hash: PaymentHash, payment_preimage: PaymentPreimage,
	fee_paid_msat: Option<u64>,
) -> PaymentDetailsUpdate {
	PaymentDetailsUpdate {
		hash: Some(Some(payment_hash)),
		preimage: Some(Some(payment_preimage)),
		fee_paid_msat: Some(fee_paid_msat),
		status: Some(PaymentStatus::Succeeded),
		..PaymentDetailsUpdate::new(payment_id)
	}
}

fn fail_circular_payment_records(
	payment_store: &PaymentStore, outbound_payment_id: PaymentId,
	event_payment_hash: Option<PaymentHash>,
) -> Result<bool, Error> {
	let Some(outbound) = payment_store.get(&outbound_payment_id) else {
		return Ok(false);
	};
	let (
		payment_hash,
		outbound_preimage,
		payment_secret,
		bolt11_invoice,
		required_receiving_channel_id,
		required_sending_channel_id,
		operation_id,
		max_routing_fee_msat,
	) = match &outbound.kind {
		PaymentKind::Bolt11 {
			hash,
			preimage,
			secret: Some(secret),
			bolt11_invoice: Some(invoice),
			required_receiving_channel_id: Some(receiving_channel_id),
			required_sending_channel_id: Some(sending_channel_id),
			circular_operation_id: Some(operation_id),
			circular_outbound_payment_id: Some(stored_outbound_payment_id),
			circular_max_routing_fee_msat: Some(max_routing_fee_msat),
		} if *stored_outbound_payment_id == outbound_payment_id => (
			*hash,
			*preimage,
			*secret,
			invoice,
			*receiving_channel_id,
			*sending_channel_id,
			*operation_id,
			*max_routing_fee_msat,
		),
		_ => return Ok(false),
	};
	if outbound.id != outbound_payment_id
		|| outbound.direction != PaymentDirection::Outbound
		|| outbound.amount_msat.is_none()
		|| outbound.fee_paid_msat.is_some()
		|| outbound.status == PaymentStatus::Succeeded
		|| crate::payment::derive_circular_outbound_payment_id(operation_id) != outbound_payment_id
		|| event_payment_hash.map_or(false, |hash| hash != payment_hash)
	{
		return Err(Error::InvalidPaymentId);
	}

	let inbound_payment_id = PaymentId(payment_hash.0);
	let inbound = payment_store.get(&inbound_payment_id).ok_or(Error::InvalidPaymentId)?;
	let inbound_preimage = match &inbound.kind {
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
		} if *hash == payment_hash
			&& *secret == payment_secret
			&& invoice == bolt11_invoice
			&& *receiving_channel_id == required_receiving_channel_id
			&& *sending_channel_id == required_sending_channel_id
			&& *stored_operation_id == operation_id
			&& *stored_outbound_payment_id == outbound_payment_id
			&& *stored_max_routing_fee_msat == max_routing_fee_msat =>
		{
			*preimage
		},
		_ => return Err(Error::InvalidPaymentId),
	};
	if inbound.id != inbound_payment_id
		|| inbound.direction != PaymentDirection::Inbound
		|| inbound.amount_msat != outbound.amount_msat
		|| inbound.fee_paid_msat.is_some()
		|| inbound.status == PaymentStatus::Succeeded
		|| outbound_preimage.map_or(false, |preimage| preimage != inbound_preimage)
		|| PaymentHash(bitcoin::hashes::sha256::Hash::hash(&inbound_preimage.0).to_byte_array())
			!= payment_hash
	{
		return Err(Error::InvalidPaymentId);
	}

	let outbound_update = PaymentDetailsUpdate {
		status: Some(PaymentStatus::Failed),
		..PaymentDetailsUpdate::new(outbound_payment_id)
	};
	let inbound_update = PaymentDetailsUpdate {
		status: Some(PaymentStatus::Failed),
		..PaymentDetailsUpdate::new(inbound_payment_id)
	};
	payment_store.update(&outbound_update)?;
	payment_store.update(&inbound_update)?;
	Ok(true)
}

fn channel_constrained_claim_decision(
	kind: &PaymentKind, status: PaymentStatus, expected_amount_msat: Option<u64>,
	actual_amount_msat: u64, receiving_channel_ids: &[(ChannelId, Option<u128>)],
) -> ChannelConstrainedClaimDecision {
	let (preimage, required_channel_id, circular_metadata_matches) = match kind {
		PaymentKind::Bolt11 {
			hash,
			preimage,
			required_receiving_channel_id: Some(required_channel_id),
			required_sending_channel_id,
			circular_operation_id,
			circular_outbound_payment_id,
			circular_max_routing_fee_msat,
			..
		} => {
			let metadata_matches = match (
				required_sending_channel_id,
				circular_operation_id,
				circular_outbound_payment_id,
				circular_max_routing_fee_msat,
			) {
				(
					Some(required_sending_channel_id),
					Some(operation_id),
					Some(outbound_payment_id),
					Some(_),
				) => {
					required_sending_channel_id != required_channel_id
						&& operation_id != outbound_payment_id
						&& outbound_payment_id.0 != hash.0
				},
				_ => false,
			};
			(preimage, required_channel_id, metadata_matches)
		},
		_ => return ChannelConstrainedClaimDecision::NotConstrained,
	};

	if status != PaymentStatus::Pending {
		return ChannelConstrainedClaimDecision::Fail(
			CircularPaymentFailureReason::PaymentNotPending,
		);
	}
	if !circular_metadata_matches {
		return ChannelConstrainedClaimDecision::Fail(
			CircularPaymentFailureReason::CircularMetadataMismatch,
		);
	}
	if expected_amount_msat.map(|expected| actual_amount_msat != expected).unwrap_or(true) {
		return ChannelConstrainedClaimDecision::Fail(CircularPaymentFailureReason::AmountMismatch);
	}
	let Some(preimage) = preimage else {
		return ChannelConstrainedClaimDecision::Fail(
			CircularPaymentFailureReason::MissingPreimage,
		);
	};
	if receiving_channel_ids.is_empty()
		|| receiving_channel_ids.iter().any(|(_, user_channel_id)| user_channel_id.is_none())
	{
		return ChannelConstrainedClaimDecision::Fail(
			CircularPaymentFailureReason::MissingReceivingChannelIdentity,
		);
	}
	if receiving_channel_ids
		.iter()
		.any(|(_, user_channel_id)| *user_channel_id != Some(required_channel_id.0))
	{
		return ChannelConstrainedClaimDecision::Fail(
			CircularPaymentFailureReason::ReceivingChannelMismatch,
		);
	}

	ChannelConstrainedClaimDecision::Claim(*preimage)
}

/// An event emitted by [`Node`], which should be handled by the user.
///
/// [`Node`]: [`crate::Node`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
	/// A sent payment was successful.
	PaymentSuccessful {
		/// A local identifier used to track the payment.
		///
		/// Will only be `None` for events serialized with LDK Node v0.2.1 or prior.
		payment_id: Option<PaymentId>,
		/// The hash of the payment.
		payment_hash: PaymentHash,
		/// The preimage to the `payment_hash`.
		///
		/// Note that this serves as a payment receipt.
		///
		/// Will only be `None` for events serialized with LDK Node v0.4.2 or prior.
		payment_preimage: Option<PaymentPreimage>,
		/// The total fee which was spent at intermediate hops in this payment.
		fee_paid_msat: Option<u64>,
	},
	/// A sent payment has failed.
	PaymentFailed {
		/// A local identifier used to track the payment.
		///
		/// Will only be `None` for events serialized with LDK Node v0.2.1 or prior.
		payment_id: Option<PaymentId>,
		/// The hash of the payment.
		///
		/// This will be `None` if the payment failed before receiving an invoice when paying a
		/// BOLT12 [`Offer`].
		///
		/// [`Offer`]: lightning::offers::offer::Offer
		payment_hash: Option<PaymentHash>,
		/// The reason why the payment failed.
		///
		/// This will be `None` for events serialized by LDK Node v0.2.1 and prior.
		reason: Option<PaymentFailureReason>,
	},
	/// A payment has been received.
	PaymentReceived {
		/// A local identifier used to track the payment.
		///
		/// Will only be `None` for events serialized with LDK Node v0.2.1 or prior.
		payment_id: Option<PaymentId>,
		/// The hash of the payment.
		payment_hash: PaymentHash,
		/// The value, in thousandths of a satoshi, that has been received.
		amount_msat: u64,
		/// Custom TLV records received on the payment
		custom_records: Vec<CustomTlvRecord>,
	},
	/// A payment has been forwarded.
	PaymentForwarded {
		/// The channel id of the incoming channel between the previous node and us.
		prev_channel_id: ChannelId,
		/// The channel id of the outgoing channel between the next node and us.
		next_channel_id: ChannelId,
		/// The `user_channel_id` of the incoming channel between the previous node and us.
		///
		/// Will only be `None` for events serialized with LDK Node v0.3.0 or prior.
		prev_user_channel_id: Option<UserChannelId>,
		/// The `user_channel_id` of the outgoing channel between the next node and us.
		///
		/// This will be `None` if the payment was settled via an on-chain transaction. See the
		/// caveat described for the `total_fee_earned_msat` field.
		next_user_channel_id: Option<UserChannelId>,
		/// The node id of the previous node.
		///
		/// This is only `None` for HTLCs received prior to LDK Node v0.5 or for events serialized by
		/// versions prior to v0.5.
		prev_node_id: Option<PublicKey>,
		/// The node id of the next node.
		///
		/// This is only `None` for HTLCs received prior to LDK Node v0.5 or for events serialized by
		/// versions prior to v0.5.
		next_node_id: Option<PublicKey>,
		/// The total fee, in milli-satoshis, which was earned as a result of the payment.
		///
		/// Note that if we force-closed the channel over which we forwarded an HTLC while the HTLC
		/// was pending, the amount the next hop claimed will have been rounded down to the nearest
		/// whole satoshi. Thus, the fee calculated here may be higher than expected as we still
		/// claimed the full value in millisatoshis from the source. In this case,
		/// `claim_from_onchain_tx` will be set.
		///
		/// If the channel which sent us the payment has been force-closed, we will claim the funds
		/// via an on-chain transaction. In that case we do not yet know the on-chain transaction
		/// fees which we will spend and will instead set this to `None`.
		total_fee_earned_msat: Option<u64>,
		/// The share of the total fee, in milli-satoshis, which was withheld in addition to the
		/// forwarding fee.
		///
		/// This will only be `Some` if we forwarded an intercepted HTLC with less than the
		/// expected amount. This means our counterparty accepted to receive less than the invoice
		/// amount.
		///
		/// The caveat described above the `total_fee_earned_msat` field applies here as well.
		skimmed_fee_msat: Option<u64>,
		/// If this is `true`, the forwarded HTLC was claimed by our counterparty via an on-chain
		/// transaction.
		claim_from_onchain_tx: bool,
		/// The final amount forwarded, in milli-satoshis, after the fee is deducted.
		///
		/// The caveat described above the `total_fee_earned_msat` field applies here as well.
		outbound_amount_forwarded_msat: Option<u64>,
	},
	/// A payment for a previously-registered payment hash has been received.
	///
	/// This needs to be manually claimed by supplying the correct preimage to [`claim_for_hash`].
	///
	/// If the the provided parameters don't match the expectations or the preimage can't be
	/// retrieved in time, should be failed-back via [`fail_for_hash`].
	///
	/// Note claiming will necessarily fail after the `claim_deadline` has been reached.
	///
	/// [`claim_for_hash`]: crate::payment::Bolt11Payment::claim_for_hash
	/// [`fail_for_hash`]: crate::payment::Bolt11Payment::fail_for_hash
	PaymentClaimable {
		/// A local identifier used to track the payment.
		payment_id: PaymentId,
		/// The hash of the payment.
		payment_hash: PaymentHash,
		/// The value, in thousandths of a satoshi, that is claimable.
		claimable_amount_msat: u64,
		/// The block height at which this payment will be failed back and will no longer be
		/// eligible for claiming.
		claim_deadline: Option<u32>,
		/// Custom TLV records attached to the payment
		custom_records: Vec<CustomTlvRecord>,
		/// The local channels over which the claimable payment parts arrived.
		///
		/// All entries must match an application's required incoming channel before it claims a
		/// channel-constrained payment.
		receiving_channels: Vec<ReceivingChannel>,
	},
	/// A channel has been created and is pending confirmation on-chain.
	ChannelPending {
		/// The `channel_id` of the channel.
		channel_id: ChannelId,
		/// The `user_channel_id` of the channel.
		user_channel_id: UserChannelId,
		/// The `temporary_channel_id` this channel used to be known by during channel establishment.
		former_temporary_channel_id: ChannelId,
		/// The `node_id` of the channel counterparty.
		counterparty_node_id: PublicKey,
		/// The outpoint of the channel's funding transaction.
		funding_txo: OutPoint,
	},
	/// A channel is ready to be used.
	///
	/// This event is emitted when:
	/// - A new channel has been established and is ready for use
	/// - An existing channel has been spliced and is ready with the new funding output
	ChannelReady {
		/// The `channel_id` of the channel.
		channel_id: ChannelId,
		/// The `user_channel_id` of the channel.
		user_channel_id: UserChannelId,
		/// The `node_id` of the channel counterparty.
		///
		/// This will be `None` for events serialized by LDK Node v0.1.0 and prior.
		counterparty_node_id: Option<PublicKey>,
		/// The outpoint of the channel's funding transaction.
		///
		/// This represents the channel's current funding output, which may change when the
		/// channel is spliced. For spliced channels, this will contain the new funding output
		/// from the confirmed splice transaction.
		///
		/// This will be `None` for events serialized by LDK Node v0.6.0 and prior.
		funding_txo: Option<OutPoint>,
	},
	/// A channel has been closed.
	ChannelClosed {
		/// The `channel_id` of the channel.
		channel_id: ChannelId,
		/// The `user_channel_id` of the channel.
		user_channel_id: UserChannelId,
		/// The `node_id` of the channel counterparty.
		///
		/// This will be `None` for events serialized by LDK Node v0.1.0 and prior.
		counterparty_node_id: Option<PublicKey>,
		/// This will be `None` for events serialized by LDK Node v0.2.1 and prior.
		reason: Option<ClosureReason>,
	},
	/// A channel splice is pending confirmation on-chain.
	SplicePending {
		/// The `channel_id` of the channel.
		channel_id: ChannelId,
		/// The `user_channel_id` of the channel.
		user_channel_id: UserChannelId,
		/// The `node_id` of the channel counterparty.
		counterparty_node_id: PublicKey,
		/// The outpoint of the channel's splice funding transaction.
		new_funding_txo: OutPoint,
	},
	/// A channel splice has failed.
	SpliceFailed {
		/// The `channel_id` of the channel.
		channel_id: ChannelId,
		/// The `user_channel_id` of the channel.
		user_channel_id: UserChannelId,
		/// The `node_id` of the channel counterparty.
		counterparty_node_id: PublicKey,
		/// The outpoint of the channel's splice funding transaction, if one was created.
		abandoned_funding_txo: Option<OutPoint>,
	},
}

impl_writeable_tlv_based_enum!(Event,
	(0, PaymentSuccessful) => {
		(0, payment_hash, required),
		(1, fee_paid_msat, option),
		(3, payment_id, option),
		(5, payment_preimage, option),
	},
	(1, PaymentFailed) => {
		(0, payment_hash, option),
		(1, reason, upgradable_option),
		(3, payment_id, option),
	},
	(2, PaymentReceived) => {
		(0, payment_hash, required),
		(1, payment_id, option),
		(2, amount_msat, required),
		(3, custom_records, optional_vec),
	},
	(3, ChannelReady) => {
		(0, channel_id, required),
		(1, counterparty_node_id, option),
		(2, user_channel_id, required),
		(3, funding_txo, option),
	},
	(4, ChannelPending) => {
		(0, channel_id, required),
		(2, user_channel_id, required),
		(4, former_temporary_channel_id, required),
		(6, counterparty_node_id, required),
		(8, funding_txo, required),
	},
	(5, ChannelClosed) => {
		(0, channel_id, required),
		(1, counterparty_node_id, option),
		(2, user_channel_id, required),
		(3, reason, upgradable_option),
	},
	(6, PaymentClaimable) => {
		(0, payment_hash, required),
		(2, payment_id, required),
		(4, claimable_amount_msat, required),
		(6, claim_deadline, option),
		(7, custom_records, optional_vec),
		(8, receiving_channels, optional_vec),
	},
	(7, PaymentForwarded) => {
		(0, prev_channel_id, required),
		(1, prev_node_id, option),
		(2, next_channel_id, required),
		(3, next_node_id, option),
		(4, prev_user_channel_id, option),
		(6, next_user_channel_id, option),
		(8, total_fee_earned_msat, option),
		(10, skimmed_fee_msat, option),
		(12, claim_from_onchain_tx, required),
		(14, outbound_amount_forwarded_msat, option),
	},
	(8, SplicePending) => {
		(1, channel_id, required),
		(3, counterparty_node_id, required),
		(5, user_channel_id, required),
		(7, new_funding_txo, required),
	},
	(9, SpliceFailed) => {
		(1, channel_id, required),
		(3, counterparty_node_id, required),
		(5, user_channel_id, required),
		(7, abandoned_funding_txo, option),
	},
);

pub struct EventQueue<L: Deref>
where
	L::Target: LdkLogger,
{
	queue: Arc<Mutex<VecDeque<Event>>>,
	waker: Arc<Mutex<Option<Waker>>>,
	kv_store: Arc<DynStore>,
	logger: L,
}

impl<L: Deref> EventQueue<L>
where
	L::Target: LdkLogger,
{
	pub(crate) fn new(kv_store: Arc<DynStore>, logger: L) -> Self {
		let queue = Arc::new(Mutex::new(VecDeque::new()));
		let waker = Arc::new(Mutex::new(None));
		Self { queue, waker, kv_store, logger }
	}

	pub(crate) async fn add_event(&self, event: Event) -> Result<(), Error> {
		let data = {
			let mut locked_queue = self.queue.lock().unwrap();
			locked_queue.push_back(event);
			EventQueueSerWrapper(&locked_queue).encode()
		};

		self.persist_queue(data).await?;

		if let Some(waker) = self.waker.lock().unwrap().take() {
			waker.wake();
		}
		Ok(())
	}

	pub(crate) fn next_event(&self) -> Option<Event> {
		let locked_queue = self.queue.lock().unwrap();
		locked_queue.front().cloned()
	}

	pub(crate) async fn next_event_async(&self) -> Event {
		EventFuture { event_queue: Arc::clone(&self.queue), waker: Arc::clone(&self.waker) }.await
	}

	pub(crate) async fn event_handled(&self) -> Result<(), Error> {
		let data = {
			let mut locked_queue = self.queue.lock().unwrap();
			locked_queue.pop_front();
			EventQueueSerWrapper(&locked_queue).encode()
		};

		self.persist_queue(data).await?;

		if let Some(waker) = self.waker.lock().unwrap().take() {
			waker.wake();
		}
		Ok(())
	}

	async fn persist_queue(&self, encoded_queue: Vec<u8>) -> Result<(), Error> {
		KVStore::write(
			&*self.kv_store,
			EVENT_QUEUE_PERSISTENCE_PRIMARY_NAMESPACE,
			EVENT_QUEUE_PERSISTENCE_SECONDARY_NAMESPACE,
			EVENT_QUEUE_PERSISTENCE_KEY,
			encoded_queue,
		)
		.await
		.map_err(|e| {
			log_error!(
				self.logger,
				"Write for key {}/{}/{} failed due to: {}",
				EVENT_QUEUE_PERSISTENCE_PRIMARY_NAMESPACE,
				EVENT_QUEUE_PERSISTENCE_SECONDARY_NAMESPACE,
				EVENT_QUEUE_PERSISTENCE_KEY,
				e
			);
			Error::PersistenceFailed
		})?;
		Ok(())
	}
}

impl<L: Deref> ReadableArgs<(Arc<DynStore>, L)> for EventQueue<L>
where
	L::Target: LdkLogger,
{
	#[inline]
	fn read<R: lightning::io::Read>(
		reader: &mut R, args: (Arc<DynStore>, L),
	) -> Result<Self, lightning::ln::msgs::DecodeError> {
		let (kv_store, logger) = args;
		let read_queue: EventQueueDeserWrapper = Readable::read(reader)?;
		let queue = Arc::new(Mutex::new(read_queue.0));
		let waker = Arc::new(Mutex::new(None));
		Ok(Self { queue, waker, kv_store, logger })
	}
}

struct EventQueueDeserWrapper(VecDeque<Event>);

impl Readable for EventQueueDeserWrapper {
	fn read<R: lightning::io::Read>(
		reader: &mut R,
	) -> Result<Self, lightning::ln::msgs::DecodeError> {
		let len: u16 = Readable::read(reader)?;
		let mut queue = VecDeque::with_capacity(len as usize);
		for _ in 0..len {
			queue.push_back(Readable::read(reader)?);
		}
		Ok(Self(queue))
	}
}

struct EventQueueSerWrapper<'a>(&'a VecDeque<Event>);

impl Writeable for EventQueueSerWrapper<'_> {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), lightning::io::Error> {
		(self.0.len() as u16).write(writer)?;
		for e in self.0.iter() {
			e.write(writer)?;
		}
		Ok(())
	}
}

struct EventFuture {
	event_queue: Arc<Mutex<VecDeque<Event>>>,
	waker: Arc<Mutex<Option<Waker>>>,
}

impl Future for EventFuture {
	type Output = Event;

	fn poll(
		self: core::pin::Pin<&mut Self>, cx: &mut core::task::Context<'_>,
	) -> core::task::Poll<Self::Output> {
		if let Some(event) = self.event_queue.lock().unwrap().front() {
			Poll::Ready(event.clone())
		} else {
			*self.waker.lock().unwrap() = Some(cx.waker().clone());
			Poll::Pending
		}
	}
}

pub(crate) struct EventHandler<L: Deref + Clone + Sync + Send + 'static>
where
	L::Target: LdkLogger,
{
	event_queue: Arc<EventQueue<L>>,
	wallet: Arc<Wallet>,
	bump_tx_event_handler: Arc<BumpTransactionEventHandler>,
	channel_manager: Arc<ChannelManager>,
	connection_manager: Arc<ConnectionManager<L>>,
	output_sweeper: Arc<Sweeper>,
	network_graph: Arc<Graph>,
	liquidity_source: Option<Arc<LiquiditySource<Arc<Logger>>>>,
	payment_store: Arc<PaymentStore>,
	peer_store: Arc<PeerStore<L>>,
	runtime: Arc<Runtime>,
	logger: L,
	config: Arc<Config>,
	static_invoice_store: Option<StaticInvoiceStore>,
	onion_messenger: Arc<OnionMessenger>,
	om_mailbox: Option<Arc<OnionMessageMailbox>>,
}

impl<L: Deref + Clone + Sync + Send + 'static> EventHandler<L>
where
	L::Target: LdkLogger,
{
	pub fn new(
		event_queue: Arc<EventQueue<L>>, wallet: Arc<Wallet>,
		bump_tx_event_handler: Arc<BumpTransactionEventHandler>,
		channel_manager: Arc<ChannelManager>, connection_manager: Arc<ConnectionManager<L>>,
		output_sweeper: Arc<Sweeper>, network_graph: Arc<Graph>,
		liquidity_source: Option<Arc<LiquiditySource<Arc<Logger>>>>,
		payment_store: Arc<PaymentStore>, peer_store: Arc<PeerStore<L>>,
		static_invoice_store: Option<StaticInvoiceStore>, onion_messenger: Arc<OnionMessenger>,
		om_mailbox: Option<Arc<OnionMessageMailbox>>, runtime: Arc<Runtime>, logger: L,
		config: Arc<Config>,
	) -> Self {
		Self {
			event_queue,
			wallet,
			bump_tx_event_handler,
			channel_manager,
			connection_manager,
			output_sweeper,
			network_graph,
			liquidity_source,
			payment_store,
			peer_store,
			logger,
			runtime,
			config,
			static_invoice_store,
			onion_messenger,
			om_mailbox,
		}
	}

	pub async fn handle_event(&self, event: LdkEvent) -> Result<(), ReplayEvent> {
		match event {
			LdkEvent::FundingGenerationReady {
				temporary_channel_id,
				counterparty_node_id,
				channel_value_satoshis,
				output_script,
				user_channel_id,
			} => {
				// Construct the raw transaction with the output that is paid the amount of the
				// channel.
				let confirmation_target = ConfirmationTarget::ChannelFunding;

				// We set nLockTime to the current height to discourage fee sniping.
				let cur_height = self.channel_manager.current_best_block().height;
				let locktime = LockTime::from_height(cur_height).unwrap_or(LockTime::ZERO);

				// Sign the final funding transaction and broadcast it.
				let channel_amount = Amount::from_sat(channel_value_satoshis);
				match self.wallet.create_funding_transaction(
					output_script,
					channel_amount,
					confirmation_target,
					locktime,
				) {
					Ok(final_tx) => {
						let needs_manual_broadcast =
							self.liquidity_source.as_ref().map_or(false, |ls| {
								ls.as_ref().lsps2_channel_needs_manual_broadcast(
									counterparty_node_id,
									user_channel_id,
								)
							});

						let result = if needs_manual_broadcast {
							self.liquidity_source.as_ref().map(|ls| {
								ls.lsps2_store_funding_transaction(
									user_channel_id,
									counterparty_node_id,
									final_tx.clone(),
								);
							});
							self.channel_manager.funding_transaction_generated_manual_broadcast(
								temporary_channel_id,
								counterparty_node_id,
								final_tx,
							)
						} else {
							self.channel_manager.funding_transaction_generated(
								temporary_channel_id,
								counterparty_node_id,
								final_tx,
							)
						};

						match result {
							Ok(()) => {},
							Err(APIError::APIMisuseError { err }) => {
								log_error!(
									self.logger,
									"Encountered APIMisuseError, this should never happen: {}",
									err
								);
								debug_assert!(false, "APIMisuseError: {}", err);
							},
							Err(APIError::ChannelUnavailable { err }) => {
								log_error!(
									self.logger,
									"Failed to process funding transaction as channel went away before we could fund it: {}",
									err
								);
							},
							Err(err) => {
								log_error!(
									self.logger,
									"Failed to process funding transaction: {:?}",
									err
								);
							},
						}
					},
					Err(err) => {
						log_error!(self.logger, "Failed to create funding transaction: {}", err);
						self.channel_manager
							.force_close_broadcasting_latest_txn(
								&temporary_channel_id,
								&counterparty_node_id,
								"Failed to create funding transaction".to_string(),
							)
							.unwrap_or_else(|e| {
								log_error!(self.logger, "Failed to force close channel after funding generation failed: {:?}", e);
								debug_assert!(false,
									"Failed to force close channel after funding generation failed"
								);
							});
					},
				}
			},
			LdkEvent::FundingTxBroadcastSafe { user_channel_id, counterparty_node_id, .. } => {
				self.liquidity_source.as_ref().map(|ls| {
					ls.lsps2_funding_tx_broadcast_safe(user_channel_id, counterparty_node_id);
				});
			},
			LdkEvent::PaymentClaimable {
				payment_hash,
				purpose,
				amount_msat,
				claim_deadline,
				onion_fields,
				counterparty_skimmed_fee_msat,
				receiving_channel_ids,
				..
			} => {
				let payment_id = PaymentId(payment_hash.0);

				if let Some((tlv_type, _)) = onion_fields
					.as_ref()
					.and_then(|fields| fields.custom_tlvs().iter().find(|(id, _)| id % 2 == 0))
				{
					log_info!(
						self.logger,
						"Refusing inbound payment with hash {} as the sender included unknown required TLVs (incl {})",
						hex_utils::to_string(&payment_hash.0),
						tlv_type,
					);
					let error_code = FailureCode::InvalidOnionPayload(Some((*tlv_type, 0)));
					self.channel_manager.fail_htlc_backwards_with_reason(&payment_hash, error_code);
					return Ok(());
				}

				if let Some(info) = self.payment_store.get(&payment_id) {
					if info.direction == PaymentDirection::Outbound {
						log_info!(
							self.logger,
							"Refused inbound payment with ID {}: circular payments are unsupported.",
							payment_id
						);
						self.channel_manager.fail_htlc_backwards(&payment_hash);
						return Ok(());
					}

					if info.status == PaymentStatus::Succeeded
						|| matches!(info.kind, PaymentKind::Spontaneous { .. })
					{
						log_info!(
							self.logger,
							"Refused duplicate inbound payment from payment hash {} of {}msat",
							hex_utils::to_string(&payment_hash.0),
							amount_msat,
						);
						self.channel_manager.fail_htlc_backwards(&payment_hash);
						return Ok(());
					}

					let max_total_opening_fee_msat = match info.kind {
						PaymentKind::Bolt11Jit { lsp_fee_limits, .. } => {
							lsp_fee_limits
								.max_total_opening_fee_msat
								.or_else(|| {
									lsp_fee_limits.max_proportional_opening_fee_ppm_msat.and_then(
										|max_prop_fee| {
											// If it's a variable amount payment, compute the actual fee.
											compute_opening_fee(amount_msat, 0, max_prop_fee)
										},
									)
								})
								.unwrap_or(0)
						},
						_ => 0,
					};

					if counterparty_skimmed_fee_msat > max_total_opening_fee_msat {
						log_info!(
							self.logger,
							"Refusing inbound payment with hash {} as the counterparty-withheld fee of {}msat exceeds our limit of {}msat",
							hex_utils::to_string(&payment_hash.0),
							counterparty_skimmed_fee_msat,
							max_total_opening_fee_msat,
						);
						self.channel_manager.fail_htlc_backwards(&payment_hash);

						let update = PaymentDetailsUpdate {
							hash: Some(Some(payment_hash)),
							status: Some(PaymentStatus::Failed),
							..PaymentDetailsUpdate::new(payment_id)
						};
						match self.payment_store.update(&update) {
							Ok(_) => return Ok(()),
							Err(e) => {
								log_error!(self.logger, "Failed to access payment store: {}", e);
								return Err(ReplayEvent());
							},
						};
					}

					// If the LSP skimmed anything, update our stored payment.
					if counterparty_skimmed_fee_msat > 0 {
						match info.kind {
							PaymentKind::Bolt11Jit { .. } => {
								let update = PaymentDetailsUpdate {
									counterparty_skimmed_fee_msat: Some(Some(counterparty_skimmed_fee_msat)),
									..PaymentDetailsUpdate::new(payment_id)
								};
								match self.payment_store.update(&update) {
									Ok(_) => (),
									Err(e) => {
										log_error!(self.logger, "Failed to access payment store: {}", e);
										return Err(ReplayEvent());
									},
								};
							}
							_ => debug_assert!(false, "We only expect the counterparty to get away with withholding fees for JIT payments."),
						}
					}

					// A prepared circular payment keeps its preimage in the payment store and may
					// claim only after every MPP part is proven to have arrived through the exact
					// required local channel. Apply the constraint even if ChannelManager unexpectedly
					// knows the preimage.
					let claim_decision = channel_constrained_claim_decision(
						&info.kind,
						info.status,
						info.amount_msat,
						amount_msat,
						receiving_channel_ids.as_slice(),
					);
					let claim_outcome = match handle_channel_constrained_claim(
						&*self.channel_manager,
						&self.payment_store,
						payment_id,
						&payment_hash,
						claim_decision,
						receiving_channel_ids.as_slice(),
					) {
						Ok(outcome) => outcome,
						Err(e) => {
							log_error!(self.logger, "Failed to access payment store: {}", e);
							return Err(ReplayEvent());
						},
					};
					match claim_outcome {
						ChannelConstrainedClaimOutcome::Claimed => {
							log_info!(
								self.logger,
								"Claimed channel-constrained inbound payment through its required channel."
							);
							return Ok(());
						},
						ChannelConstrainedClaimOutcome::Failed => {
							log_info!(
								self.logger,
								"Refused channel-constrained inbound payment because its amount, preimage state, or receiving channels did not match the persisted constraint."
							);
							return Ok(());
						},
						ChannelConstrainedClaimOutcome::NotConstrained => {},
					}

					// If this is known by the store but ChannelManager doesn't know the preimage,
					// the payment has been registered via a `_for_hash` variant. Ordinary payments
					// are surfaced for manual claiming.
					let manually_claimable = match info.kind {
						PaymentKind::Bolt11 { preimage, required_receiving_channel_id, .. }
							if purpose.preimage().is_none() =>
						{
							debug_assert!(required_receiving_channel_id.is_none());
							debug_assert!(
								preimage.is_none(),
								"Ordinary manual-claim payments must not persist a preimage"
							);
							true
						},
						PaymentKind::Bolt11Jit { preimage, .. } if purpose.preimage().is_none() => {
							debug_assert!(
								preimage.is_none(),
								"We would have registered the preimage if we knew"
							);
							true
						},
						_ => false,
					};

					if manually_claimable {
						let custom_records = onion_fields
							.map(|cf| cf.custom_tlvs().into_iter().map(|tlv| tlv.into()).collect())
							.unwrap_or_default();
						let event = Event::PaymentClaimable {
							payment_id,
							payment_hash,
							claimable_amount_msat: amount_msat,
							claim_deadline,
							custom_records,
							receiving_channels: receiving_channel_ids
								.iter()
								.map(|(channel_id, user_channel_id)| ReceivingChannel {
									channel_id: *channel_id,
									user_channel_id: user_channel_id.map(UserChannelId),
								})
								.collect(),
						};
						match self.event_queue.add_event(event).await {
							Ok(_) => return Ok(()),
							Err(e) => {
								log_error!(self.logger, "Failed to push to event queue: {}", e);
								return Err(ReplayEvent());
							},
						};
					}
				} else if counterparty_skimmed_fee_msat > 0 {
					// We only ever authorize an LSP to withhold a fee for JIT-channel payments we
					// previously registered. Any other payment (e.g., BOLT12 offer or spontaneous
					// payments, for which no record exists yet) must not have fees skimmed.
					log_info!(
						self.logger,
						"Refusing inbound payment with hash {} as the counterparty withheld {}msat without a corresponding JIT-channel payment authorizing it",
						hex_utils::to_string(&payment_hash.0),
						counterparty_skimmed_fee_msat,
					);
					self.channel_manager.fail_htlc_backwards(&payment_hash);
					return Ok(());
				}

				log_info!(
					self.logger,
					"Received payment from payment hash {} of {}msat",
					hex_utils::to_string(&payment_hash.0),
					amount_msat,
				);
				let payment_preimage = match purpose {
					PaymentPurpose::Bolt11InvoicePayment { payment_preimage, .. } => {
						payment_preimage
					},
					PaymentPurpose::Bolt12OfferPayment {
						payment_preimage,
						payment_secret,
						payment_context,
						..
					} => {
						let payer_note = payment_context.invoice_request.payer_note_truncated;
						let offer_id = payment_context.offer_id;
						let quantity = payment_context.invoice_request.quantity;
						let kind = PaymentKind::Bolt12Offer {
							hash: Some(payment_hash),
							preimage: payment_preimage,
							secret: Some(payment_secret),
							offer_id,
							payer_note,
							quantity,
						};

						let payment = PaymentDetails::new(
							payment_id,
							kind,
							Some(amount_msat),
							None,
							PaymentDirection::Inbound,
							PaymentStatus::Pending,
						);

						match self.payment_store.insert(payment) {
							Ok(false) => (),
							Ok(true) => {
								log_error!(
									self.logger,
									"Bolt12OfferPayment with ID {} was previously known",
									payment_id,
								);
								debug_assert!(false);
							},
							Err(e) => {
								log_error!(
									self.logger,
									"Failed to insert payment with ID {}: {}",
									payment_id,
									e
								);
								debug_assert!(false);
							},
						}
						payment_preimage
					},
					PaymentPurpose::Bolt12RefundPayment { payment_preimage, .. } => {
						payment_preimage
					},
					PaymentPurpose::SpontaneousPayment(preimage) => {
						// TODO: use CustomTlvRecord instead of TlvEntry
						let custom_tlvs = onion_fields
							.map(|of| {
								of.custom_tlvs()
									.iter()
									.map(|(t, v)| TlvEntry { r#type: *t, value: v.clone() })
									.collect()
							})
							.unwrap_or_default();
						log_info!(
							self.logger,
							"Saving spontaneous payment with custom TLVs {:?} for payment hash {} of {}msat",
							custom_tlvs,
							hex_utils::to_string(&payment_hash.0),
							amount_msat,
						);

						// Since it's spontaneous, we insert it now into our store.
						let kind = PaymentKind::Spontaneous {
							hash: payment_hash,
							preimage: Some(preimage),
							custom_tlvs,
						};

						let payment = PaymentDetails::new(
							payment_id,
							kind,
							Some(amount_msat),
							None,
							PaymentDirection::Inbound,
							PaymentStatus::Pending,
						);

						match self.payment_store.insert(payment) {
							Ok(false) => (),
							Ok(true) => {
								log_error!(
									self.logger,
									"Spontaneous payment with ID {} was previously known",
									payment_id,
								);
								debug_assert!(false);
							},
							Err(e) => {
								log_error!(
									self.logger,
									"Failed to insert payment with ID {}: {}",
									payment_id,
									e
								);
								debug_assert!(false);
							},
						}

						Some(preimage)
					},
				};

				if let Some(preimage) = payment_preimage {
					self.channel_manager.claim_funds(preimage);
				} else {
					log_error!(
						self.logger,
						"Failed to claim payment with ID {}: preimage unknown.",
						payment_id,
					);
					self.channel_manager.fail_htlc_backwards(&payment_hash);

					let update = PaymentDetailsUpdate {
						hash: Some(Some(payment_hash)),
						status: Some(PaymentStatus::Failed),
						..PaymentDetailsUpdate::new(payment_id)
					};
					match self.payment_store.update(&update) {
						Ok(_) => return Ok(()),
						Err(e) => {
							log_error!(self.logger, "Failed to access payment store: {}", e);
							return Err(ReplayEvent());
						},
					};
				}
			},
			LdkEvent::PaymentClaimed {
				payment_hash,
				purpose,
				amount_msat,
				receiver_node_id: _,
				htlcs: _,
				sender_intended_total_msat: _,
				onion_fields,
				payment_id: _,
			} => {
				let payment_id = PaymentId(payment_hash.0);
				log_info!(
					self.logger,
					"Claimed payment with ID {} from payment hash {} of {}msat.",
					payment_id,
					hex_utils::to_string(&payment_hash.0),
					amount_msat,
				);

				let update = payment_claimed_store_update(payment_id, purpose, amount_msat);

				match self.payment_store.update(&update) {
					Ok(DataStoreUpdateResult::Updated) | Ok(DataStoreUpdateResult::Unchanged) => (
						// No need to do anything if the idempotent update was applied, which might
						// be the result of a replayed event.
					),
					Ok(DataStoreUpdateResult::NotFound) => {
						log_error!(
							self.logger,
							"Claimed payment with ID {} couldn't be found in store",
							payment_id,
						);
					},
					Err(e) => {
						log_error!(
							self.logger,
							"Failed to update payment with ID {}: {}",
							payment_id,
							e
						);
						return Err(ReplayEvent());
					},
				}

				let event = Event::PaymentReceived {
					payment_id: Some(payment_id),
					payment_hash,
					amount_msat,
					custom_records: onion_fields
						.map(|cf| cf.custom_tlvs().into_iter().map(|tlv| tlv.into()).collect())
						.unwrap_or_default(),
				};
				match self.event_queue.add_event(event).await {
					Ok(_) => return Ok(()),
					Err(e) => {
						log_error!(self.logger, "Failed to push to event queue: {}", e);
						return Err(ReplayEvent());
					},
				};
			},
			LdkEvent::PaymentSent {
				payment_id,
				payment_preimage,
				payment_hash,
				fee_paid_msat,
				..
			} => {
				let payment_id = if let Some(id) = payment_id {
					id
				} else {
					debug_assert!(false, "payment_id should always be set.");
					return Ok(());
				};

				let update = payment_sent_store_update(
					payment_id,
					payment_hash,
					payment_preimage,
					fee_paid_msat,
				);

				match self.payment_store.update(&update) {
					Ok(_) => {},
					Err(e) => {
						log_error!(self.logger, "Failed to access payment store: {}", e);
						return Err(ReplayEvent());
					},
				};

				self.payment_store.get(&payment_id).map(|payment| {
					log_info!(
						self.logger,
						"Successfully sent payment of {}msat{} with payment hash {}",
						payment.amount_msat.unwrap(),
						if let Some(fee) = fee_paid_msat {
							format!(" (fee {} msat)", fee)
						} else {
							"".to_string()
						},
						hex_utils::to_string(&payment_hash.0),
					);
				});
				let event = Event::PaymentSuccessful {
					payment_id: Some(payment_id),
					payment_hash,
					payment_preimage: Some(payment_preimage),
					fee_paid_msat,
				};

				match self.event_queue.add_event(event).await {
					Ok(_) => return Ok(()),
					Err(e) => {
						log_error!(self.logger, "Failed to push to event queue: {}", e);
						return Err(ReplayEvent());
					},
				};
			},
			LdkEvent::PaymentFailed { payment_id, payment_hash, reason, .. } => {
				// LDK may emit PaymentFailed after PaymentSent. Ignore the entire late failure so
				// it cannot alter payment metadata or emit a contradictory event.
				if let Some(payment) = self.payment_store.get(&payment_id) {
					if payment.direction == PaymentDirection::Outbound
						&& payment.kind.is_lightning_payment()
						&& payment.status == PaymentStatus::Succeeded
					{
						log_info!(
							self.logger,
							"Ignoring late payment failure for already-succeeded payment with ID {}.",
							payment_id
						);
						return Ok(());
					}
				}

				log_info!(
					self.logger,
					"Failed to send payment with ID {} due to {:?}.",
					payment_id,
					reason
				);

				match fail_circular_payment_records(&self.payment_store, payment_id, payment_hash) {
					Ok(true) => {},
					Ok(false) => {
						let update = PaymentDetailsUpdate {
							hash: Some(payment_hash),
							status: Some(PaymentStatus::Failed),
							..PaymentDetailsUpdate::new(payment_id)
						};
						if let Err(e) = self.payment_store.update(&update) {
							log_error!(self.logger, "Failed to access payment store: {}", e);
							return Err(ReplayEvent());
						}
					},
					Err(e) => {
						log_error!(
							self.logger,
							"Failed to persist both circular payment failure records: {}",
							e
						);
						return Err(ReplayEvent());
					},
				}

				let event =
					Event::PaymentFailed { payment_id: Some(payment_id), payment_hash, reason };
				match self.event_queue.add_event(event).await {
					Ok(_) => return Ok(()),
					Err(e) => {
						log_error!(self.logger, "Failed to push to event queue: {}", e);
						return Err(ReplayEvent());
					},
				};
			},

			LdkEvent::PaymentPathSuccessful { .. } => {},
			LdkEvent::PaymentPathFailed { .. } => {},
			LdkEvent::ProbeSuccessful { .. } => {},
			LdkEvent::ProbeFailed { .. } => {},
			LdkEvent::HTLCHandlingFailed { failure_type, .. } => {
				if let Some(liquidity_source) = self.liquidity_source.as_ref() {
					liquidity_source.handle_htlc_handling_failed(failure_type).await;
				}
			},
			LdkEvent::SpendableOutputs { outputs, channel_id } => {
				match self
					.output_sweeper
					.track_spendable_outputs(outputs, channel_id, true, None)
					.await
				{
					Ok(_) => return Ok(()),
					Err(_) => {
						log_error!(self.logger, "Failed to track spendable outputs");
						return Err(ReplayEvent());
					},
				};
			},
			LdkEvent::OpenChannelRequest {
				temporary_channel_id,
				counterparty_node_id,
				funding_satoshis,
				channel_type,
				channel_negotiation_type: _,
				is_announced,
				params: _,
			} => {
				if is_announced {
					if let Err(err) = may_announce_channel(&*self.config) {
						log_error!(self.logger, "Rejecting inbound announced channel from peer {} due to missing configuration: {}", counterparty_node_id, err);

						self.channel_manager
							.force_close_broadcasting_latest_txn(
								&temporary_channel_id,
								&counterparty_node_id,
								"Channel request rejected".to_string(),
							)
							.unwrap_or_else(|e| {
								log_error!(self.logger, "Failed to reject channel: {:?}", e);
							});
						return Ok(());
					}
				}

				let anchor_channel = channel_type.requires_anchors_zero_fee_htlc_tx();
				if anchor_channel {
					if let Some(anchor_channels_config) =
						self.config.anchor_channels_config.as_ref()
					{
						let cur_anchor_reserve_sats = crate::total_anchor_channels_reserve_sats(
							&self.channel_manager,
							&self.config,
						);
						let spendable_amount_sats = self
							.wallet
							.get_spendable_amount_sats(cur_anchor_reserve_sats)
							.unwrap_or(0);

						let required_amount_sats = if anchor_channels_config
							.trusted_peers_no_reserve
							.contains(&counterparty_node_id)
						{
							0
						} else {
							anchor_channels_config.per_channel_reserve_sats
						};

						if spendable_amount_sats < required_amount_sats {
							log_error!(
								self.logger,
								"Rejecting inbound Anchor channel from peer {} due to insufficient available on-chain reserves. Available: {}/{}sats",
								counterparty_node_id,
								spendable_amount_sats,
								required_amount_sats,
							);
							self.channel_manager
								.force_close_broadcasting_latest_txn(
									&temporary_channel_id,
									&counterparty_node_id,
									"Channel request rejected".to_string(),
								)
								.unwrap_or_else(|e| {
									log_error!(self.logger, "Failed to reject channel: {:?}", e);
								});
							return Ok(());
						}
					} else {
						log_error!(
							self.logger,
							"Rejecting inbound channel from peer {} due to Anchor channels being disabled.",
							counterparty_node_id,
						);
						self.channel_manager
							.force_close_broadcasting_latest_txn(
								&temporary_channel_id,
								&counterparty_node_id,
								"Channel request rejected".to_string(),
							)
							.unwrap_or_else(|e| {
								log_error!(self.logger, "Failed to reject channel: {:?}", e);
							});
						return Ok(());
					}
				}

				/*// fix for LND nodes which support both 0-conf and non-0conf
				// remove when https://github.com/lightningnetwork/lnd/pull/8796 is in LND
				let mut lnd_0conf_non0conf_fix: Vec<PublicKey> = Vec::new();
				// Olympus
				lnd_0conf_non0conf_fix.push(
					PublicKey::from_str(
						"031b301307574bbe9b9ac7b79cbe1700e31e544513eae0b5d7497483083f99e581",
					)
					.unwrap(),
				);
				// Olympus (mutinynet)
				lnd_0conf_non0conf_fix.push(
					PublicKey::from_str(
						"032ae843e4d7d177f151d021ac8044b0636ec72b1ce3ffcde5c04748db2517ab03",
					)
					.unwrap(),
				);
				// Megalith
				lnd_0conf_non0conf_fix.push(
					PublicKey::from_str(
						"038a9e56512ec98da2b5789761f7af8f280baf98a09282360cd6ff1381b5e889bf",
					)
					.unwrap(),
				);
				// Megalith (mutinynet)
				lnd_0conf_non0conf_fix.push(
					PublicKey::from_str(
						"03e30fda71887a916ef5548a4d02b06fe04aaa1a8de9e24134ce7f139cf79d7579",
					)
					.unwrap(),
				);

				log_info!(
					self.logger,
					"new channel with peer {} requires 0 conf: {}",
					counterparty_node_id,
					channel_type.requires_zero_conf()
				);

				let user_channel_id: u128 = rand::thread_rng().gen::<u128>();
				let allow_0conf = (channel_type.requires_zero_conf()
					|| !lnd_0conf_non0conf_fix.contains(&counterparty_node_id))
					&& self.config.trusted_peers_0conf.contains(&counterparty_node_id);*/
				let user_channel_id: u128 = rng().random();
				let allow_0conf = self.config.trusted_peers_0conf.contains(&counterparty_node_id);
				let mut channel_override_config = None;
				if let Some((lsp_node_id, _)) = self
					.liquidity_source
					.as_ref()
					.and_then(|ls| ls.as_ref().get_lsps2_lsp_details())
				{
					if lsp_node_id == counterparty_node_id {
						// When we're an LSPS2 client, allow claiming underpaying HTLCs as the LSP will skim off some fee. We'll
						// check that they don't take too much before claiming.
						//
						// We also set maximum allowed inbound HTLC value in flight
						// to 100%. We should eventually be able to set this on a per-channel basis, but for
						// now we just bump the default for all channels.
						channel_override_config = Some(ChannelConfigOverrides {
							handshake_overrides: Some(ChannelHandshakeConfigUpdate {
								max_inbound_htlc_value_in_flight_percent_of_channel: Some(100),
								..Default::default()
							}),
							update_overrides: Some(ChannelConfigUpdate {
								accept_underpaying_htlcs: Some(true),
								..Default::default()
							}),
						});
					}
				}
				let res = if allow_0conf {
					self.channel_manager.accept_inbound_channel_from_trusted_peer_0conf(
						&temporary_channel_id,
						&counterparty_node_id,
						user_channel_id,
						channel_override_config,
					)
				} else {
					self.channel_manager.accept_inbound_channel(
						&temporary_channel_id,
						&counterparty_node_id,
						user_channel_id,
						channel_override_config,
					)
				};

				match res {
					Ok(()) => {
						log_info!(
							self.logger,
							"Accepting inbound{}{} channel of {}sats from{} peer {}",
							if allow_0conf { " 0conf" } else { "" },
							if anchor_channel { " Anchor" } else { "" },
							funding_satoshis,
							if allow_0conf { " trusted" } else { "" },
							counterparty_node_id,
						);
					},
					Err(e) => {
						log_error!(
							self.logger,
							"Error while accepting inbound{}{} channel from{} peer {}: {:?}",
							if allow_0conf { " 0conf" } else { "" },
							if anchor_channel { " Anchor" } else { "" },
							counterparty_node_id,
							if allow_0conf { " trusted" } else { "" },
							e,
						);
					},
				}
			},
			LdkEvent::PaymentForwarded {
				prev_channel_id,
				next_channel_id,
				prev_user_channel_id,
				next_user_channel_id,
				prev_node_id,
				next_node_id,
				total_fee_earned_msat,
				skimmed_fee_msat,
				claim_from_onchain_tx,
				outbound_amount_forwarded_msat,
			} => {
				{
					let read_only_network_graph = self.network_graph.read_only();
					let nodes = read_only_network_graph.nodes();
					let channels = self.channel_manager.list_channels();

					let node_str = |channel_id: &Option<ChannelId>| {
						channel_id
							.and_then(|channel_id| {
								channels.iter().find(|c| c.channel_id == channel_id)
							})
							.and_then(|channel| {
								nodes.get(&NodeId::from_pubkey(&channel.counterparty.node_id))
							})
							.map_or("private_node".to_string(), |node| {
								node.announcement_info
									.as_ref()
									.map_or("unnamed node".to_string(), |ann| {
										format!("node {}", ann.alias())
									})
							})
					};
					let channel_str = |channel_id: &Option<ChannelId>| {
						channel_id
							.map(|channel_id| format!(" with channel {}", channel_id))
							.unwrap_or_default()
					};
					let from_prev_str = format!(
						" from {}{}",
						node_str(&prev_channel_id),
						channel_str(&prev_channel_id)
					);
					let to_next_str = format!(
						" to {}{}",
						node_str(&next_channel_id),
						channel_str(&next_channel_id)
					);

					let fee_earned = total_fee_earned_msat.unwrap_or(0);
					if claim_from_onchain_tx {
						log_info!(
						self.logger,
						"Forwarded payment{}{} of {}msat, earning {}msat in fees from claiming onchain.",
						from_prev_str,
						to_next_str,
						outbound_amount_forwarded_msat.unwrap_or(0),
						fee_earned,
					);
					} else {
						log_info!(
							self.logger,
							"Forwarded payment{}{} of {}msat, earning {}msat in fees.",
							from_prev_str,
							to_next_str,
							outbound_amount_forwarded_msat.unwrap_or(0),
							fee_earned,
						);
					}
				}

				if let Some(liquidity_source) = self.liquidity_source.as_ref() {
					let skimmed_fee_msat = skimmed_fee_msat.unwrap_or(0);
					liquidity_source
						.handle_payment_forwarded(next_channel_id, skimmed_fee_msat)
						.await;
				}

				let event = Event::PaymentForwarded {
					prev_channel_id: prev_channel_id.expect("prev_channel_id expected for events generated by LDK versions greater than 0.0.107."),
					next_channel_id: next_channel_id.expect("next_channel_id expected for events generated by LDK versions greater than 0.0.107."),
					prev_user_channel_id: prev_user_channel_id.map(UserChannelId),
					next_user_channel_id: next_user_channel_id.map(UserChannelId),
					prev_node_id,
					next_node_id,
					total_fee_earned_msat,
					skimmed_fee_msat,
					claim_from_onchain_tx,
					outbound_amount_forwarded_msat,
				};
				self.event_queue.add_event(event).await.map_err(|e| {
					log_error!(self.logger, "Failed to push to event queue: {}", e);
					ReplayEvent()
				})?;
			},
			LdkEvent::ChannelPending {
				channel_id,
				user_channel_id,
				former_temporary_channel_id,
				counterparty_node_id,
				funding_txo,
				..
			} => {
				log_info!(
					self.logger,
					"New channel {} with counterparty {} has been created and is pending confirmation on chain.",
					channel_id,
					counterparty_node_id,
				);

				let event = Event::ChannelPending {
					channel_id,
					user_channel_id: UserChannelId(user_channel_id),
					former_temporary_channel_id: former_temporary_channel_id.unwrap(),
					counterparty_node_id,
					funding_txo,
				};
				match self.event_queue.add_event(event).await {
					Ok(_) => {},
					Err(e) => {
						log_error!(self.logger, "Failed to push to event queue: {}", e);
						return Err(ReplayEvent());
					},
				};

				let network_graph = self.network_graph.read_only();
				let channels =
					self.channel_manager.list_channels_with_counterparty(&counterparty_node_id);
				if let Some(pending_channel) =
					channels.into_iter().find(|c| c.channel_id == channel_id)
				{
					if !pending_channel.is_outbound
						&& self.peer_store.get_peer(&counterparty_node_id).is_none()
					{
						if let Some(address) = network_graph
							.nodes()
							.get(&NodeId::from_pubkey(&counterparty_node_id))
							.and_then(|node_info| node_info.announcement_info.as_ref())
							.and_then(|ann_info| ann_info.addresses().first())
						{
							let peer = PeerInfo {
								node_id: counterparty_node_id,
								address: address.clone(),
							};

							self.peer_store.add_peer(peer).unwrap_or_else(|e| {
								log_error!(
									self.logger,
									"Failed to add peer {} to peer store: {}",
									counterparty_node_id,
									e
								);
							});
						}
					}
				}
			},
			LdkEvent::ChannelReady {
				channel_id,
				user_channel_id,
				counterparty_node_id,
				funding_txo,
				..
			} => {
				if let Some(funding_txo) = funding_txo {
					log_info!(
						self.logger,
						"Channel {} with counterparty {} ready to be used with funding_txo {}",
						channel_id,
						counterparty_node_id,
						funding_txo,
					);
				} else {
					log_info!(
						self.logger,
						"Channel {} with counterparty {} ready to be used",
						channel_id,
						counterparty_node_id,
					);
				}

				if let Some(liquidity_source) = self.liquidity_source.as_ref() {
					liquidity_source
						.handle_channel_ready(user_channel_id, &channel_id, &counterparty_node_id)
						.await;
				}

				let event = Event::ChannelReady {
					channel_id,
					user_channel_id: UserChannelId(user_channel_id),
					counterparty_node_id: Some(counterparty_node_id),
					funding_txo,
				};
				match self.event_queue.add_event(event).await {
					Ok(_) => {},
					Err(e) => {
						log_error!(self.logger, "Failed to push to event queue: {}", e);
						return Err(ReplayEvent());
					},
				};
			},
			LdkEvent::ChannelClosed {
				channel_id,
				reason,
				user_channel_id,
				counterparty_node_id,
				..
			} => {
				log_info!(
					self.logger,
					"Channel {} peer {:?} closed due to: {}",
					channel_id,
					counterparty_node_id,
					reason
				);

				let event = Event::ChannelClosed {
					channel_id,
					user_channel_id: UserChannelId(user_channel_id),
					counterparty_node_id,
					reason: Some(reason),
				};

				match self.event_queue.add_event(event).await {
					Ok(_) => {},
					Err(e) => {
						log_error!(self.logger, "Failed to push to event queue: {}", e);
						return Err(ReplayEvent());
					},
				};
			},
			LdkEvent::DiscardFunding { .. } => {},
			LdkEvent::HTLCIntercepted {
				requested_next_hop_scid,
				intercept_id,
				expected_outbound_amount_msat,
				payment_hash,
				..
			} => {
				if let Some(liquidity_source) = self.liquidity_source.as_ref() {
					liquidity_source
						.handle_htlc_intercepted(
							requested_next_hop_scid,
							intercept_id,
							expected_outbound_amount_msat,
							payment_hash,
						)
						.await;
				}
			},
			LdkEvent::InvoiceReceived { .. } => {
				debug_assert!(false, "We currently don't handle BOLT12 invoices manually, so this event should never be emitted.");
			},
			LdkEvent::ConnectionNeeded { node_id, addresses } => {
				let spawn_logger = self.logger.clone();
				let spawn_cm = Arc::clone(&self.connection_manager);
				let future = async move {
					for addr in &addresses {
						match spawn_cm.connect_peer_if_necessary(node_id, addr.clone()).await {
							Ok(()) => {
								return;
							},
							Err(e) => {
								log_error!(
									spawn_logger,
									"Failed to establish connection to peer {}@{}: {}",
									node_id,
									addr,
									e
								);
							},
						}
					}
				};
				self.runtime.spawn_cancellable_background_task(future);
			},
			LdkEvent::BumpTransaction(bte) => {
				match bte {
					BumpTransactionEvent::ChannelClose {
						ref channel_id,
						ref counterparty_node_id,
						..
					} => {
						// Skip bumping channel closes if our counterparty is trusted.
						if let Some(anchor_channels_config) =
							self.config.anchor_channels_config.as_ref()
						{
							if anchor_channels_config
								.trusted_peers_no_reserve
								.contains(counterparty_node_id)
							{
								log_debug!(self.logger,
									"Ignoring BumpTransactionEvent::ChannelClose for channel {} due to trusted counterparty {}",
									channel_id, counterparty_node_id
								);
								return Ok(());
							}
						}
					},
					BumpTransactionEvent::HTLCResolution { .. } => {},
				}

				self.bump_tx_event_handler.handle_event(&bte).await;
			},
			LdkEvent::OnionMessageIntercepted { peer_node_id, message } => {
				if let Some(om_mailbox) = self.om_mailbox.as_ref() {
					om_mailbox.onion_message_intercepted(peer_node_id, message);
				} else {
					log_trace!(
						self.logger,
						"Onion message intercepted, but no onion message mailbox available"
					);
				}
			},
			LdkEvent::OnionMessagePeerConnected { peer_node_id } => {
				if let Some(om_mailbox) = self.om_mailbox.as_ref() {
					let messages = om_mailbox.onion_message_peer_connected(peer_node_id);

					for message in messages {
						if let Err(e) =
							self.onion_messenger.forward_onion_message(message, &peer_node_id)
						{
							log_trace!(
								self.logger,
								"Failed to forward onion message to peer {}: {:?}",
								peer_node_id,
								e
							);
						}
					}
				}
			},

			LdkEvent::PersistStaticInvoice {
				invoice,
				invoice_request_path,
				invoice_slot,
				recipient_id,
				invoice_persisted_path,
			} => {
				if let Some(store) = self.static_invoice_store.as_ref() {
					match store
						.handle_persist_static_invoice(
							invoice,
							invoice_request_path,
							invoice_slot,
							recipient_id,
						)
						.await
					{
						Ok(_) => {
							self.channel_manager.static_invoice_persisted(invoice_persisted_path);
						},
						Err(e) => {
							log_error!(self.logger, "Failed to persist static invoice: {}", e);
							return Err(ReplayEvent());
						},
					};
				}
			},
			LdkEvent::StaticInvoiceRequested {
				recipient_id,
				invoice_slot,
				reply_path,
				invoice_request,
			} => {
				if let Some(store) = self.static_invoice_store.as_ref() {
					let invoice =
						store.handle_static_invoice_requested(&recipient_id, invoice_slot).await;

					match invoice {
						Ok(Some((invoice, invoice_request_path))) => {
							if let Err(e) = self.channel_manager.respond_to_static_invoice_request(
								invoice,
								reply_path,
								invoice_request,
								invoice_request_path,
							) {
								log_error!(self.logger, "Failed to send static invoice: {:?}", e);
							}
						},
						Ok(None) => {
							log_trace!(
								self.logger,
								"No static invoice found for recipient {} and slot {}",
								hex_utils::to_string(&recipient_id),
								invoice_slot
							);
						},
						Err(e) => {
							log_error!(self.logger, "Failed to retrieve static invoice: {}", e);
							return Err(ReplayEvent());
						},
					}
				}
			},
			// TODO(splicing): Revisit error handling once splicing API is settled in LDK 0.3
			LdkEvent::FundingTransactionReadyForSigning {
				channel_id,
				counterparty_node_id,
				unsigned_transaction,
				..
			} => match self.wallet.sign_owned_inputs(unsigned_transaction) {
				Ok(partially_signed_tx) => {
					match self.channel_manager.funding_transaction_signed(
						&channel_id,
						&counterparty_node_id,
						partially_signed_tx,
					) {
						Ok(()) => {
							log_info!(
								self.logger,
								"Signed funding transaction for channel {} with counterparty {}",
								channel_id,
								counterparty_node_id
							);
						},
						Err(e) => {
							// TODO(splicing): Abort splice once supported in LDK 0.3
							debug_assert!(false, "Failed signing funding transaction: {:?}", e);
							log_error!(self.logger, "Failed signing funding transaction: {:?}", e);
						},
					}
				},
				Err(()) => {
					log_error!(self.logger, "Failed signing funding transaction");
				},
			},
			LdkEvent::SplicePending {
				channel_id,
				user_channel_id,
				counterparty_node_id,
				new_funding_txo,
				..
			} => {
				log_info!(
					self.logger,
					"Channel {} with counterparty {} pending splice with funding_txo {}",
					channel_id,
					counterparty_node_id,
					new_funding_txo,
				);

				let event = Event::SplicePending {
					channel_id,
					user_channel_id: UserChannelId(user_channel_id),
					counterparty_node_id,
					new_funding_txo,
				};

				match self.event_queue.add_event(event).await {
					Ok(_) => {},
					Err(e) => {
						log_error!(self.logger, "Failed to push to event queue: {}", e);
						return Err(ReplayEvent());
					},
				};
			},
			LdkEvent::SpliceFailed {
				channel_id,
				user_channel_id,
				counterparty_node_id,
				abandoned_funding_txo,
				contributed_outputs,
				..
			} => {
				if let Some(funding_txo) = abandoned_funding_txo {
					log_info!(
						self.logger,
						"Channel {} with counterparty {} failed splice with funding_txo {}",
						channel_id,
						counterparty_node_id,
						funding_txo,
					);
				} else {
					log_info!(
						self.logger,
						"Channel {} with counterparty {} failed splice",
						channel_id,
						counterparty_node_id,
					);
				}

				let tx = bitcoin::Transaction {
					version: bitcoin::transaction::Version::TWO,
					lock_time: bitcoin::absolute::LockTime::ZERO,
					input: vec![],
					output: contributed_outputs,
				};
				if let Err(e) = self.wallet.cancel_tx(&tx) {
					log_error!(self.logger, "Failed reclaiming unused addresses: {}", e);
					return Err(ReplayEvent());
				}

				let event = Event::SpliceFailed {
					channel_id,
					user_channel_id: UserChannelId(user_channel_id),
					counterparty_node_id,
					abandoned_funding_txo,
				};

				match self.event_queue.add_event(event).await {
					Ok(_) => {},
					Err(e) => {
						log_error!(self.logger, "Failed to push to event queue: {}", e);
						return Err(ReplayEvent());
					},
				};
			},
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use std::sync::atomic::{AtomicU16, Ordering};
	use std::time::Duration;

	use bitcoin::hashes::Hash as _;
	use lightning::ln::channelmanager::{
		Bolt11InvoiceParameters, RecentPaymentDetails, RecipientOnionFields,
	};
	use lightning::ln::functional_test_utils::{
		_reload_node, claim_payment_along_route, create_announced_chan_between_nodes,
		create_announced_chan_between_nodes_with_value, create_chanmon_cfgs, create_network,
		create_node_cfgs, create_node_chanmgrs, do_claim_payment_along_route,
		fail_payment_along_route, pass_along_path, reconnect_nodes, remove_first_msg_event_to_node,
		test_default_channel_config, ClaimAlongRouteArgs, ReconnectArgs, SendEvent,
		TEST_FINAL_CLTV,
	};
	use lightning::ln::msgs::{BaseMessageHandler, ChannelMessageHandler, MessageSendEvent};
	use lightning::reload_node;
	use lightning::util::test_utils::TestLogger;

	use super::*;
	use crate::io::test_utils::InMemoryStore;
	use crate::io::{
		PAYMENT_INFO_PERSISTENCE_PRIMARY_NAMESPACE, PAYMENT_INFO_PERSISTENCE_SECONDARY_NAMESPACE,
	};

	#[derive(Default)]
	struct TestChannelConstrainedClaimActions {
		claimed: Mutex<Vec<PaymentPreimage>>,
		failed: Mutex<Vec<PaymentHash>>,
	}

	impl ChannelConstrainedClaimActions for TestChannelConstrainedClaimActions {
		fn claim(&self, preimage: PaymentPreimage) {
			self.claimed.lock().unwrap().push(preimage);
		}

		fn fail(&self, payment_hash: &PaymentHash) {
			self.failed.lock().unwrap().push(*payment_hash);
		}
	}

	#[tokio::test]
	async fn event_queue_persistence() {
		let store: Arc<DynStore> = Arc::new(InMemoryStore::new());
		let logger = Arc::new(TestLogger::new());
		let event_queue = Arc::new(EventQueue::new(Arc::clone(&store), Arc::clone(&logger)));
		assert_eq!(event_queue.next_event(), None);

		let expected_event = Event::ChannelReady {
			channel_id: ChannelId([23u8; 32]),
			user_channel_id: UserChannelId(2323),
			counterparty_node_id: None,
			funding_txo: None,
		};
		event_queue.add_event(expected_event.clone()).await.unwrap();

		// Check we get the expected event and that it is returned until we mark it handled.
		for _ in 0..5 {
			assert_eq!(event_queue.next_event_async().await, expected_event);
			assert_eq!(event_queue.next_event(), Some(expected_event.clone()));
		}

		// Check we can read back what we persisted.
		let persisted_bytes = KVStore::read(
			&*store,
			EVENT_QUEUE_PERSISTENCE_PRIMARY_NAMESPACE,
			EVENT_QUEUE_PERSISTENCE_SECONDARY_NAMESPACE,
			EVENT_QUEUE_PERSISTENCE_KEY,
		)
		.await
		.unwrap();
		let deser_event_queue =
			EventQueue::read(&mut &persisted_bytes[..], (Arc::clone(&store), logger)).unwrap();
		assert_eq!(deser_event_queue.next_event_async().await, expected_event);

		event_queue.event_handled().await.unwrap();
		assert_eq!(event_queue.next_event(), None);
	}

	#[tokio::test]
	async fn payment_claimable_receiving_channels_persist() {
		let store: Arc<DynStore> = Arc::new(InMemoryStore::new());
		let logger = Arc::new(TestLogger::new());
		let event_queue = Arc::new(EventQueue::new(Arc::clone(&store), Arc::clone(&logger)));
		let expected_event = Event::PaymentClaimable {
			payment_id: PaymentId([1u8; 32]),
			payment_hash: PaymentHash([2u8; 32]),
			claimable_amount_msat: 500_000,
			claim_deadline: Some(840_000),
			custom_records: Vec::new(),
			receiving_channels: vec![ReceivingChannel {
				channel_id: ChannelId([3u8; 32]),
				user_channel_id: Some(UserChannelId(4)),
			}],
		};

		event_queue.add_event(expected_event.clone()).await.unwrap();
		let persisted_bytes = KVStore::read(
			&*store,
			EVENT_QUEUE_PERSISTENCE_PRIMARY_NAMESPACE,
			EVENT_QUEUE_PERSISTENCE_SECONDARY_NAMESPACE,
			EVENT_QUEUE_PERSISTENCE_KEY,
		)
		.await
		.unwrap();
		let deser_event_queue =
			EventQueue::read(&mut &persisted_bytes[..], (Arc::clone(&store), logger)).unwrap();
		assert_eq!(deser_event_queue.next_event(), Some(expected_event));
	}

	#[test]
	fn channel_constrained_claim_requires_amount_preimage_and_every_exact_mpp_part() {
		let preimage = PaymentPreimage([3u8; 32]);
		let constrained = PaymentKind::Bolt11 {
			hash: PaymentHash([2u8; 32]),
			preimage: Some(preimage),
			secret: None,
			bolt11_invoice: None,
			required_receiving_channel_id: Some(UserChannelId(42)),
			required_sending_channel_id: Some(UserChannelId(41)),
			circular_operation_id: Some(PaymentId([4u8; 32])),
			circular_outbound_payment_id: Some(PaymentId([5u8; 32])),
			circular_max_routing_fee_msat: Some(1_000_000),
		};
		let exact_parts = vec![(ChannelId([1u8; 32]), Some(42)), (ChannelId([2u8; 32]), Some(42))];
		assert_eq!(
			channel_constrained_claim_decision(
				&constrained,
				PaymentStatus::Pending,
				Some(20_000_000),
				20_000_000,
				&exact_parts
			),
			ChannelConstrainedClaimDecision::Claim(preimage)
		);

		let mixed_parts = vec![(ChannelId([1u8; 32]), Some(42)), (ChannelId([2u8; 32]), Some(43))];
		let unidentified_part = vec![(ChannelId([1u8; 32]), None)];
		assert_eq!(
			channel_constrained_claim_decision(
				&constrained,
				PaymentStatus::Pending,
				Some(20_000_000),
				20_000_000,
				&mixed_parts,
			),
			ChannelConstrainedClaimDecision::Fail(
				CircularPaymentFailureReason::ReceivingChannelMismatch,
			)
		);
		for unidentified_parts in [&unidentified_part[..], &[]] {
			assert_eq!(
				channel_constrained_claim_decision(
					&constrained,
					PaymentStatus::Pending,
					Some(20_000_000),
					20_000_000,
					unidentified_parts,
				),
				ChannelConstrainedClaimDecision::Fail(
					CircularPaymentFailureReason::MissingReceivingChannelIdentity,
				)
			);
		}
		assert_eq!(
			channel_constrained_claim_decision(
				&constrained,
				PaymentStatus::Pending,
				Some(20_000_000),
				19_999_999,
				&exact_parts
			),
			ChannelConstrainedClaimDecision::Fail(CircularPaymentFailureReason::AmountMismatch)
		);
		assert_eq!(
			channel_constrained_claim_decision(
				&constrained,
				PaymentStatus::Pending,
				Some(20_000_000),
				20_000_001,
				&exact_parts,
			),
			ChannelConstrainedClaimDecision::Fail(CircularPaymentFailureReason::AmountMismatch)
		);
		assert_eq!(
			channel_constrained_claim_decision(
				&constrained,
				PaymentStatus::Pending,
				None,
				20_000_000,
				&exact_parts,
			),
			ChannelConstrainedClaimDecision::Fail(CircularPaymentFailureReason::AmountMismatch)
		);
		assert_eq!(
			channel_constrained_claim_decision(
				&constrained,
				PaymentStatus::Failed,
				Some(20_000_000),
				20_000_000,
				&exact_parts,
			),
			ChannelConstrainedClaimDecision::Fail(CircularPaymentFailureReason::PaymentNotPending,)
		);

		let mut missing_preimage = constrained.clone();
		if let PaymentKind::Bolt11 { preimage, .. } = &mut missing_preimage {
			*preimage = None;
		}
		assert_eq!(
			channel_constrained_claim_decision(
				&missing_preimage,
				PaymentStatus::Pending,
				Some(20_000_000),
				20_000_000,
				&exact_parts,
			),
			ChannelConstrainedClaimDecision::Fail(CircularPaymentFailureReason::MissingPreimage)
		);

		let mut missing_operation = constrained.clone();
		if let PaymentKind::Bolt11 { circular_operation_id, .. } = &mut missing_operation {
			*circular_operation_id = None;
		}
		assert_eq!(
			channel_constrained_claim_decision(
				&missing_operation,
				PaymentStatus::Pending,
				Some(20_000_000),
				20_000_000,
				&exact_parts,
			),
			ChannelConstrainedClaimDecision::Fail(
				CircularPaymentFailureReason::CircularMetadataMismatch,
			)
		);

		let mut unconstrained = constrained;
		if let PaymentKind::Bolt11 { required_receiving_channel_id, .. } = &mut unconstrained {
			*required_receiving_channel_id = None;
		}
		assert_eq!(
			channel_constrained_claim_decision(
				&unconstrained,
				PaymentStatus::Pending,
				Some(20_000_000),
				20_000_000,
				&exact_parts,
			),
			ChannelConstrainedClaimDecision::NotConstrained
		);
	}

	#[test]
	fn channel_constrained_claim_dispatches_exactly_one_action() {
		let actions = TestChannelConstrainedClaimActions::default();
		let payment_hash = PaymentHash([2u8; 32]);
		let preimage = PaymentPreimage([3u8; 32]);

		assert_eq!(
			apply_channel_constrained_claim_decision(
				&actions,
				&payment_hash,
				ChannelConstrainedClaimDecision::Claim(preimage),
			),
			ChannelConstrainedClaimOutcome::Claimed
		);
		assert_eq!(*actions.claimed.lock().unwrap(), vec![preimage]);
		assert!(actions.failed.lock().unwrap().is_empty());

		assert_eq!(
			apply_channel_constrained_claim_decision(
				&actions,
				&payment_hash,
				ChannelConstrainedClaimDecision::Fail(
					CircularPaymentFailureReason::ReceivingChannelMismatch,
				),
			),
			ChannelConstrainedClaimOutcome::Failed
		);
		assert_eq!(*actions.claimed.lock().unwrap(), vec![preimage]);
		assert_eq!(*actions.failed.lock().unwrap(), vec![payment_hash]);

		assert_eq!(
			apply_channel_constrained_claim_decision(
				&actions,
				&payment_hash,
				ChannelConstrainedClaimDecision::NotConstrained,
			),
			ChannelConstrainedClaimOutcome::NotConstrained
		);
		assert_eq!(*actions.claimed.lock().unwrap(), vec![preimage]);
		assert_eq!(*actions.failed.lock().unwrap(), vec![payment_hash]);
	}

	#[test]
	fn rejected_constrained_claim_persists_failed_state_for_reload() {
		let kv_store: Arc<DynStore> = Arc::new(InMemoryStore::new());
		let logger = Arc::new(Logger::new_log_facade());
		let payment_store = PaymentStore::new(
			Vec::new(),
			PAYMENT_INFO_PERSISTENCE_PRIMARY_NAMESPACE.to_string(),
			PAYMENT_INFO_PERSISTENCE_SECONDARY_NAMESPACE.to_string(),
			Arc::clone(&kv_store),
			Arc::clone(&logger),
		);
		let payment_hash = PaymentHash([2u8; 32]);
		let payment_id = PaymentId(payment_hash.0);
		let payment = PaymentDetails::new(
			payment_id,
			test_circular_payment_kind(payment_hash, PaymentPreimage([3u8; 32]), UserChannelId(42)),
			Some(20_000_000),
			None,
			PaymentDirection::Inbound,
			PaymentStatus::Pending,
		);
		payment_store.insert(payment).unwrap();

		let actions = TestChannelConstrainedClaimActions::default();
		assert_eq!(
			handle_channel_constrained_claim(
				&actions,
				&payment_store,
				payment_id,
				&payment_hash,
				ChannelConstrainedClaimDecision::Fail(
					CircularPaymentFailureReason::ReceivingChannelMismatch,
				),
				&[(ChannelId([4u8; 32]), Some(41))],
			)
			.unwrap(),
			ChannelConstrainedClaimOutcome::Failed
		);
		assert_eq!(*actions.failed.lock().unwrap(), vec![payment_hash]);

		let reloaded = crate::io::utils::read_payments(kv_store, logger).unwrap();
		assert_eq!(reloaded.len(), 1);
		assert_eq!(reloaded[0].id, payment_id);
		assert_eq!(reloaded[0].status, PaymentStatus::Failed);
		assert_eq!(
			reloaded[0].circular_failure_reason,
			Some(CircularPaymentFailureReason::ReceivingChannelMismatch)
		);
		assert_eq!(reloaded[0].circular_observed_receiving_channel_ids, vec![UserChannelId(41)]);
	}

	#[test]
	fn circular_terminal_updates_are_distinct_and_idempotent_after_reload() {
		let kv_store: Arc<DynStore> = Arc::new(InMemoryStore::new());
		let logger = Arc::new(Logger::new_log_facade());
		let payment_store = PaymentStore::new(
			Vec::new(),
			PAYMENT_INFO_PERSISTENCE_PRIMARY_NAMESPACE.to_string(),
			PAYMENT_INFO_PERSISTENCE_SECONDARY_NAMESPACE.to_string(),
			Arc::clone(&kv_store),
			Arc::clone(&logger),
		);
		let payment_hash = PaymentHash([2u8; 32]);
		let inbound_payment_id = PaymentId(payment_hash.0);
		let payment_preimage = PaymentPreimage([3u8; 32]);
		let payment_secret = lightning_types::payment::PaymentSecret([4u8; 32]);
		let operation_id = PaymentId([5u8; 32]);
		let outbound_payment_id = crate::payment::derive_circular_outbound_payment_id(operation_id);
		let first_hop_user_channel_id = UserChannelId(41);
		let last_hop_user_channel_id = UserChannelId(42);
		let amount_msat = 20_000_000;
		let fee_paid_msat = 17_062;

		payment_store
			.insert(crate::payment::prepared_circular_payment_details(
				"test-invoice".to_string(),
				payment_hash,
				payment_preimage,
				payment_secret,
				amount_msat,
				crate::payment::CircularPaymentContext {
					operation_id,
					outbound_payment_id,
					first_hop_user_channel_id,
					last_hop_user_channel_id,
					max_routing_fee_msat: 50_000,
				},
			))
			.unwrap();
		payment_store
			.insert(PaymentDetails::new(
				outbound_payment_id,
				PaymentKind::Bolt11 {
					hash: payment_hash,
					preimage: None,
					secret: Some(payment_secret),
					bolt11_invoice: Some("test-invoice".to_string()),
					required_receiving_channel_id: Some(last_hop_user_channel_id),
					required_sending_channel_id: Some(first_hop_user_channel_id),
					circular_operation_id: Some(operation_id),
					circular_outbound_payment_id: Some(outbound_payment_id),
					circular_max_routing_fee_msat: Some(50_000),
				},
				Some(amount_msat),
				None,
				PaymentDirection::Outbound,
				PaymentStatus::Pending,
			))
			.unwrap();

		let claimed_update = payment_claimed_store_update(
			inbound_payment_id,
			PaymentPurpose::Bolt11InvoicePayment {
				payment_preimage: Some(payment_preimage),
				payment_secret,
			},
			amount_msat,
		);
		let sent_update = payment_sent_store_update(
			outbound_payment_id,
			payment_hash,
			payment_preimage,
			Some(fee_paid_msat),
		);
		assert_eq!(payment_store.update(&claimed_update).unwrap(), DataStoreUpdateResult::Updated);
		assert_eq!(payment_store.update(&sent_update).unwrap(), DataStoreUpdateResult::Updated);

		let reloaded_payments =
			crate::io::utils::read_payments(Arc::clone(&kv_store), Arc::clone(&logger)).unwrap();
		assert_eq!(reloaded_payments.len(), 2);
		let reloaded_store = PaymentStore::new(
			reloaded_payments,
			PAYMENT_INFO_PERSISTENCE_PRIMARY_NAMESPACE.to_string(),
			PAYMENT_INFO_PERSISTENCE_SECONDARY_NAMESPACE.to_string(),
			kv_store,
			logger,
		);
		assert_eq!(
			reloaded_store.update(&claimed_update).unwrap(),
			DataStoreUpdateResult::Unchanged
		);
		assert_eq!(reloaded_store.update(&sent_update).unwrap(), DataStoreUpdateResult::Unchanged);

		let inbound = reloaded_store.get(&inbound_payment_id).unwrap();
		let outbound = reloaded_store.get(&outbound_payment_id).unwrap();
		assert_ne!(inbound.id, outbound.id);
		assert_eq!(inbound.direction, PaymentDirection::Inbound);
		assert_eq!(outbound.direction, PaymentDirection::Outbound);
		assert_eq!(inbound.status, PaymentStatus::Succeeded);
		assert_eq!(outbound.status, PaymentStatus::Succeeded);
		assert_eq!(inbound.amount_msat, Some(amount_msat));
		assert_eq!(outbound.amount_msat, Some(amount_msat));
		assert_eq!(inbound.fee_paid_msat, None);
		assert_eq!(outbound.fee_paid_msat, Some(fee_paid_msat));
		match (&inbound.kind, &outbound.kind) {
			(
				PaymentKind::Bolt11 { preimage: inbound_preimage, .. },
				PaymentKind::Bolt11 { preimage: outbound_preimage, .. },
			) => {
				assert_eq!(*inbound_preimage, Some(payment_preimage));
				assert_eq!(*outbound_preimage, Some(payment_preimage));
			},
			other => panic!("expected two BOLT 11 payment records, got {other:?}"),
		}
	}

	#[test]
	fn circular_failure_marks_both_exact_records_and_replays_idempotently() {
		let kv_store: Arc<DynStore> = Arc::new(InMemoryStore::new());
		let logger = Arc::new(Logger::new_log_facade());
		let payment_store = PaymentStore::new(
			Vec::new(),
			PAYMENT_INFO_PERSISTENCE_PRIMARY_NAMESPACE.to_string(),
			PAYMENT_INFO_PERSISTENCE_SECONDARY_NAMESPACE.to_string(),
			Arc::clone(&kv_store),
			Arc::clone(&logger),
		);
		let payment_preimage = PaymentPreimage([13u8; 32]);
		let payment_hash =
			PaymentHash(bitcoin::hashes::sha256::Hash::hash(&payment_preimage.0).to_byte_array());
		let inbound_payment_id = PaymentId(payment_hash.0);
		let payment_secret = lightning_types::payment::PaymentSecret([14u8; 32]);
		let operation_id = PaymentId([15u8; 32]);
		let outbound_payment_id = crate::payment::derive_circular_outbound_payment_id(operation_id);
		let first_hop_user_channel_id = UserChannelId(51);
		let last_hop_user_channel_id = UserChannelId(52);
		let amount_msat = 20_000_000;
		let max_routing_fee_msat = 50_000;

		payment_store
			.insert(crate::payment::prepared_circular_payment_details(
				"failure-test-invoice".to_string(),
				payment_hash,
				payment_preimage,
				payment_secret,
				amount_msat,
				crate::payment::CircularPaymentContext {
					operation_id,
					outbound_payment_id,
					first_hop_user_channel_id,
					last_hop_user_channel_id,
					max_routing_fee_msat,
				},
			))
			.unwrap();
		payment_store
			.insert(PaymentDetails::new(
				outbound_payment_id,
				PaymentKind::Bolt11 {
					hash: payment_hash,
					preimage: None,
					secret: Some(payment_secret),
					bolt11_invoice: Some("failure-test-invoice".to_string()),
					required_receiving_channel_id: Some(last_hop_user_channel_id),
					required_sending_channel_id: Some(first_hop_user_channel_id),
					circular_operation_id: Some(operation_id),
					circular_outbound_payment_id: Some(outbound_payment_id),
					circular_max_routing_fee_msat: Some(max_routing_fee_msat),
				},
				Some(amount_msat),
				None,
				PaymentDirection::Outbound,
				PaymentStatus::Pending,
			))
			.unwrap();

		assert_eq!(
			fail_circular_payment_records(&payment_store, outbound_payment_id, Some(payment_hash),),
			Ok(true)
		);
		assert_eq!(payment_store.get(&inbound_payment_id).unwrap().status, PaymentStatus::Failed);
		assert_eq!(payment_store.get(&outbound_payment_id).unwrap().status, PaymentStatus::Failed);

		let reloaded_payments =
			crate::io::utils::read_payments(Arc::clone(&kv_store), Arc::clone(&logger)).unwrap();
		let reloaded_store = PaymentStore::new(
			reloaded_payments,
			PAYMENT_INFO_PERSISTENCE_PRIMARY_NAMESPACE.to_string(),
			PAYMENT_INFO_PERSISTENCE_SECONDARY_NAMESPACE.to_string(),
			kv_store,
			logger,
		);
		assert_eq!(
			fail_circular_payment_records(&reloaded_store, outbound_payment_id, Some(payment_hash),),
			Ok(true)
		);
		assert_eq!(reloaded_store.get(&inbound_payment_id).unwrap().status, PaymentStatus::Failed);
		assert_eq!(reloaded_store.get(&outbound_payment_id).unwrap().status, PaymentStatus::Failed);
	}

	#[test]
	fn circular_failure_rejects_mismatched_inbound_binding_without_updates() {
		let kv_store: Arc<DynStore> = Arc::new(InMemoryStore::new());
		let logger = Arc::new(Logger::new_log_facade());
		let payment_store = PaymentStore::new(
			Vec::new(),
			PAYMENT_INFO_PERSISTENCE_PRIMARY_NAMESPACE.to_string(),
			PAYMENT_INFO_PERSISTENCE_SECONDARY_NAMESPACE.to_string(),
			kv_store,
			logger,
		);
		let payment_preimage = PaymentPreimage([16u8; 32]);
		let payment_hash =
			PaymentHash(bitcoin::hashes::sha256::Hash::hash(&payment_preimage.0).to_byte_array());
		let inbound_payment_id = PaymentId(payment_hash.0);
		let payment_secret = lightning_types::payment::PaymentSecret([17u8; 32]);
		let operation_id = PaymentId([18u8; 32]);
		let outbound_payment_id = crate::payment::derive_circular_outbound_payment_id(operation_id);
		let first_hop_user_channel_id = UserChannelId(61);
		let inbound_last_hop_user_channel_id = UserChannelId(62);
		let outbound_last_hop_user_channel_id = UserChannelId(63);

		payment_store
			.insert(crate::payment::prepared_circular_payment_details(
				"mismatch-test-invoice".to_string(),
				payment_hash,
				payment_preimage,
				payment_secret,
				20_000_000,
				crate::payment::CircularPaymentContext {
					operation_id,
					outbound_payment_id,
					first_hop_user_channel_id,
					last_hop_user_channel_id: inbound_last_hop_user_channel_id,
					max_routing_fee_msat: 50_000,
				},
			))
			.unwrap();
		payment_store
			.insert(PaymentDetails::new(
				outbound_payment_id,
				PaymentKind::Bolt11 {
					hash: payment_hash,
					preimage: None,
					secret: Some(payment_secret),
					bolt11_invoice: Some("mismatch-test-invoice".to_string()),
					required_receiving_channel_id: Some(outbound_last_hop_user_channel_id),
					required_sending_channel_id: Some(first_hop_user_channel_id),
					circular_operation_id: Some(operation_id),
					circular_outbound_payment_id: Some(outbound_payment_id),
					circular_max_routing_fee_msat: Some(50_000),
				},
				Some(20_000_000),
				None,
				PaymentDirection::Outbound,
				PaymentStatus::Pending,
			))
			.unwrap();

		assert_eq!(
			fail_circular_payment_records(&payment_store, outbound_payment_id, Some(payment_hash),),
			Err(Error::InvalidPaymentId)
		);
		assert_eq!(payment_store.get(&inbound_payment_id).unwrap().status, PaymentStatus::Pending);
		assert_eq!(payment_store.get(&outbound_payment_id).unwrap().status, PaymentStatus::Pending);
	}

	#[test]
	fn pending_prepared_operation_and_channel_manager_state_survive_restart() {
		let chanmon_cfgs = create_chanmon_cfgs(3);
		let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
		let persister;
		let new_chain_monitor;
		let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
		let node_1_deserialized;
		let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
		let (_, _, first_channel_id, _) =
			create_announced_chan_between_nodes_with_value(&nodes, 1, 0, 100_000, 0);
		let (_, _, last_channel_id, _) =
			create_announced_chan_between_nodes_with_value(&nodes, 2, 1, 100_000, 0);
		let (_, _, middle_channel_id, _) =
			create_announced_chan_between_nodes_with_value(&nodes, 0, 2, 100_000, 0);

		let channels = nodes[1].node.list_channels();
		let first_channel =
			channels.iter().find(|channel| channel.channel_id == first_channel_id).unwrap();
		let last_channel =
			channels.iter().find(|channel| channel.channel_id == last_channel_id).unwrap();
		let first_hop_user_channel_id = UserChannelId(first_channel.user_channel_id);
		let last_hop_user_channel_id = UserChannelId(last_channel.user_channel_id);
		assert_ne!(first_hop_user_channel_id, last_hop_user_channel_id);

		let amount_msat = 5_000_000;
		let max_routing_fee_msat = 1_000_000;
		let invoice = nodes[1]
			.node
			.create_bolt11_invoice(Bolt11InvoiceParameters {
				amount_msats: Some(amount_msat),
				..Default::default()
			})
			.unwrap();
		let payment_hash = PaymentHash(invoice.payment_hash().to_byte_array());
		let payment_secret = *invoice.payment_secret();
		let payment_preimage =
			nodes[1].node.get_payment_preimage(payment_hash, payment_secret).unwrap();
		let payment_id = PaymentId(payment_hash.0);
		let operation_id = PaymentId([7u8; 32]);
		let outbound_payment_id = crate::payment::derive_circular_outbound_payment_id(operation_id);

		let kv_store: Arc<DynStore> = Arc::new(InMemoryStore::new());
		let logger = Arc::new(Logger::new_log_facade());
		let payment_store = PaymentStore::new(
			Vec::new(),
			PAYMENT_INFO_PERSISTENCE_PRIMARY_NAMESPACE.to_string(),
			PAYMENT_INFO_PERSISTENCE_SECONDARY_NAMESPACE.to_string(),
			Arc::clone(&kv_store),
			Arc::clone(&logger),
		);
		let payment = crate::payment::prepared_circular_payment_details(
			invoice.to_string(),
			payment_hash,
			payment_preimage,
			payment_secret,
			amount_msat,
			crate::payment::CircularPaymentContext {
				operation_id,
				outbound_payment_id,
				first_hop_user_channel_id,
				last_hop_user_channel_id,
				max_routing_fee_msat,
			},
		);
		payment_store.insert(payment.clone()).unwrap();
		assert!(nodes[1].node.list_recent_payments().is_empty());

		let middle_channel = nodes[0]
			.node
			.list_channels()
			.into_iter()
			.find(|channel| channel.channel_id == middle_channel_id)
			.unwrap();
		let first_hop_scid = first_channel.get_outbound_payment_scid().unwrap();
		let middle_hop_scid = middle_channel.get_outbound_payment_scid().unwrap();
		let last_hop_scid = last_channel.get_inbound_payment_scid().unwrap();
		let route = lightning::routing::router::Route {
			paths: vec![lightning::routing::router::Path {
				hops: vec![
					lightning::routing::router::RouteHop {
						pubkey: first_channel.counterparty.node_id,
						node_features: lightning::types::features::NodeFeatures::empty(),
						short_channel_id: first_hop_scid,
						channel_features: lightning::types::features::ChannelFeatures::empty(),
						fee_msat: 1_000,
						cltv_expiry_delta: 48,
						maybe_announced_channel: true,
					},
					lightning::routing::router::RouteHop {
						pubkey: last_channel.counterparty.node_id,
						node_features: lightning::types::features::NodeFeatures::empty(),
						short_channel_id: middle_hop_scid,
						channel_features: lightning::types::features::ChannelFeatures::empty(),
						fee_msat: 1_000,
						cltv_expiry_delta: 48,
						maybe_announced_channel: true,
					},
					lightning::routing::router::RouteHop {
						pubkey: nodes[1].node.get_our_node_id(),
						node_features: lightning::types::features::NodeFeatures::empty(),
						short_channel_id: last_hop_scid,
						channel_features: lightning::types::features::ChannelFeatures::empty(),
						fee_msat: amount_msat,
						cltv_expiry_delta: TEST_FINAL_CLTV as u32,
						maybe_announced_channel: true,
					},
				],
				blinded_tail: None,
			}],
			route_params: None,
		};
		let quote = crate::CircularRouteQuote {
			amount_msat,
			total_routing_fee_msat: 2_000,
			first_hop_user_channel_id,
			first_hop_short_channel_id: first_hop_scid,
			last_hop_user_channel_id,
			last_hop_short_channel_id: last_hop_scid,
			paths: vec![crate::CircularRoutePath {
				hops: route.paths[0]
					.hops
					.iter()
					.map(|hop| crate::CircularRouteHop {
						node_id: hop.pubkey,
						short_channel_id: hop.short_channel_id,
						fee_msat: hop.fee_msat,
						cltv_expiry_delta: hop.cltv_expiry_delta,
					})
					.collect(),
				amount_msat,
				fee_msat: 2_000,
			}],
			route_bytes: route.encode(),
		};
		let execution = crate::payment::build_prepared_circular_execution(
			&payment_store,
			operation_id,
			&quote,
			first_channel.counterparty.node_id,
			first_hop_scid,
			first_channel.outbound_capacity_msat,
			last_channel.counterparty.node_id,
			last_hop_scid,
			last_channel.inbound_capacity_msat,
			nodes[1].node.get_our_node_id(),
		)
		.unwrap();
		assert_eq!(execution.route, route);
		assert_eq!(execution.payment_hash, payment_hash);
		assert_eq!(execution.outbound_payment_id, outbound_payment_id);
		assert_eq!(execution.outbound_payment.direction, PaymentDirection::Outbound);
		assert_eq!(execution.outbound_payment.status, PaymentStatus::Pending);
		assert_eq!(
			crate::payment::build_prepared_circular_execution(
				&payment_store,
				operation_id,
				&quote,
				first_channel.counterparty.node_id,
				first_hop_scid,
				1,
				last_channel.counterparty.node_id,
				last_hop_scid,
				last_channel.inbound_capacity_msat,
				nodes[1].node.get_our_node_id(),
			)
			.err(),
			Some(Error::InsufficientFunds)
		);

		let mut wrong_last_source_route = route.clone();
		wrong_last_source_route.paths[0].hops[1].pubkey = first_channel.counterparty.node_id;
		let mut wrong_last_source_quote = quote.clone();
		wrong_last_source_quote.paths[0].hops[1].node_id = first_channel.counterparty.node_id;
		wrong_last_source_quote.route_bytes = wrong_last_source_route.encode();
		assert_eq!(
			crate::payment::build_prepared_circular_execution(
				&payment_store,
				operation_id,
				&wrong_last_source_quote,
				first_channel.counterparty.node_id,
				first_hop_scid,
				first_channel.outbound_capacity_msat,
				last_channel.counterparty.node_id,
				last_hop_scid,
				last_channel.inbound_capacity_msat,
				nodes[1].node.get_our_node_id(),
			)
			.err(),
			Some(Error::PaymentSendingFailed)
		);

		let mut over_fee_route = route.clone();
		over_fee_route.paths[0].hops[0].fee_msat = max_routing_fee_msat + 1;
		let mut over_fee_quote = quote.clone();
		let over_fee_total_msat = max_routing_fee_msat + 1_001;
		over_fee_quote.total_routing_fee_msat = over_fee_total_msat;
		over_fee_quote.paths[0].fee_msat = over_fee_total_msat;
		over_fee_quote.paths[0].hops[0].fee_msat = max_routing_fee_msat + 1;
		over_fee_quote.route_bytes = over_fee_route.encode();
		assert_eq!(
			crate::payment::build_prepared_circular_execution(
				&payment_store,
				operation_id,
				&over_fee_quote,
				first_channel.counterparty.node_id,
				first_hop_scid,
				first_channel.outbound_capacity_msat,
				last_channel.counterparty.node_id,
				last_hop_scid,
				last_channel.inbound_capacity_msat,
				nodes[1].node.get_our_node_id(),
			)
			.err(),
			Some(Error::InvalidPaymentId)
		);

		let expired_invoice = nodes[1]
			.node
			.create_bolt11_invoice(Bolt11InvoiceParameters {
				amount_msats: Some(amount_msat),
				invoice_expiry_delta_secs: Some(0),
				..Default::default()
			})
			.unwrap();
		assert!(expired_invoice.is_expired());
		let expired_hash = PaymentHash(expired_invoice.payment_hash().to_byte_array());
		let expired_secret = *expired_invoice.payment_secret();
		let expired_preimage =
			nodes[1].node.get_payment_preimage(expired_hash, expired_secret).unwrap();
		let expired_operation_id = PaymentId([9u8; 32]);
		let expired_outbound_payment_id =
			crate::payment::derive_circular_outbound_payment_id(expired_operation_id);
		let expired_store = PaymentStore::new(
			Vec::new(),
			PAYMENT_INFO_PERSISTENCE_PRIMARY_NAMESPACE.to_string(),
			PAYMENT_INFO_PERSISTENCE_SECONDARY_NAMESPACE.to_string(),
			Arc::new(InMemoryStore::new()),
			Arc::clone(&logger),
		);
		expired_store
			.insert(crate::payment::prepared_circular_payment_details(
				expired_invoice.to_string(),
				expired_hash,
				expired_preimage,
				expired_secret,
				amount_msat,
				crate::payment::CircularPaymentContext {
					operation_id: expired_operation_id,
					outbound_payment_id: expired_outbound_payment_id,
					first_hop_user_channel_id,
					last_hop_user_channel_id,
					max_routing_fee_msat,
				},
			))
			.unwrap();
		assert_eq!(
			crate::payment::build_prepared_circular_execution(
				&expired_store,
				expired_operation_id,
				&quote,
				first_channel.counterparty.node_id,
				first_hop_scid,
				first_channel.outbound_capacity_msat,
				last_channel.counterparty.node_id,
				last_hop_scid,
				last_channel.inbound_capacity_msat,
				nodes[1].node.get_our_node_id(),
			)
			.err(),
			Some(Error::InvalidInvoice)
		);

		let channel_manager_bytes = nodes[1].node.encode();
		let first_monitor_bytes = lightning::get_monitor!(nodes[1], first_channel_id).encode();
		let last_monitor_bytes = lightning::get_monitor!(nodes[1], last_channel_id).encode();
		reload_node!(
			nodes[1],
			channel_manager_bytes,
			&[&first_monitor_bytes, &last_monitor_bytes],
			persister,
			new_chain_monitor,
			node_1_deserialized
		);

		assert_eq!(
			nodes[1].node.get_payment_preimage(payment_hash, payment_secret).unwrap(),
			payment_preimage
		);
		let reloaded_channels = nodes[1].node.list_channels();
		let reloaded_first_channel = reloaded_channels
			.iter()
			.find(|channel| channel.channel_id == first_channel_id)
			.unwrap();
		assert_eq!(reloaded_first_channel.user_channel_id, first_hop_user_channel_id.0);
		assert!(!reloaded_first_channel.is_usable);
		let reloaded_last_channel =
			reloaded_channels.iter().find(|channel| channel.channel_id == last_channel_id).unwrap();
		assert_eq!(reloaded_last_channel.user_channel_id, last_hop_user_channel_id.0);
		assert!(!reloaded_last_channel.is_usable);
		assert!(nodes[1].node.list_recent_payments().is_empty());

		let reloaded_payments =
			crate::io::utils::read_payments(Arc::clone(&kv_store), Arc::clone(&logger)).unwrap();
		assert_eq!(reloaded_payments, vec![payment.clone()]);
		let reloaded_payment_store = PaymentStore::new(
			reloaded_payments,
			PAYMENT_INFO_PERSISTENCE_PRIMARY_NAMESPACE.to_string(),
			PAYMENT_INFO_PERSISTENCE_SECONDARY_NAMESPACE.to_string(),
			kv_store,
			logger,
		);
		assert!(crate::payment::circular_operation_is_prepared(
			&reloaded_payment_store,
			operation_id,
		));
		assert_eq!(reloaded_payment_store.get(&payment_id), Some(payment));
		let recovered_preparation = crate::payment::recover_prepared_circular_payment(
			&reloaded_payment_store,
			operation_id,
			amount_msat,
			first_hop_user_channel_id,
			first_hop_scid,
			last_hop_user_channel_id,
			last_hop_scid,
			max_routing_fee_msat,
		)
		.unwrap()
		.unwrap();
		assert_eq!(recovered_preparation.bolt11_invoice, invoice.to_string());
		assert_eq!(recovered_preparation.payment_hash, payment_hash);
		assert_eq!(recovered_preparation.operation_id, operation_id);
		assert_eq!(recovered_preparation.outbound_payment_id, outbound_payment_id);
		assert_eq!(recovered_preparation.first_hop_short_channel_id, first_hop_scid);
		assert_eq!(recovered_preparation.last_hop_short_channel_id, last_hop_scid);
		assert_eq!(
			crate::payment::recover_prepared_circular_payment(
				&reloaded_payment_store,
				operation_id,
				amount_msat + 1,
				first_hop_user_channel_id,
				first_hop_scid,
				last_hop_user_channel_id,
				last_hop_scid,
				max_routing_fee_msat,
			),
			Err(Error::InvalidPaymentId)
		);
		assert_eq!(
			crate::payment::recover_prepared_circular_payment(
				&reloaded_payment_store,
				operation_id,
				amount_msat,
				first_hop_user_channel_id,
				first_hop_scid,
				last_hop_user_channel_id,
				last_hop_scid,
				max_routing_fee_msat + 1,
			),
			Err(Error::InvalidPaymentId)
		);
		assert!(crate::payment::recover_prepared_circular_payment(
			&expired_store,
			expired_operation_id,
			amount_msat,
			first_hop_user_channel_id,
			first_hop_scid,
			last_hop_user_channel_id,
			last_hop_scid,
			max_routing_fee_msat,
		)
		.unwrap()
		.is_some());

		let send_count = AtomicU16::new(0);
		let duplicate_execution = execution.clone();
		let failed_execution = execution.clone();
		let recovered_duplicate_execution = execution.clone();
		assert_eq!(
			crate::payment::submit_prepared_circular_execution(
				&reloaded_payment_store,
				execution,
				|submitted_route, submitted_hash, _, submitted_id| {
					send_count.fetch_add(1, Ordering::AcqRel);
					assert_eq!(submitted_route, route);
					assert_eq!(submitted_hash, payment_hash);
					assert_eq!(submitted_id, outbound_payment_id);
					assert_eq!(
						reloaded_payment_store.get(&submitted_id).unwrap().status,
						PaymentStatus::Pending
					);
					Ok(())
				},
			),
			Ok(outbound_payment_id)
		);
		assert_eq!(send_count.load(Ordering::Acquire), 1);
		assert_eq!(
			crate::payment::recover_existing_circular_payment(
				&reloaded_payment_store,
				operation_id,
				&quote,
				&[],
			),
			Ok(None)
		);
		assert_eq!(
			crate::payment::recover_existing_circular_payment(
				&reloaded_payment_store,
				operation_id,
				&quote,
				&[RecentPaymentDetails::Pending {
					payment_id: outbound_payment_id,
					payment_hash,
					total_msat: amount_msat,
				}],
			),
			Ok(Some(outbound_payment_id))
		);
		assert_eq!(
			crate::payment::recover_existing_circular_payment(
				&reloaded_payment_store,
				operation_id,
				&quote,
				&[RecentPaymentDetails::Pending {
					payment_id: outbound_payment_id,
					payment_hash: PaymentHash([11u8; 32]),
					total_msat: amount_msat,
				}],
			),
			Err(Error::InvalidPaymentId)
		);
		assert_eq!(
			crate::payment::recover_existing_circular_payment(
				&reloaded_payment_store,
				operation_id,
				&quote,
				&[RecentPaymentDetails::Pending {
					payment_id: outbound_payment_id,
					payment_hash,
					total_msat: amount_msat + 1,
				}],
			),
			Err(Error::InvalidPaymentId)
		);
		reloaded_payment_store
			.update(&PaymentDetailsUpdate {
				status: Some(PaymentStatus::Failed),
				..PaymentDetailsUpdate::new(payment_id)
			})
			.unwrap();
		assert_eq!(
			crate::payment::recover_existing_circular_payment(
				&reloaded_payment_store,
				operation_id,
				&quote,
				&[],
			),
			Err(Error::InvalidPaymentId)
		);
		reloaded_payment_store
			.update(&PaymentDetailsUpdate {
				status: Some(PaymentStatus::Pending),
				..PaymentDetailsUpdate::new(payment_id)
			})
			.unwrap();
		assert_eq!(
			crate::payment::submit_prepared_circular_execution(
				&reloaded_payment_store,
				duplicate_execution,
				|_, _, _, _| {
					send_count.fetch_add(1, Ordering::AcqRel);
					Err(lightning::ln::channelmanager::RetryableSendFailure::DuplicatePayment)
				},
			),
			Ok(outbound_payment_id)
		);
		assert_eq!(send_count.load(Ordering::Acquire), 2);
		reloaded_payment_store
			.update(&PaymentDetailsUpdate {
				status: Some(PaymentStatus::Succeeded),
				..PaymentDetailsUpdate::new(outbound_payment_id)
			})
			.unwrap();
		assert_eq!(
			crate::payment::recover_existing_circular_payment(
				&reloaded_payment_store,
				operation_id,
				&quote,
				&[],
			),
			Ok(Some(outbound_payment_id))
		);
		reloaded_payment_store
			.update(&PaymentDetailsUpdate {
				status: Some(PaymentStatus::Failed),
				..PaymentDetailsUpdate::new(outbound_payment_id)
			})
			.unwrap();
		assert_eq!(
			crate::payment::recover_existing_circular_payment(
				&reloaded_payment_store,
				operation_id,
				&quote,
				&[],
			),
			Err(Error::PaymentSendingFailed)
		);

		reloaded_payment_store.remove(&outbound_payment_id).unwrap();
		assert_eq!(
			crate::payment::submit_prepared_circular_execution(
				&reloaded_payment_store,
				failed_execution,
				|_, _, _, _| {
					send_count.fetch_add(1, Ordering::AcqRel);
					Err(lightning::ln::channelmanager::RetryableSendFailure::RouteNotFound)
				},
			),
			Err(Error::PaymentSendingFailed)
		);
		assert_eq!(send_count.load(Ordering::Acquire), 3);
		assert_eq!(reloaded_payment_store.get(&payment_id).unwrap().status, PaymentStatus::Failed);
		assert_eq!(
			reloaded_payment_store.get(&outbound_payment_id).unwrap().status,
			PaymentStatus::Failed
		);

		reloaded_payment_store.remove(&outbound_payment_id).unwrap();
		reloaded_payment_store
			.update(&PaymentDetailsUpdate {
				status: Some(PaymentStatus::Pending),
				..PaymentDetailsUpdate::new(payment_id)
			})
			.unwrap();
		assert_eq!(
			crate::payment::submit_prepared_circular_execution(
				&reloaded_payment_store,
				recovered_duplicate_execution,
				|_, _, _, _| {
					send_count.fetch_add(1, Ordering::AcqRel);
					Err(lightning::ln::channelmanager::RetryableSendFailure::DuplicatePayment)
				},
			),
			Ok(outbound_payment_id)
		);
		assert_eq!(send_count.load(Ordering::Acquire), 4);
		assert_eq!(reloaded_payment_store.get(&payment_id).unwrap().status, PaymentStatus::Pending);
		assert_eq!(
			reloaded_payment_store.get(&outbound_payment_id).unwrap().status,
			PaymentStatus::Pending
		);
	}

	#[test]
	fn real_htlc_wrong_channel_fails_and_exact_channel_claims() {
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
		create_announced_chan_between_nodes(&nodes, 0, 1);

		let amount_msat = 5_000_000;
		let path = &[&nodes[1]][..];

		let (wrong_route, wrong_hash, wrong_preimage, wrong_secret) =
			lightning::get_route_and_payment_hash!(nodes[0], nodes[1], amount_msat);
		nodes[0]
			.node
			.send_payment_with_route(
				wrong_route,
				wrong_hash,
				RecipientOnionFields::secret_only(wrong_secret),
				PaymentId(wrong_hash.0),
			)
			.unwrap();
		lightning::check_added_monitors!(nodes[0], 1);
		let mut wrong_messages = nodes[0].node.get_and_clear_pending_msg_events();
		let wrong_event = pass_along_path(
			&nodes[0],
			path,
			amount_msat,
			wrong_hash,
			Some(wrong_secret),
			remove_first_msg_event_to_node(&nodes[1].node.get_our_node_id(), &mut wrong_messages),
			true,
			None,
		)
		.unwrap();
		let wrong_receiving_channels = match wrong_event {
			LdkEvent::PaymentClaimable { receiving_channel_ids, .. } => receiving_channel_ids,
			_ => panic!("expected PaymentClaimable"),
		};
		let actual_user_channel_id =
			wrong_receiving_channels[0].1.expect("test channel has a user channel ID");
		let wrong_required_channel_id = UserChannelId(actual_user_channel_id.wrapping_add(1));
		let wrong_kind =
			test_circular_payment_kind(wrong_hash, wrong_preimage, wrong_required_channel_id);
		assert_eq!(
			channel_constrained_claim_decision(
				&wrong_kind,
				PaymentStatus::Pending,
				Some(amount_msat),
				amount_msat,
				&wrong_receiving_channels,
			),
			ChannelConstrainedClaimDecision::Fail(
				CircularPaymentFailureReason::ReceivingChannelMismatch,
			)
		);
		fail_payment_along_route(&nodes[0], &[path], false, wrong_hash);

		let (exact_route, exact_hash, exact_preimage, exact_secret) =
			lightning::get_route_and_payment_hash!(nodes[0], nodes[1], amount_msat);
		nodes[0]
			.node
			.send_payment_with_route(
				exact_route,
				exact_hash,
				RecipientOnionFields::secret_only(exact_secret),
				PaymentId(exact_hash.0),
			)
			.unwrap();
		lightning::check_added_monitors!(nodes[0], 1);
		let mut exact_messages = nodes[0].node.get_and_clear_pending_msg_events();
		let exact_event = pass_along_path(
			&nodes[0],
			path,
			amount_msat,
			exact_hash,
			Some(exact_secret),
			remove_first_msg_event_to_node(&nodes[1].node.get_our_node_id(), &mut exact_messages),
			true,
			None,
		)
		.unwrap();
		let exact_receiving_channels = match exact_event {
			LdkEvent::PaymentClaimable { receiving_channel_ids, .. } => receiving_channel_ids,
			_ => panic!("expected PaymentClaimable"),
		};
		let exact_required_channel_id = UserChannelId(
			exact_receiving_channels[0].1.expect("test channel has a user channel ID"),
		);
		let exact_kind =
			test_circular_payment_kind(exact_hash, exact_preimage, exact_required_channel_id);
		assert_eq!(
			channel_constrained_claim_decision(
				&exact_kind,
				PaymentStatus::Pending,
				Some(amount_msat),
				amount_msat,
				&exact_receiving_channels,
			),
			ChannelConstrainedClaimDecision::Claim(exact_preimage)
		);
		claim_payment_along_route(ClaimAlongRouteArgs::new(&nodes[0], &[path], exact_preimage));
	}

	#[test]
	fn real_mpp_split_across_mixed_incoming_channels_fails() {
		let chanmon_cfgs = create_chanmon_cfgs(4);
		let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
		let nodes = create_network(4, &node_cfgs, &node_chanmgrs);
		create_announced_chan_between_nodes(&nodes, 0, 1);
		create_announced_chan_between_nodes(&nodes, 0, 2);
		create_announced_chan_between_nodes(&nodes, 1, 3);
		create_announced_chan_between_nodes(&nodes, 2, 3);

		let amount_msat = 15_000_000;
		let path_a = &[&nodes[1], &nodes[3]][..];
		let path_b = &[&nodes[2], &nodes[3]][..];
		let (route, payment_hash, payment_preimage, payment_secret) =
			lightning::get_route_and_payment_hash!(nodes[0], nodes[3], amount_msat);
		assert_eq!(route.paths.len(), 2);
		nodes[0]
			.node
			.send_payment_with_route(
				route,
				payment_hash,
				RecipientOnionFields::secret_only(payment_secret),
				PaymentId(payment_hash.0),
			)
			.unwrap();
		lightning::check_added_monitors!(nodes[0], 2);
		let mut messages = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(messages.len(), 2);

		let first_message =
			remove_first_msg_event_to_node(&path_a[0].node.get_our_node_id(), &mut messages);
		assert!(pass_along_path(
			&nodes[0],
			path_a,
			amount_msat,
			payment_hash,
			Some(payment_secret),
			first_message,
			false,
			None,
		)
		.is_none());
		let second_message =
			remove_first_msg_event_to_node(&path_b[0].node.get_our_node_id(), &mut messages);
		let claimable_event = pass_along_path(
			&nodes[0],
			path_b,
			amount_msat,
			payment_hash,
			Some(payment_secret),
			second_message,
			true,
			None,
		)
		.unwrap();
		let receiving_channels = match claimable_event {
			LdkEvent::PaymentClaimable { receiving_channel_ids, .. } => receiving_channel_ids,
			_ => panic!("expected PaymentClaimable"),
		};
		assert_eq!(receiving_channels.len(), 2);
		let first_user_channel_id =
			receiving_channels[0].1.expect("first MPP part has a user channel ID");
		let second_user_channel_id =
			receiving_channels[1].1.expect("second MPP part has a user channel ID");
		assert_ne!(first_user_channel_id, second_user_channel_id);

		let kind = test_circular_payment_kind(
			payment_hash,
			payment_preimage,
			UserChannelId(first_user_channel_id),
		);
		assert_eq!(
			channel_constrained_claim_decision(
				&kind,
				PaymentStatus::Pending,
				Some(amount_msat),
				amount_msat,
				&receiving_channels,
			),
			ChannelConstrainedClaimDecision::Fail(
				CircularPaymentFailureReason::ReceivingChannelMismatch,
			)
		);
		fail_payment_along_route(&nodes[0], &[path_a, path_b], false, payment_hash);
	}

	#[test]
	fn real_prepared_circular_payment_recovers_in_flight_on_exact_channels() {
		let chanmon_cfgs = create_chanmon_cfgs(3);
		let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
		let persister;
		let new_chain_monitor;
		let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
		let node_0_deserialized;
		let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
		let (_, _, first_channel_id, _) =
			create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, 0);
		let (_, _, middle_channel_id, _) =
			create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 100_000, 0);
		let (_, _, last_channel_id, _) =
			create_announced_chan_between_nodes_with_value(&nodes, 2, 0, 100_000, 0);

		let local_channels = nodes[0].node.list_channels();
		let first_channel =
			local_channels.iter().find(|channel| channel.channel_id == first_channel_id).unwrap();
		let last_channel =
			local_channels.iter().find(|channel| channel.channel_id == last_channel_id).unwrap();
		let middle_channel = nodes[1]
			.node
			.list_channels()
			.into_iter()
			.find(|channel| channel.channel_id == middle_channel_id)
			.unwrap();
		let first_hop_user_channel_id = UserChannelId(first_channel.user_channel_id);
		let last_hop_user_channel_id = UserChannelId(last_channel.user_channel_id);
		let first_hop_scid = first_channel.get_outbound_payment_scid().unwrap();
		let middle_hop_scid = middle_channel.get_outbound_payment_scid().unwrap();
		let last_hop_scid = last_channel.get_inbound_payment_scid().unwrap();

		let amount_msat = 5_000_000;
		let max_routing_fee_msat = 10_000;
		let invoice = nodes[0]
			.node
			.create_bolt11_invoice(Bolt11InvoiceParameters {
				amount_msats: Some(amount_msat),
				..Default::default()
			})
			.unwrap();
		let payment_hash = PaymentHash(invoice.payment_hash().to_byte_array());
		let payment_secret = *invoice.payment_secret();
		let payment_preimage =
			nodes[0].node.get_payment_preimage(payment_hash, payment_secret).unwrap();
		let operation_id = PaymentId([8u8; 32]);
		let outbound_payment_id = crate::payment::derive_circular_outbound_payment_id(operation_id);

		let kv_store: Arc<DynStore> = Arc::new(InMemoryStore::new());
		let logger = Arc::new(Logger::new_log_facade());
		let payment_store = PaymentStore::new(
			Vec::new(),
			PAYMENT_INFO_PERSISTENCE_PRIMARY_NAMESPACE.to_string(),
			PAYMENT_INFO_PERSISTENCE_SECONDARY_NAMESPACE.to_string(),
			Arc::clone(&kv_store),
			Arc::clone(&logger),
		);
		payment_store
			.insert(crate::payment::prepared_circular_payment_details(
				invoice.to_string(),
				payment_hash,
				payment_preimage,
				payment_secret,
				amount_msat,
				crate::payment::CircularPaymentContext {
					operation_id,
					outbound_payment_id,
					first_hop_user_channel_id,
					last_hop_user_channel_id,
					max_routing_fee_msat,
				},
			))
			.unwrap();

		let route = lightning::routing::router::Route {
			paths: vec![lightning::routing::router::Path {
				hops: vec![
					lightning::routing::router::RouteHop {
						pubkey: nodes[1].node.get_our_node_id(),
						node_features: lightning::types::features::NodeFeatures::empty(),
						short_channel_id: first_hop_scid,
						channel_features: lightning::types::features::ChannelFeatures::empty(),
						fee_msat: 1_000,
						cltv_expiry_delta: 48,
						maybe_announced_channel: true,
					},
					lightning::routing::router::RouteHop {
						pubkey: nodes[2].node.get_our_node_id(),
						node_features: lightning::types::features::NodeFeatures::empty(),
						short_channel_id: middle_hop_scid,
						channel_features: lightning::types::features::ChannelFeatures::empty(),
						fee_msat: 1_000,
						cltv_expiry_delta: 48,
						maybe_announced_channel: true,
					},
					lightning::routing::router::RouteHop {
						pubkey: nodes[0].node.get_our_node_id(),
						node_features: lightning::types::features::NodeFeatures::empty(),
						short_channel_id: last_hop_scid,
						channel_features: lightning::types::features::ChannelFeatures::empty(),
						fee_msat: amount_msat,
						cltv_expiry_delta: TEST_FINAL_CLTV as u32,
						maybe_announced_channel: true,
					},
				],
				blinded_tail: None,
			}],
			route_params: None,
		};
		let quote = crate::CircularRouteQuote {
			amount_msat,
			total_routing_fee_msat: 2_000,
			first_hop_user_channel_id,
			first_hop_short_channel_id: first_hop_scid,
			last_hop_user_channel_id,
			last_hop_short_channel_id: last_hop_scid,
			paths: vec![crate::CircularRoutePath {
				hops: route.paths[0]
					.hops
					.iter()
					.map(|hop| crate::CircularRouteHop {
						node_id: hop.pubkey,
						short_channel_id: hop.short_channel_id,
						fee_msat: hop.fee_msat,
						cltv_expiry_delta: hop.cltv_expiry_delta,
					})
					.collect(),
				amount_msat,
				fee_msat: 2_000,
			}],
			route_bytes: route.encode(),
		};
		let execution = crate::payment::build_prepared_circular_execution(
			&payment_store,
			operation_id,
			&quote,
			nodes[1].node.get_our_node_id(),
			first_hop_scid,
			first_channel.outbound_capacity_msat,
			nodes[2].node.get_our_node_id(),
			last_hop_scid,
			last_channel.inbound_capacity_msat,
			nodes[0].node.get_our_node_id(),
		)
		.unwrap();
		let duplicate_execution = execution.clone();
		let send_count = AtomicU16::new(0);
		assert_eq!(
			crate::payment::submit_prepared_circular_execution(
				&payment_store,
				execution,
				|route, hash, onion, id| {
					send_count.fetch_add(1, Ordering::AcqRel);
					nodes[0].node.send_payment_with_route(route, hash, onion, id)
				},
			),
			Ok(outbound_payment_id)
		);
		assert_eq!(send_count.load(Ordering::Acquire), 1);
		lightning::check_added_monitors!(nodes[0], 1);

		let channel_manager_bytes = nodes[0].node.encode();
		let first_monitor_bytes = lightning::get_monitor!(nodes[0], first_channel_id).encode();
		let last_monitor_bytes = lightning::get_monitor!(nodes[0], last_channel_id).encode();
		nodes[1].node.peer_disconnected(nodes[0].node.get_our_node_id());
		nodes[2].node.peer_disconnected(nodes[0].node.get_our_node_id());
		reload_node!(
			nodes[0],
			channel_manager_bytes,
			&[&first_monitor_bytes, &last_monitor_bytes],
			persister,
			new_chain_monitor,
			node_0_deserialized
		);
		assert!(nodes[0].node.list_channels().iter().all(|channel| !channel.is_usable));
		let reloaded_payments =
			crate::io::utils::read_payments(Arc::clone(&kv_store), Arc::clone(&logger)).unwrap();
		let reloaded_payment_store = PaymentStore::new(
			reloaded_payments,
			PAYMENT_INFO_PERSISTENCE_PRIMARY_NAMESPACE.to_string(),
			PAYMENT_INFO_PERSISTENCE_SECONDARY_NAMESPACE.to_string(),
			kv_store,
			logger,
		);
		assert_eq!(
			reloaded_payment_store.get(&PaymentId(payment_hash.0)).unwrap().status,
			PaymentStatus::Pending
		);
		assert_eq!(
			reloaded_payment_store.get(&outbound_payment_id).unwrap().status,
			PaymentStatus::Pending
		);
		let recent_payments = nodes[0].node.list_recent_payments();
		assert!(recent_payments.iter().any(|payment| matches!(
			payment,
			RecentPaymentDetails::Pending {
				payment_id,
				payment_hash: tracked_hash,
				total_msat,
			} if *payment_id == outbound_payment_id
				&& *tracked_hash == payment_hash
				&& *total_msat == amount_msat
		)));
		assert_eq!(
			crate::payment::recover_existing_circular_payment(
				&reloaded_payment_store,
				operation_id,
				&quote,
				&recent_payments,
			),
			Ok(Some(outbound_payment_id))
		);
		assert_eq!(
			crate::payment::submit_prepared_circular_execution(
				&reloaded_payment_store,
				duplicate_execution,
				|route, hash, onion, id| {
					send_count.fetch_add(1, Ordering::AcqRel);
					nodes[0].node.send_payment_with_route(route, hash, onion, id)
				},
			),
			Ok(outbound_payment_id)
		);
		assert_eq!(send_count.load(Ordering::Acquire), 2);
		lightning::check_added_monitors!(nodes[0], 0);

		let mut reconnect_destination = ReconnectArgs::new(&nodes[0], &nodes[2]);
		reconnect_destination.send_channel_ready = (true, true);
		reconnect_destination.send_announcement_sigs = (true, true);
		reconnect_nodes(reconnect_destination);
		let mut reconnect_source = ReconnectArgs::new(&nodes[0], &nodes[1]);
		reconnect_source.send_channel_ready = (true, true);
		reconnect_source.send_announcement_sigs = (true, true);
		reconnect_source.pending_htlc_adds = (0, 1);
		reconnect_nodes(reconnect_source);
		nodes[1].node.process_pending_htlc_forwards();
		lightning::check_added_monitors!(nodes[1], 1);

		let path = &[&nodes[1], &nodes[2], &nodes[0]][..];
		let mut messages = nodes[1].node.get_and_clear_pending_msg_events();
		let claimable_event = pass_along_path(
			&nodes[1],
			&path[1..],
			amount_msat,
			payment_hash,
			Some(payment_secret),
			remove_first_msg_event_to_node(&nodes[2].node.get_our_node_id(), &mut messages),
			true,
			Some(payment_preimage),
		)
		.unwrap();
		let receiving_channels = match claimable_event {
			LdkEvent::PaymentClaimable { receiving_channel_ids, .. } => receiving_channel_ids,
			_ => panic!("expected PaymentClaimable"),
		};
		assert_eq!(receiving_channels.len(), 1);
		assert_eq!(receiving_channels[0].1, Some(last_hop_user_channel_id.0));
		let prepared = payment_store.get(&PaymentId(payment_hash.0)).unwrap();
		assert_eq!(
			channel_constrained_claim_decision(
				&prepared.kind,
				prepared.status,
				prepared.amount_msat,
				amount_msat,
				&receiving_channels,
			),
			ChannelConstrainedClaimDecision::Claim(payment_preimage)
		);
		let paid_fee_msat = do_claim_payment_along_route(ClaimAlongRouteArgs::new(
			&nodes[0],
			&[path],
			payment_preimage,
		));
		assert_eq!(paid_fee_msat, 2_000);
		let settlement_events = nodes[0].node.get_and_clear_pending_events();
		lightning::check_added_monitors!(nodes[0], 1);
		assert_eq!(settlement_events.len(), 2, "{settlement_events:?}");
		match &settlement_events[0] {
			LdkEvent::PaymentSent {
				payment_id,
				payment_preimage: settled_preimage,
				payment_hash: settled_hash,
				amount_msat: settled_amount_msat,
				fee_paid_msat,
				..
			} => {
				assert_eq!(*payment_id, Some(outbound_payment_id));
				assert_eq!(*settled_preimage, payment_preimage);
				assert_eq!(*settled_hash, payment_hash);
				assert_eq!(*settled_amount_msat, Some(amount_msat));
				assert_eq!(*fee_paid_msat, Some(2_000));
			},
			other => panic!("expected PaymentSent, got {other:?}"),
		}
		match &settlement_events[1] {
			LdkEvent::PaymentPathSuccessful {
				payment_id, payment_hash: path_hash, path, ..
			} => {
				assert_eq!(*payment_id, outbound_payment_id);
				assert_eq!(*path_hash, Some(payment_hash));
				assert_eq!(path.hops.first().unwrap().short_channel_id, first_hop_scid);
				assert_eq!(path.hops.last().unwrap().short_channel_id, last_hop_scid);
			},
			other => panic!("expected PaymentPathSuccessful, got {other:?}"),
		}
	}

	#[test]
	fn real_prepared_circular_mpp_keeps_both_exact_local_channels() {
		let chanmon_cfgs = create_chanmon_cfgs(5);
		let node_cfgs = create_node_cfgs(5, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(5, &node_cfgs, &[None, None, None, None, None]);
		let nodes = create_network(5, &node_cfgs, &node_chanmgrs);
		let (_, _, first_channel_id, _) =
			create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, 0);
		let (_, _, branch_a_channel_id, _) =
			create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 100_000, 0);
		let (_, _, branch_b_channel_id, _) =
			create_announced_chan_between_nodes_with_value(&nodes, 1, 3, 100_000, 0);
		let (_, _, converge_a_channel_id, _) =
			create_announced_chan_between_nodes_with_value(&nodes, 2, 4, 100_000, 0);
		let (_, _, converge_b_channel_id, _) =
			create_announced_chan_between_nodes_with_value(&nodes, 3, 4, 100_000, 0);
		let (_, _, last_channel_id, _) =
			create_announced_chan_between_nodes_with_value(&nodes, 4, 0, 100_000, 0);

		let local_channels = nodes[0].node.list_channels();
		let first_channel =
			local_channels.iter().find(|channel| channel.channel_id == first_channel_id).unwrap();
		let last_channel =
			local_channels.iter().find(|channel| channel.channel_id == last_channel_id).unwrap();
		let first_hop_user_channel_id = UserChannelId(first_channel.user_channel_id);
		let last_hop_user_channel_id = UserChannelId(last_channel.user_channel_id);
		let first_hop_scid = first_channel.get_outbound_payment_scid().unwrap();
		let branch_a_scid = nodes[1]
			.node
			.list_channels()
			.into_iter()
			.find(|channel| channel.channel_id == branch_a_channel_id)
			.unwrap()
			.get_outbound_payment_scid()
			.unwrap();
		let branch_b_scid = nodes[1]
			.node
			.list_channels()
			.into_iter()
			.find(|channel| channel.channel_id == branch_b_channel_id)
			.unwrap()
			.get_outbound_payment_scid()
			.unwrap();
		let converge_a_scid = nodes[2]
			.node
			.list_channels()
			.into_iter()
			.find(|channel| channel.channel_id == converge_a_channel_id)
			.unwrap()
			.get_outbound_payment_scid()
			.unwrap();
		let converge_b_scid = nodes[3]
			.node
			.list_channels()
			.into_iter()
			.find(|channel| channel.channel_id == converge_b_channel_id)
			.unwrap()
			.get_outbound_payment_scid()
			.unwrap();
		let last_hop_scid = last_channel.get_inbound_payment_scid().unwrap();

		let amount_msat = 5_000_000;
		let path_a_amount_msat = 3_000_000;
		let path_b_amount_msat = 2_000_000;
		let total_routing_fee_msat = 6_000;
		let max_routing_fee_msat = 10_000;
		let invoice = nodes[0]
			.node
			.create_bolt11_invoice(Bolt11InvoiceParameters {
				amount_msats: Some(amount_msat),
				..Default::default()
			})
			.unwrap();
		let payment_hash = PaymentHash(invoice.payment_hash().to_byte_array());
		let payment_secret = *invoice.payment_secret();
		let payment_preimage =
			nodes[0].node.get_payment_preimage(payment_hash, payment_secret).unwrap();
		let operation_id = PaymentId([10u8; 32]);
		let outbound_payment_id = crate::payment::derive_circular_outbound_payment_id(operation_id);

		let kv_store: Arc<DynStore> = Arc::new(InMemoryStore::new());
		let logger = Arc::new(Logger::new_log_facade());
		let payment_store = PaymentStore::new(
			Vec::new(),
			PAYMENT_INFO_PERSISTENCE_PRIMARY_NAMESPACE.to_string(),
			PAYMENT_INFO_PERSISTENCE_SECONDARY_NAMESPACE.to_string(),
			kv_store,
			logger,
		);
		payment_store
			.insert(crate::payment::prepared_circular_payment_details(
				invoice.to_string(),
				payment_hash,
				payment_preimage,
				payment_secret,
				amount_msat,
				crate::payment::CircularPaymentContext {
					operation_id,
					outbound_payment_id,
					first_hop_user_channel_id,
					last_hop_user_channel_id,
					max_routing_fee_msat,
				},
			))
			.unwrap();

		let make_hop = |pubkey, short_channel_id, fee_msat| lightning::routing::router::RouteHop {
			pubkey,
			node_features: lightning::types::features::NodeFeatures::empty(),
			short_channel_id,
			channel_features: lightning::types::features::ChannelFeatures::empty(),
			fee_msat,
			cltv_expiry_delta: if pubkey == nodes[0].node.get_our_node_id() {
				TEST_FINAL_CLTV as u32
			} else {
				48
			},
			maybe_announced_channel: true,
		};
		let route = lightning::routing::router::Route {
			paths: vec![
				lightning::routing::router::Path {
					hops: vec![
						make_hop(nodes[1].node.get_our_node_id(), first_hop_scid, 1_000),
						make_hop(nodes[2].node.get_our_node_id(), branch_a_scid, 1_000),
						make_hop(nodes[4].node.get_our_node_id(), converge_a_scid, 1_000),
						make_hop(
							nodes[0].node.get_our_node_id(),
							last_hop_scid,
							path_a_amount_msat,
						),
					],
					blinded_tail: None,
				},
				lightning::routing::router::Path {
					hops: vec![
						make_hop(nodes[1].node.get_our_node_id(), first_hop_scid, 1_000),
						make_hop(nodes[3].node.get_our_node_id(), branch_b_scid, 1_000),
						make_hop(nodes[4].node.get_our_node_id(), converge_b_scid, 1_000),
						make_hop(
							nodes[0].node.get_our_node_id(),
							last_hop_scid,
							path_b_amount_msat,
						),
					],
					blinded_tail: None,
				},
			],
			route_params: None,
		};
		let quote_paths = route
			.paths
			.iter()
			.map(|path| crate::CircularRoutePath {
				hops: path
					.hops
					.iter()
					.map(|hop| crate::CircularRouteHop {
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
		let quote = crate::CircularRouteQuote {
			amount_msat,
			total_routing_fee_msat,
			first_hop_user_channel_id,
			first_hop_short_channel_id: first_hop_scid,
			last_hop_user_channel_id,
			last_hop_short_channel_id: last_hop_scid,
			paths: quote_paths,
			route_bytes: route.encode(),
		};
		let execution = crate::payment::build_prepared_circular_execution(
			&payment_store,
			operation_id,
			&quote,
			nodes[1].node.get_our_node_id(),
			first_hop_scid,
			first_channel.outbound_capacity_msat,
			nodes[4].node.get_our_node_id(),
			last_hop_scid,
			last_channel.inbound_capacity_msat,
			nodes[0].node.get_our_node_id(),
		)
		.unwrap();
		assert_eq!(
			crate::payment::submit_prepared_circular_execution(
				&payment_store,
				execution,
				|route, hash, onion, id| {
					nodes[0].node.send_payment_with_route(route, hash, onion, id)
				},
			),
			Ok(outbound_payment_id)
		);
		lightning::check_added_monitors!(nodes[0], 1);

		let path_a = &[&nodes[1], &nodes[2], &nodes[4], &nodes[0]][..];
		let path_b = &[&nodes[1], &nodes[3], &nodes[4], &nodes[0]][..];
		let mut messages = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(messages.len(), 1);
		let first_part =
			remove_first_msg_event_to_node(&nodes[1].node.get_our_node_id(), &mut messages);
		let first_part = SendEvent::from_event(first_part);
		assert_eq!(first_part.msgs.len(), 1);
		nodes[1].node.handle_update_add_htlc(nodes[0].node.get_our_node_id(), &first_part.msgs[0]);
		lightning::check_added_monitors!(nodes[1], 0);
		nodes[1].node.handle_commitment_signed_batch_test(
			nodes[0].node.get_our_node_id(),
			&first_part.commitment_msg,
		);
		lightning::check_added_monitors!(nodes[1], 1);
		let (first_revoke_and_ack, first_commitment_signed) =
			lightning::get_revoke_commit_msgs!(nodes[1], nodes[0].node.get_our_node_id());
		nodes[0].node.handle_revoke_and_ack(nodes[1].node.get_our_node_id(), &first_revoke_and_ack);
		lightning::check_added_monitors!(nodes[0], 1);
		let mut messages = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(messages.len(), 1);
		let second_part =
			remove_first_msg_event_to_node(&nodes[1].node.get_our_node_id(), &mut messages);
		nodes[0].node.handle_commitment_signed_batch_test(
			nodes[1].node.get_our_node_id(),
			&first_commitment_signed,
		);
		lightning::check_added_monitors!(nodes[0], 1);
		let final_revoke_and_ack = lightning::get_event_msg!(
			nodes[0],
			MessageSendEvent::SendRevokeAndACK,
			nodes[1].node.get_our_node_id()
		);
		nodes[1].node.handle_revoke_and_ack(nodes[0].node.get_our_node_id(), &final_revoke_and_ack);
		lightning::check_added_monitors!(nodes[1], 1);
		nodes[1].node.process_pending_htlc_forwards();
		lightning::check_added_monitors!(nodes[1], 1);
		let mut first_forward_messages = nodes[1].node.get_and_clear_pending_msg_events();
		let first_forward = remove_first_msg_event_to_node(
			&nodes[2].node.get_our_node_id(),
			&mut first_forward_messages,
		);
		assert!(pass_along_path(
			&nodes[1],
			&path_a[1..],
			path_a_amount_msat,
			payment_hash,
			Some(payment_secret),
			first_forward,
			false,
			Some(payment_preimage),
		)
		.is_none());
		let claimable_event = pass_along_path(
			&nodes[0],
			path_b,
			amount_msat,
			payment_hash,
			Some(payment_secret),
			second_part,
			true,
			Some(payment_preimage),
		)
		.unwrap();
		let receiving_channels = match claimable_event {
			LdkEvent::PaymentClaimable { receiving_channel_ids, .. } => receiving_channel_ids,
			_ => panic!("expected PaymentClaimable"),
		};
		assert_eq!(receiving_channels.len(), 2);
		assert!(receiving_channels
			.iter()
			.all(|(_, user_channel_id)| *user_channel_id == Some(last_hop_user_channel_id.0)));
		let prepared = payment_store.get(&PaymentId(payment_hash.0)).unwrap();
		assert_eq!(
			channel_constrained_claim_decision(
				&prepared.kind,
				prepared.status,
				prepared.amount_msat,
				amount_msat,
				&receiving_channels,
			),
			ChannelConstrainedClaimDecision::Claim(payment_preimage)
		);

		nodes[0].node.claim_funds(payment_preimage);
		let claimed_events = nodes[0].node.get_and_clear_pending_events();
		assert_eq!(claimed_events.len(), 1, "{claimed_events:?}");
		match &claimed_events[0] {
			LdkEvent::PaymentClaimed {
				payment_hash: claimed_hash,
				amount_msat: claimed_amount_msat,
				htlcs,
				..
			} => {
				assert_eq!(*claimed_hash, payment_hash);
				assert_eq!(*claimed_amount_msat, amount_msat);
				assert_eq!(htlcs.len(), 2);
				assert!(htlcs.iter().all(|htlc| {
					htlc.user_channel_id == last_hop_user_channel_id.0
						&& htlc.channel_id == last_channel_id
				}));
			},
			other => panic!("expected PaymentClaimed, got {other:?}"),
		}
		lightning::check_added_monitors!(nodes[0], 2);

		let parse_single_fulfill = |event| match event {
			MessageSendEvent::UpdateHTLCs { node_id, updates, .. } => {
				assert!(updates.update_add_htlcs.is_empty());
				assert_eq!(updates.update_fulfill_htlcs.len(), 1);
				assert!(updates.update_fail_htlcs.is_empty());
				assert!(updates.update_fail_malformed_htlcs.is_empty());
				assert!(updates.update_fee.is_none());
				((updates.update_fulfill_htlcs[0].clone(), updates.commitment_signed), node_id)
			},
			other => panic!("expected a single fulfill update, got {other:?}"),
		};
		macro_rules! pass_fulfill_through_common_inbound_peer {
			($settlement_event:expr, $next_node:expr, $expect_held_fulfill:expr) => {{
				let ((fulfill, commitment_signed), target_node_id) =
					parse_single_fulfill($settlement_event);
				assert_eq!(target_node_id, nodes[4].node.get_our_node_id());
				nodes[4].node.handle_update_fulfill_htlc(nodes[0].node.get_our_node_id(), fulfill);
				lightning::check_added_monitors!(nodes[4], 1);
				let forwarded_events = nodes[4].node.get_and_clear_pending_events();
				assert_eq!(forwarded_events.len(), 1, "{forwarded_events:?}");
				assert_eq!(
					lightning::ln::functional_test_utils::expect_payment_forwarded(
						forwarded_events.into_iter().next().unwrap(),
						&nodes[4],
						&$next_node,
						&nodes[0],
						Some(1_000),
						None,
						false,
						false,
						false,
					),
					Some(1_000)
				);
				let mut forward_messages = nodes[4].node.get_and_clear_pending_msg_events();
				let forward = remove_first_msg_event_to_node(
					&$next_node.node.get_our_node_id(),
					&mut forward_messages,
				);
				assert!(forward_messages.is_empty());

				nodes[4].node.handle_commitment_signed_batch_test(
					nodes[0].node.get_our_node_id(),
					&commitment_signed,
				);
				lightning::check_added_monitors!(nodes[4], 1);
				let (revoke_and_ack, counterparty_commitment_signed) =
					lightning::get_revoke_commit_msgs!(nodes[4], nodes[0].node.get_our_node_id());
				nodes[0]
					.node
					.handle_revoke_and_ack(nodes[4].node.get_our_node_id(), &revoke_and_ack);
				lightning::check_added_monitors!(nodes[0], 1);
				let mut held_messages = nodes[0].node.get_and_clear_pending_msg_events();
				let held_fulfill = if $expect_held_fulfill {
					assert_eq!(held_messages.len(), 1);
					Some(remove_first_msg_event_to_node(
						&nodes[4].node.get_our_node_id(),
						&mut held_messages,
					))
				} else {
					assert!(held_messages.is_empty());
					None
				};
				nodes[0].node.handle_commitment_signed_batch_test(
					nodes[4].node.get_our_node_id(),
					&counterparty_commitment_signed,
				);
				lightning::check_added_monitors!(nodes[0], 1);
				let final_revoke_and_ack = lightning::get_event_msg!(
					nodes[0],
					MessageSendEvent::SendRevokeAndACK,
					nodes[4].node.get_our_node_id()
				);
				nodes[4]
					.node
					.handle_revoke_and_ack(nodes[0].node.get_our_node_id(), &final_revoke_and_ack);
				lightning::check_added_monitors!(nodes[4], 1);
				(forward, held_fulfill)
			}};
		}

		let mut settlement_messages = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(settlement_messages.len(), 1);
		let first_settlement_part = remove_first_msg_event_to_node(
			&nodes[4].node.get_our_node_id(),
			&mut settlement_messages,
		);
		let (first_forward, second_settlement_part) =
			pass_fulfill_through_common_inbound_peer!(first_settlement_part, nodes[2], true);
		let (second_forward, no_more_settlement_parts) = pass_fulfill_through_common_inbound_peer!(
			second_settlement_part.unwrap(),
			nodes[3],
			false
		);
		assert!(no_more_settlement_parts.is_none());

		let first_forward = parse_single_fulfill(first_forward);
		let second_forward = parse_single_fulfill(second_forward);
		let path_a_after_inbound_peer = &[&nodes[1], &nodes[2], &nodes[4]][..];
		let path_b_after_inbound_peer = &[&nodes[1], &nodes[3], &nodes[4]][..];
		let first_remaining_fee_msat =
			lightning::ln::functional_test_utils::pass_claimed_payment_along_route_from_ev(
				path_a_amount_msat,
				vec![first_forward],
				ClaimAlongRouteArgs::new(&nodes[0], &[path_a_after_inbound_peer], payment_preimage),
			);
		let mut settlement_events = nodes[0].node.get_and_clear_pending_events();
		lightning::check_added_monitors!(nodes[0], 1);
		let second_remaining_fee_msat =
			lightning::ln::functional_test_utils::pass_claimed_payment_along_route_from_ev(
				path_b_amount_msat,
				vec![second_forward],
				ClaimAlongRouteArgs::new(&nodes[0], &[path_b_after_inbound_peer], payment_preimage),
			);
		settlement_events.extend(nodes[0].node.get_and_clear_pending_events());
		lightning::check_added_monitors!(nodes[0], 0);
		assert_eq!(
			first_remaining_fee_msat + second_remaining_fee_msat + 2_000,
			total_routing_fee_msat
		);
		assert_eq!(settlement_events.len(), 3, "{settlement_events:?}");
		match &settlement_events[0] {
			LdkEvent::PaymentSent {
				payment_id,
				payment_preimage: settled_preimage,
				payment_hash: settled_hash,
				amount_msat: settled_amount_msat,
				fee_paid_msat,
				..
			} => {
				assert_eq!(*payment_id, Some(outbound_payment_id));
				assert_eq!(*settled_preimage, payment_preimage);
				assert_eq!(*settled_hash, payment_hash);
				assert_eq!(*settled_amount_msat, Some(amount_msat));
				assert_eq!(*fee_paid_msat, Some(total_routing_fee_msat));
			},
			other => panic!("expected PaymentSent, got {other:?}"),
		}
		for event in &settlement_events[1..] {
			match event {
				LdkEvent::PaymentPathSuccessful {
					payment_id,
					payment_hash: path_hash,
					path,
					..
				} => {
					assert_eq!(*payment_id, outbound_payment_id);
					assert_eq!(*path_hash, Some(payment_hash));
					assert_eq!(path.hops.first().unwrap().short_channel_id, first_hop_scid);
					assert_eq!(path.hops.last().unwrap().short_channel_id, last_hop_scid);
				},
				other => panic!("expected PaymentPathSuccessful, got {other:?}"),
			}
		}
	}

	fn test_circular_payment_kind(
		hash: PaymentHash, preimage: PaymentPreimage, required_channel_id: UserChannelId,
	) -> PaymentKind {
		PaymentKind::Bolt11 {
			hash,
			preimage: Some(preimage),
			secret: None,
			bolt11_invoice: None,
			required_receiving_channel_id: Some(required_channel_id),
			required_sending_channel_id: Some(UserChannelId(required_channel_id.0.wrapping_add(2))),
			circular_operation_id: Some(PaymentId([4u8; 32])),
			circular_outbound_payment_id: Some(PaymentId([5u8; 32])),
			circular_max_routing_fee_msat: Some(1_000_000),
		}
	}

	#[tokio::test]
	async fn event_queue_concurrency() {
		let store: Arc<DynStore> = Arc::new(InMemoryStore::new());
		let logger = Arc::new(TestLogger::new());
		let event_queue = Arc::new(EventQueue::new(Arc::clone(&store), Arc::clone(&logger)));
		assert_eq!(event_queue.next_event(), None);

		let expected_event = Event::ChannelReady {
			channel_id: ChannelId([23u8; 32]),
			user_channel_id: UserChannelId(2323),
			counterparty_node_id: None,
			funding_txo: None,
		};

		// Check `next_event_async` won't return if the queue is empty and always rather timeout.
		tokio::select! {
			_ = tokio::time::sleep(Duration::from_secs(1)) => {
				// Timeout
			}
			_ = event_queue.next_event_async() => {
				panic!();
			}
		}

		assert_eq!(event_queue.next_event(), None);
		// Check we get the expected number of events when polling/enqueuing concurrently.
		let enqueued_events = AtomicU16::new(0);
		let received_events = AtomicU16::new(0);
		let mut delayed_enqueue = false;

		for _ in 0..25 {
			event_queue.add_event(expected_event.clone()).await.unwrap();
			enqueued_events.fetch_add(1, Ordering::SeqCst);
		}

		loop {
			tokio::select! {
				_ = tokio::time::sleep(Duration::from_millis(10)), if !delayed_enqueue => {
					event_queue.add_event(expected_event.clone()).await.unwrap();
					enqueued_events.fetch_add(1, Ordering::SeqCst);
					delayed_enqueue = true;
				}
				e = event_queue.next_event_async() => {
					assert_eq!(e, expected_event);
					event_queue.event_handled().await.unwrap();
					received_events.fetch_add(1, Ordering::SeqCst);

					event_queue.add_event(expected_event.clone()).await.unwrap();
					enqueued_events.fetch_add(1, Ordering::SeqCst);
				}
				e = event_queue.next_event_async() => {
					assert_eq!(e, expected_event);
					event_queue.event_handled().await.unwrap();
					received_events.fetch_add(1, Ordering::SeqCst);
				}
			}

			if delayed_enqueue
				&& received_events.load(Ordering::SeqCst) == enqueued_events.load(Ordering::SeqCst)
			{
				break;
			}
		}
		assert_eq!(event_queue.next_event(), None);
	}
}
