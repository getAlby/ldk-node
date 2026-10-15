// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use std::collections::HashSet;
use std::ops::Deref;

use bitcoin::{OutPoint, Transaction};
use lightning::chain::chaininterface::BroadcasterInterface;
use tokio::sync::{mpsc, Mutex, MutexGuard};

use crate::logger::{log_error, LdkLogger};

const BCAST_PACKAGE_QUEUE_SIZE: usize = 50;

pub(crate) struct TransactionBroadcaster<L: Deref>
where
	L::Target: LdkLogger,
{
	queue_sender: mpsc::Sender<Vec<Transaction>>,
	queue_receiver: Mutex<mpsc::Receiver<Vec<Transaction>>>,
	// Alby: funding outputs of channels whose monitors were restored from a static channel backup
	blocked_funding_outpoints: std::sync::Mutex<HashSet<OutPoint>>,
	logger: L,
}

impl<L: Deref> TransactionBroadcaster<L>
where
	L::Target: LdkLogger,
{
	pub(crate) fn new(logger: L) -> Self {
		let (queue_sender, queue_receiver) = mpsc::channel(BCAST_PACKAGE_QUEUE_SIZE);
		Self {
			queue_sender,
			queue_receiver: Mutex::new(queue_receiver),
			blocked_funding_outpoints: std::sync::Mutex::new(HashSet::new()),
			logger,
		}
	}

	/// Alby: never broadcast transactions spending the given channel funding outputs.
	///
	/// Channel monitors restored from a static channel backup are outdated, so a commitment
	/// transaction built from them (e.g. to time out an expired HTLC) is likely revoked and
	/// broadcasting it would allow the counterparty to claim the whole channel balance with a
	/// penalty transaction. The only transactions spending a funding output are our commitment
	/// transactions and cooperative closes, which cannot happen without a channel manager.
	pub(crate) fn block_funding_outpoint_spends(
		&self, outpoints: impl IntoIterator<Item = OutPoint>,
	) {
		self.blocked_funding_outpoints.lock().unwrap().extend(outpoints);
	}

	fn spends_blocked_funding_outpoint(&self, tx: &Transaction) -> bool {
		let blocked_funding_outpoints = self.blocked_funding_outpoints.lock().unwrap();
		tx.input.iter().any(|input| blocked_funding_outpoints.contains(&input.previous_output))
	}

	pub(crate) async fn get_broadcast_queue(
		&self,
	) -> MutexGuard<'_, mpsc::Receiver<Vec<Transaction>>> {
		self.queue_receiver.lock().await
	}
}

impl<L: Deref> BroadcasterInterface for TransactionBroadcaster<L>
where
	L::Target: LdkLogger,
{
	fn broadcast_transactions(&self, txs: &[&Transaction]) {
		// Alby: drop the whole package, the other transactions (e.g. an anchor CPFP) depend on the
		// commitment transaction.
		if let Some(tx) = txs.iter().find(|tx| self.spends_blocked_funding_outpoint(tx)) {
			log_error!(
				self.logger,
				"Refusing to broadcast transaction {} spending the funding output of a restored channel monitor",
				tx.compute_txid()
			);
			return;
		}
		let package = txs.iter().map(|&t| t.clone()).collect::<Vec<Transaction>>();
		self.queue_sender.try_send(package).unwrap_or_else(|e| {
			log_error!(self.logger, "Failed to broadcast transactions: {}", e);
		});
	}
}

#[cfg(test)]
mod tests {
	use std::str::FromStr;
	use std::sync::Arc;

	use bitcoin::absolute::LockTime;
	use bitcoin::transaction::Version;
	use bitcoin::{Amount, ScriptBuf, Sequence, TxIn, TxOut, Txid, Witness};

	use super::*;
	use crate::logger::Logger;

	fn spending_tx(previous_output: OutPoint) -> Transaction {
		Transaction {
			version: Version::TWO,
			lock_time: LockTime::ZERO,
			input: vec![TxIn {
				previous_output,
				script_sig: ScriptBuf::new(),
				sequence: Sequence::MAX,
				witness: Witness::new(),
			}],
			output: vec![TxOut { value: Amount::from_sat(1000), script_pubkey: ScriptBuf::new() }],
		}
	}

	#[tokio::test]
	async fn refuses_to_broadcast_spends_of_blocked_funding_outpoints() {
		let broadcaster = TransactionBroadcaster::new(Arc::new(Logger::new_log_facade()));
		let txid =
			Txid::from_str("4141414141414141414141414141414141414141414141414141414141414141")
				.unwrap();
		let funding_outpoint = OutPoint { txid, vout: 0 };
		broadcaster.block_funding_outpoint_spends([funding_outpoint]);

		let commitment_tx = spending_tx(funding_outpoint);
		let anchor_cpfp_tx = spending_tx(OutPoint { txid: commitment_tx.compute_txid(), vout: 0 });
		broadcaster.broadcast_transactions(&[&commitment_tx, &anchor_cpfp_tx]);

		let other_tx = spending_tx(OutPoint { txid, vout: 1 });
		broadcaster.broadcast_transactions(&[&other_tx]);

		let mut queue = broadcaster.get_broadcast_queue().await;
		assert_eq!(queue.try_recv().unwrap(), vec![other_tx]);
		assert!(queue.try_recv().is_err());
	}
}
