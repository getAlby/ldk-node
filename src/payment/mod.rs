// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Objects for different types of payments.

pub(crate) mod asynchronous;
mod bolt11;
mod bolt12;
mod onchain;
mod spontaneous;
pub(crate) mod store;
mod unified_qr;

pub(crate) use bolt11::derive_circular_outbound_payment_id;
pub use bolt11::Bolt11Payment;
#[cfg(test)]
pub(crate) use bolt11::{
	build_prepared_circular_execution, circular_operation_is_prepared,
	prepared_circular_payment_details, recover_existing_circular_payment,
	recover_prepared_circular_payment, submit_prepared_circular_execution, CircularPaymentContext,
};
pub use bolt12::Bolt12Payment;
pub use onchain::OnchainPayment;
pub use spontaneous::SpontaneousPayment;
pub use store::{
	CircularPaymentFailureReason, ConfirmationStatus, LSPFeeLimits, PaymentDetails,
	PaymentDirection, PaymentKind, PaymentStatus,
};
pub use unified_qr::{QrPaymentResult, UnifiedQrPayment};
