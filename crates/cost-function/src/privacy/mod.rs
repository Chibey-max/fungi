use bitcoin::{Amount, SignedAmount};

use crate::simulate::WalletStateDiff;

/// Defines interfaces for privacy metrics.

/// Convert a metric output into a `SignedAmount` relative to a privacy budget.
pub(crate) trait IntoCost {
    fn into_cost(&self, budget: Amount) -> SignedAmount;
}

/// Object-safe erased form of a privacy metric, suitable for storage as a trait object.
pub(crate) trait ErasedPrivacyMetric: std::fmt::Debug {
    fn evaluate_erased(&self, plan: &WalletStateDiff) -> Box<dyn IntoCost>;
    fn clone_box(&self) -> Box<dyn ErasedPrivacyMetric>;
}

impl Clone for Box<dyn ErasedPrivacyMetric> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

#[allow(unused)]
pub(crate) trait PrivacyMetric: ErasedPrivacyMetric {
    type Output: IntoCost + std::fmt::Debug;
    fn evaluate(&self, plan: WalletStateDiff) -> Self::Output;
}

/// A collection of privacy metrics evaluated together against a shared budget.
#[derive(Debug, Clone)]
pub(crate) struct PrivacyBundle {
    pub(crate) metrics: Vec<Box<dyn ErasedPrivacyMetric>>,
    pub(crate) budget: Amount,
}
