//! Change strategy.

use bitcoin::{Amount, Weight};

use crate::selection::InputSelection;

/// The values of the change outputs a `ChangeSelector` decided to create.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ChangeSelection(Vec<Amount>);

/// Change selection strategy.
pub(crate) trait ChangeSelector {
    type Error;

    fn select(&self, request: &InputSelection) -> Result<ChangeSelection, Self::Error>;
}

/// The wallet's source of change scriptpubkeys.
///
/// Reports what a change output will cost before any scriptpubkey is assigned, so change can
/// be priced without deriving an address for a transaction that may never be broadcast.
pub(crate) trait ScriptpubkeyAssigner {
    /// Weight a change output adds to a transaction.
    fn output_weight(&self) -> Weight;

    /// Weight of the scriptSig and witness that will spend a change output.
    fn satisfaction_weight(&self) -> Weight;

    /// Smallest value relay policy accepts for a change output.
    fn dust(&self) -> Amount;
}
