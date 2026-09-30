//! Change strategy.

use bitcoin::Amount;

use crate::selection::InputSelection;

/// The values of the change outputs a `ChangeSelector` decided to create.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ChangeSelection(Vec<Amount>);

/// Change selection strategy.
pub(crate) trait ChangeSelector {
    type Error;

    fn select(&self, request: &InputSelection) -> Result<ChangeSelection, Self::Error>;
}
