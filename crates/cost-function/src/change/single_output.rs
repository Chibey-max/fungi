use std::convert::Infallible;

use crate::{
    change::{ChangeSelection, ChangeSelector},
    selection::InputSelection,
};

/// Returns the whole surplus as one change output.
pub(crate) struct SingleOutputChangeSelector;

impl ChangeSelector for SingleOutputChangeSelector {
    fn select(&self, request: &InputSelection) -> Result<ChangeSelection, Self::Error> {
        Ok(ChangeSelection(vec![request.surplus]))
    }

    type Error = Infallible;
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Amount;

    #[test]
    fn returns_the_surplus_as_one_output() {
        let request = InputSelection {
            selected_inputs: vec![],
            surplus: Amount::from_sat(1_000),
        };

        assert_eq!(
            SingleOutputChangeSelector.select(&request),
            Ok(ChangeSelection(vec![Amount::from_sat(1_000)]))
        );
    }
}
