use crate::{
    error::*,
    scripts::*,
    transactions::{
        utils, RevaultPresignedTransaction, RevaultTransaction, EMER_TX_FEERATE, INSANE_FEES,
        MAX_STANDARD_TX_WEIGHT,
    },
    txins::*,
    txouts::*,
};

use miniscript::bitcoin::{
    blockdata::constants::max_money, consensus::encode::Decodable,
    util::psbt::PartiallySignedTransaction as Psbt, Amount, Network, OutPoint,
};

#[cfg(feature = "use-serde")]
use {
    serde::de::{self, Deserialize, Deserializer},
    serde::ser::{Serialize, Serializer},
};

use std::convert::TryInto;

impl_revault_transaction!(
    UnvaultEmergencyTransaction,
    doc = "The transaction spending an unvault output to The Emergency Script."
);
impl RevaultPresignedTransaction for UnvaultEmergencyTransaction {}
impl UnvaultEmergencyTransaction {
    /// The second emergency transaction always spends an unvault output and pays to the Emergency
    /// Script.
    ///
    /// BIP174 Creator and Updater roles.
    pub fn new(
        unvault_input: UnvaultTxIn,
        emer_address: EmergencyAddress,
        lock_time: u32,
    ) -> Result<UnvaultEmergencyTransaction, TransactionCreationError> {
        // First, create a dummy transaction to get its weight without Witness.
        let emer_txo = EmergencyTxOut::new(emer_address.clone(), Amount::from_sat(u64::MAX));
        let dummy_tx = utils::create_psbt(unvault_input.clone(), emer_txo, lock_time)
            .global
            .unsigned_tx;

        // The weight of the Unvault Emergency transaction is the weight of the witness-stripped
        // transaction plus the weight required to satisfy the Unvault txin
        let total_weight = dummy_tx
            .get_weight()
            .checked_add(unvault_input.txout().max_sat_weight())
            .expect("Weight computation bug");
        let total_weight: u64 = total_weight.try_into().expect("usize in u64");
        let fees = EMER_TX_FEERATE
            .checked_mul(total_weight)
            .expect("Weight computation bug");
        assert!(fees < INSANE_FEES);

        assert!(
            total_weight <= MAX_STANDARD_TX_WEIGHT as u64,
            "A single output and a single output"
        );

        // Now, get the emergency output value out of it.
        let deposit_value = unvault_input.txout().txout().value;
        let emer_value = deposit_value
            .checked_sub(fees)
            .expect("We would never create a dust unvault txo");
        assert!(
            emer_value < max_money(Network::Bitcoin),
            "Checked in UnvaultTransaction constructor already"
        );
        let emer_txo = EmergencyTxOut::new(emer_address, Amount::from_sat(emer_value));

        Ok(UnvaultEmergencyTransaction(utils::create_psbt(
            unvault_input,
            emer_txo,
            lock_time,
        )))
    }

    /// Parse an UnvaultEmergency transaction from a PSBT
    pub fn from_raw_psbt(raw_psbt: &[u8]) -> Result<Self, TransactionSerialisationError> {
        let psbt = Decodable::consensus_decode(raw_psbt)?;
        let psbt = utils::psbt_common_sanity_checks(psbt)?;

        // Emergency txo
        let output_count = psbt.global.unsigned_tx.output.len();
        if output_count != 1 {
            return Err(PsbtValidationError::InvalidOutputCount(output_count).into());
        }

        let input_count = psbt.global.unsigned_tx.input.len();
        if psbt.inputs.len() != 1 {
            return Err(PsbtValidationError::InvalidInputCount(input_count).into());
        }

        Ok(UnvaultEmergencyTransaction(psbt))
    }

    /// Get the reference to the Emergency UTXO
    pub fn emergency_outpoint(&self) -> OutPoint {
        // We only ever have a single output, the emergency one.
        OutPoint {
            txid: self.txid(),
            vout: 0,
        }
    }
}
