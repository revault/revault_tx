use crate::{
    error::*,
    scripts::*,
    transactions::{
        utils, RevaultTransaction, EMER_TX_FEERATE, INSANE_FEES, MAX_STANDARD_TX_WEIGHT, TX_VERSION,
    },
    txins::*,
    txouts::*,
};

use miniscript::bitcoin::{
    blockdata::constants::max_money,
    consensus::encode::Decodable,
    secp256k1,
    util::psbt::{
        Global as PsbtGlobal, Input as PsbtIn, Output as PsbtOut,
        PartiallySignedTransaction as Psbt,
    },
    Amount, Network, OutPoint, SigHashType, Transaction,
};

#[cfg(feature = "use-serde")]
use {
    serde::de::{self, Deserialize, Deserializer},
    serde::ser::{Serialize, Serializer},
};

use std::{collections::BTreeMap, convert::TryInto};

impl_revault_transaction!(
    EmergencyTransaction,
    doc = "The transaction spending a deposit output to The Emergency Script."
);
impl EmergencyTransaction {
    // Internal DRY routine for creating the inner PSBT
    fn create_psbt(
        deposit_txin: DepositTxIn,
        emergency_txo: EmergencyTxOut,
        lock_time: u32,
    ) -> Psbt {
        let txins = vec![deposit_txin.unsigned_txin()];
        let psbtins = vec![PsbtIn {
            witness_script: Some(deposit_txin.txout().witness_script().clone()),
            bip32_derivation: deposit_txin.txout().bip32_derivation().clone(),
            sighash_type: Some(SigHashType::All),
            witness_utxo: Some(deposit_txin.into_txout().into_txout()),
            ..PsbtIn::default()
        }];

        Psbt {
            global: PsbtGlobal {
                unsigned_tx: Transaction {
                    version: TX_VERSION,
                    lock_time,
                    input: txins,
                    output: vec![emergency_txo.into_txout()],
                },
                version: 0,
                xpub: BTreeMap::new(),
                proprietary: BTreeMap::new(),
                unknown: BTreeMap::new(),
            },
            inputs: psbtins,
            // Deposit txout
            outputs: vec![PsbtOut::default()],
        }
    }

    /// The first emergency transaction always spends a deposit output and pays to the Emergency
    /// Script.
    /// Will error **only** when trying to spend a dust deposit.
    ///
    /// BIP174 Creator and Updater roles.
    pub fn new(
        deposit_input: DepositTxIn,
        emer_address: EmergencyAddress,
        lock_time: u32,
    ) -> Result<EmergencyTransaction, TransactionCreationError> {
        // First, create a dummy transaction to get its weight without Witness.
        let emer_txo = EmergencyTxOut::new(emer_address.clone(), Amount::from_sat(u64::MAX));
        let dummy_tx =
            EmergencyTransaction::create_psbt(deposit_input.clone(), emer_txo, lock_time)
                .global
                .unsigned_tx;

        // The weight of the Emergency transaction is the weight of the witness-stripped transaction
        // plus the weight required to satisfy the Deposit txin
        let total_weight = dummy_tx
            .get_weight()
            .checked_add(deposit_input.txout().max_sat_weight())
            .expect("Weight computation bug");
        let total_weight: u64 = total_weight.try_into().expect("usize in u64");
        let fees = EMER_TX_FEERATE
            .checked_mul(total_weight)
            .expect("Weight computation bug");
        assert!(fees < INSANE_FEES);

        assert!(
            total_weight <= MAX_STANDARD_TX_WEIGHT as u64,
            "Single input and single output"
        );

        // Now, get the emergency output value out of it.
        let deposit_value = deposit_input.txout().txout().value;
        let emer_value = deposit_value
            .checked_sub(fees)
            .ok_or(TransactionCreationError::Dust)?;
        // The emer output is the single one
        if emer_value > max_money(Network::Bitcoin) {
            return Err(TransactionCreationError::InsaneAmounts);
        }
        let emer_txo = EmergencyTxOut::new(emer_address, Amount::from_sat(emer_value));

        Ok(EmergencyTransaction(EmergencyTransaction::create_psbt(
            deposit_input,
            emer_txo,
            lock_time,
        )))
    }

    /// Parse an Emergency transaction from a PSBT
    pub fn from_raw_psbt(raw_psbt: &[u8]) -> Result<Self, TransactionSerialisationError> {
        let psbt = Decodable::consensus_decode(raw_psbt)?;
        let psbt = utils::psbt_common_sanity_checks(psbt)?;

        // Emergency txo
        let output_count = psbt.global.unsigned_tx.output.len();
        if output_count != 1 {
            return Err(PsbtValidationError::InvalidOutputCount(output_count).into());
        }

        if psbt.inputs.len() != 1 {
            return Err(PsbtValidationError::InvalidInputCount(psbt.inputs.len()).into());
        }
        utils::check_revocationtx_input(&psbt.inputs[0])?;

        Ok(EmergencyTransaction(psbt))
    }

    /// Add a signature for the input spending the Deposit transaction
    pub fn add_sig<C: secp256k1::Verification>(
        &mut self,
        pubkey: secp256k1::PublicKey,
        signature: secp256k1::Signature,
        secp: &secp256k1::Secp256k1<C>,
    ) -> Result<Option<Vec<u8>>, InputSatisfactionError> {
        assert_eq!(
            self.psbt().inputs.len(),
            1,
            "We are always created with a (single) P2WSH input"
        );
        RevaultTransaction::add_signature(self, 0, pubkey, signature, secp)
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
