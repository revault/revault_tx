use crate::{
    error::*,
    scripts::*,
    transactions::{
        utils, RevaultTransaction, CANCEL_TX_FEERATE, INSANE_FEES, MAX_STANDARD_TX_WEIGHT,
        TX_VERSION,
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
    CancelTransaction,
    doc = "The transaction \"revaulting\" a spend attempt, i.e. spending the unvaulting transaction back to a deposit txo."
);
impl CancelTransaction {
    // Internal DRY routine for creating the inner PSBT
    fn create_psbt(unvault_txin: UnvaultTxIn, deposit_txo: DepositTxOut, lock_time: u32) -> Psbt {
        let txins = vec![unvault_txin.unsigned_txin()];
        let psbtins = vec![PsbtIn {
            witness_script: Some(unvault_txin.txout().witness_script().clone()),
            bip32_derivation: unvault_txin.txout().bip32_derivation().clone(),
            sighash_type: Some(SigHashType::All),
            witness_utxo: Some(unvault_txin.into_txout().into_txout()),
            ..PsbtIn::default()
        }];

        Psbt {
            inputs: psbtins,
            // Deposit txout
            outputs: vec![PsbtOut {
                bip32_derivation: deposit_txo.bip32_derivation().clone(),
                ..PsbtOut::default()
            }],
            global: PsbtGlobal {
                unsigned_tx: Transaction {
                    version: TX_VERSION,
                    lock_time,
                    input: txins,
                    output: vec![deposit_txo.into_txout()],
                },
                version: 0,
                xpub: BTreeMap::new(),
                proprietary: BTreeMap::new(),
                unknown: BTreeMap::new(),
            },
        }
    }

    /// A Cancel transaction always pays to a Deposit output and spends the Unvault output.
    ///
    /// BIP174 Creator and Updater roles.
    pub fn new(
        unvault_input: UnvaultTxIn,
        deposit_descriptor: &DerivedDepositDescriptor,
        lock_time: u32,
    ) -> Result<CancelTransaction, TransactionCreationError> {
        // First, create a dummy transaction to get its weight without Witness.
        let dummy_deposit_txo = DepositTxOut::new(Amount::from_sat(u64::MAX), deposit_descriptor);
        let dummy_tx =
            CancelTransaction::create_psbt(unvault_input.clone(), dummy_deposit_txo, lock_time)
                .global
                .unsigned_tx;

        // The weight of the cancel transaction is the weight of the witness-stripped transaction
        // plus the weight required to satisfy the Unvault txin
        let total_weight = dummy_tx
            .get_weight()
            .checked_add(unvault_input.txout().max_sat_weight())
            .expect("Properly computed weight won't overflow");
        let total_weight: u64 = total_weight.try_into().expect("usize in u64");
        let fees = CANCEL_TX_FEERATE
            .checked_mul(total_weight)
            .expect("Properly computed weight won't overflow");
        assert!(fees < INSANE_FEES);

        assert!(
            total_weight <= MAX_STANDARD_TX_WEIGHT as u64,
            "Single input and single output"
        );

        // Now, get the revaulting output value out of it.
        let unvault_value = unvault_input.txout().txout().value;
        let revault_value = unvault_value
            .checked_sub(fees)
            .expect("We would not create a dust unvault txo");
        assert!(
            revault_value < max_money(Network::Bitcoin),
            "Checked in UnvaultTransaction constructor already"
        );
        let deposit_txo = DepositTxOut::new(Amount::from_sat(revault_value), deposit_descriptor);

        Ok(CancelTransaction(CancelTransaction::create_psbt(
            unvault_input,
            deposit_txo,
            lock_time,
        )))
    }

    /// Parse a Cancel transaction from a PSBT
    pub fn from_raw_psbt(raw_psbt: &[u8]) -> Result<Self, TransactionSerialisationError> {
        let psbt = Decodable::consensus_decode(raw_psbt)?;
        let psbt = utils::psbt_common_sanity_checks(psbt)?;

        // Deposit txo
        let output_count = psbt.global.unsigned_tx.output.len();
        if output_count != 1 {
            return Err(PsbtValidationError::InvalidOutputCount(output_count).into());
        }

        for output in psbt.outputs.iter() {
            if output.bip32_derivation.is_empty() {
                return Err(PsbtValidationError::InvalidOutputField(output.clone()).into());
            }
        }

        // Deposit txo is P2WSH
        let output = &psbt.outputs[0];
        if output.redeem_script.is_some() {
            return Err(PsbtValidationError::InvalidOutputField(output.clone()).into());
        }

        if psbt.inputs.len() != 1 {
            return Err(PsbtValidationError::InvalidInputCount(psbt.inputs.len()).into());
        }

        Ok(CancelTransaction(psbt))
    }

    /// Add a signature for the input spending the Unvault transaction
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

    /// Get the Deposit txo to be referenced by the Unvault / Emergency txs
    pub fn deposit_txin(&self, deposit_descriptor: &DerivedDepositDescriptor) -> DepositTxIn {
        // We only have a single output, the deposit output.
        let txo = &self.tx().output[0];
        let prev_txout = DepositTxOut::new(Amount::from_sat(txo.value), deposit_descriptor);

        DepositTxIn::new(
            OutPoint {
                txid: self.txid(),
                vout: 0,
            },
            prev_txout,
        )
    }
}
