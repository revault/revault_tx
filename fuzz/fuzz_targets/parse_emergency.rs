#![no_main]
use libfuzzer_sys::fuzz_target;

use revault_tx::{
    miniscript::bitcoin::{
        secp256k1::{Signature, SECP256K1},
        PublicKey, SigHashType,
    },
    transactions::{EmergencyTransaction, RevaultTransaction},
};

use std::str::FromStr;

fuzz_target!(|data: &[u8]| {
    if let Ok(mut tx) = EmergencyTransaction::from_psbt_serialized(data) {
        // We can serialize it back
        tx.as_psbt_serialized();

        // We can network serialize it (without witness data)
        tx.clone().into_bitcoin_serialized();

        let dummykey = PublicKey::from_str(
            "02ca06be8e497d578314c77ca735aa5fcca76d8a5b04019b7a80ff0baaf4a6cf46",
        )
        .unwrap();
        let dummy_sig = Signature::from_str("3045022100e6ffa6cc76339944fa428bcd058a27d0e660d0554a418a79620d7e14cda4cbde022045ba1bcec9fbbdcb4b70328dc7efae7ee59ff496aa8139c81a10b898911b8b52").unwrap();

        let unvault_in_index = tx
            .inner_tx()
            .inputs
            .iter()
            .position(|i| i.witness_utxo.as_ref().unwrap().script_pubkey.is_v0_p2wsh())
            .unwrap();

        if !tx.is_finalized() {
            // We can compute the sighash for the unvault input
            tx.signature_hash_internal_input(unvault_in_index, SigHashType::AllPlusAnyoneCanPay)
                .expect("Must be in bound as it was parsed!");
            // We can add a signature
            tx.add_signature(0, dummykey, (dummy_sig, SigHashType::AllPlusAnyoneCanPay))
                .expect("This does not check the signature");
        } else {
            // But not if it's final
            tx.signature_hash_internal_input(unvault_in_index, SigHashType::AllPlusAnyoneCanPay)
                .expect_err("Already final");
            tx.add_signature(
                unvault_in_index,
                dummykey,
                (dummy_sig, SigHashType::AllPlusAnyoneCanPay),
            )
            .expect_err("Already final");
        }

        if tx.inner_tx().global.unsigned_tx.input.len() > 1 {
            let fb_in_index = tx
                .inner_tx()
                .inputs
                .iter()
                .position(|i| {
                    i.witness_utxo
                        .as_ref()
                        .unwrap()
                        .script_pubkey
                        .is_v0_p2wpkh()
                })
                .unwrap();

            tx.add_signature(
                fb_in_index,
                dummykey,
                (dummy_sig, SigHashType::AllPlusAnyoneCanPay),
            )
            .expect_err("Invalid sighash");
            if !tx.is_finalized() {
                tx.add_signature(fb_in_index, dummykey, (dummy_sig, SigHashType::All))
                    .expect("This does not check the signature");
            } else {
                tx.add_signature(fb_in_index, dummykey, (dummy_sig, SigHashType::All))
                    .expect_err("Already final");
            }
        } else {
            tx.add_signature(1, dummykey, (dummy_sig, SigHashType::All))
                .expect_err("Out of bounds");
        }

        // And verify the input without crashing (will likely fail though)
        #[allow(unused_must_use)]
        tx.verify_input(0);

        // Same for the finalization
        #[allow(unused_must_use)]
        tx.finalize(&SECP256K1);
    }
});
