# Fetch the corpus from https://github.com/revault/revault_tx_corpus and run the targets on it
# Meant to be ran by CI
#!/usr/bin/env sh

cd corpus && git clone https://github.com/revault/revault_tx_corpus

cargo install --git https://github.com/darosior/cargo-fuzz --branch no_cfg
for target in $(ls fuzz/fuzz_targets);do
    cargo +nightly fuzz run --no-cfg-fuzzing -O -a "${target%.*}" -- -runs=1000 -max_len=500000
done
