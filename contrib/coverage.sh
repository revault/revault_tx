set -ex

if ! command -v grcov &>/dev/null; then
    cargo install grcov
fi

cargo clean

LLVM_PROFILE_FILE="revault_tx_coverage_%m.profraw" RUSTFLAGS="-Zinstrument-coverage" RUSTDOCFLAGS="$RUSTFLAGS -Z unstable-options --persist-doctests target/debug/doctestbins" cargo +nightly build --all-features
LLVM_PROFILE_FILE="revault_tx_coverage_%m.profraw" RUSTFLAGS="-Zinstrument-coverage" RUSTDOCFLAGS="$RUSTFLAGS -Z unstable-options --persist-doctests target/debug/doctestbins" cargo +nightly test --all-features

grcov . --binary-path ./target/debug/ -t html --branch --ignore-not-existing --llvm -o ./target/grcov/
firefox target/grcov/index.html

set +ex
