# Generate a source-based code coverage from the unit tests, then an HTML report using
# grcov, and start it with Firefox.
# https://rustc-dev-guide.rust-lang.org/llvm-coverage-instrumentation.html
# https://github.com/mozilla/grcov

set -ex

if ! command -v grcov &>/dev/null; then
    cargo +nightly install grcov
fi

rustup +nightly component add llvm-tools-preview

mkdir -p ./target/grcov/

cargo clean

RUSTUP_TOOLCHAIN=nightly LLVM_PROFILE_FILE="$PWD/target/grcov/revault_tx_coverage_%m.profraw" RUSTFLAGS="-Zinstrument-coverage" RUSTDOCFLAGS="$RUSTFLAGS -Z unstable-options --persist-doctests target/debug/doctestbins" cargo +nightly build --all-features
RUSTUP_TOOLCHAIN=nightly LLVM_PROFILE_FILE="$PWD/target/grcov/revault_tx_coverage_%m.profraw" cargo +nightly test --all-features

RUSTUP_TOOLCHAIN=nightly grcov ./target/grcov/ --source-dir ./ --binary-path ./target/debug/ -t html --branch --ignore-not-existing --llvm -o ./target/grcov/
firefox target/grcov/index.html

rm ./target/grcov/*.profraw

set +ex
