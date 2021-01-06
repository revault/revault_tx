set -ex

rustup update nightly

if ! command -v grcov &>/dev/null; then
    cargo install grcov
fi

cargo clean
CARGO_INCREMENTAL=0 RUSTFLAGS="-Zprofile -Ccodegen-units=1 -Copt-level=0 -Cinline-threshold=0 -Clink-dead-code -Coverflow-checks=off -Cpanic=abort -Zpanic_abort_tests" RUSTDOCFLAGS="$RUSTFLAGS" cargo +nightly test --all-features
grcov ./target/debug/ --source-dir . -t html --branch --ignore-not-existing --llvm -o ./target/grcov/
firefox target/grcov/index.html

set +ex
