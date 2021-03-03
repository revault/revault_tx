# `revault_tx` fuzzing

## How to

We have a basic integration of fuzzing using [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz).  
For basic usage and documentation see [the Rust fuzz book](https://rust-fuzz.github.io/book/cargo-fuzz.html).  
Note that using `nightly` is required for running the targets.

```shell
# Run a specific target with `cargo fuzz run <target name>`
cargo +nightly fuzz run parse_cancel
# You can pass any libfuzzer flag, see the available ones with
cargo +nightly fuzz run parse_cancel -- -help=1
# For example to run the target only once on each corpus with an increased length
cargo +nightly fuzz run parse_cancel -- -runs=0 -max_len=200000
```

## Corpus storage and new seed generation

We for now store the corpora at https://github.com/revault/revault_tx_corpus. Coverage-increasing seeds
are very welcome to be contributed there, just be sure to minimize the corpus beforehand:
```shell
cargo +nightly fuzz cmin <target name>
```

## More about fuzz testing and libFuzzer

- [Intro to fuzzing](https://github.com/google/fuzzing/blob/master/docs/intro-to-fuzzing.md)
- [What makes a good fuzz target](https://github.com/google/fuzzing/blob/master/docs/good-fuzz-target.md)
- [libFuzzer documentation](https://www.llvm.org/docs/LibFuzzer.html)
