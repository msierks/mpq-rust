# mpq-rust [![Build Status](https://travis-ci.org/msierks/mpq-rust.svg?branch=master)](https://travis-ci.org/msierks/mpq-rust) [![Documentation](https://docs.rs/mpq/badge.svg)](https://docs.rs/mpq)

A library for reading MPQ archives.

```toml
# Cargo.toml
[dependencies]
mpq = "0.6"
```

## Reading an archive

```rust,no_run
extern crate mpq;

use std::str;
use mpq::Archive;

fn main() {
    let mut a = Archive::open("common.MPQ").unwrap();
    let file = a.open_file("(listfile)").unwrap();

    let mut buf: Vec<u8> = vec![0; file.size(&a) as usize];

    file.read(&mut a, &mut buf).unwrap();

    print!("{}", str::from_utf8(&buf).unwrap());
}
```

## CLI

### Build

```sh
git clone https://github.com/msierks/mpq-rust.git && cd mpq-rust && cargo build --release
```

### Run

print '(listfile)' contents:
```sh
target/release/mpq -l common.MPQ
```

extract file:
```
target/release/mpq -x "(listfile)" common.MPQ
```

More help:
```
target/release/mpq -h
```

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any 
additional terms or conditions.
