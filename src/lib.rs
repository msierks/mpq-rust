//! A library for reading MPQ archives

#![cfg_attr(feature="cargo-clippy", allow(unreadable_literal))]

extern crate adler32;
extern crate byteorder;
extern crate bzip2;
extern crate flate2;
extern crate implode;

mod archive;
mod crypt;
mod chain;
mod compression;

pub use archive::{Archive,File};
pub use chain::Chain;
