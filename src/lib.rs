//! A library for reading MPQ archives

extern crate adler32;
extern crate byteorder;
extern crate bzip2;
extern crate flate2;

mod archive;
mod crypt;
mod chain;
mod compression;

pub use archive::{Archive,File};
pub use chain::Chain;
