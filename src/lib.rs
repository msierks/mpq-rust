//! A library for reading MPQ archives

extern crate byteorder;
extern crate bzip2;
extern crate flate2;

mod archive;
mod crypt;
mod compression;

pub use archive::{Archive,File};
