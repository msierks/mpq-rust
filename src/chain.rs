use crate::archive::Archive;
use std::io::{Error, ErrorKind};
use std::path::Path;
use std::collections::HashSet;

#[derive(Default)]
pub struct Chain {
    chain: Vec<Archive>,
}

impl Chain {
    pub fn new() -> Self {
        Chain { chain: Vec::new() }
    }

    pub fn size(&self) -> usize {
        self.chain.len()
    }

    pub fn add<P: AsRef<Path>>(&mut self, path: P) -> Result<(), Error> {
        match Archive::open(path) {
            Ok(v) => self.chain.insert(0, v),
            Err(e) => return Err(e),
        }

        Ok(())
    }

    pub fn read(&mut self, filename: &str) -> Result<Vec<u8>, Error> {
        for mut archive in &mut self.chain.iter_mut() {
            if let Ok(file) = archive.open_file(filename) {
                let mut buf: Vec<u8> = vec![0; file.size() as usize];

                match file.read(&mut archive, &mut buf) {
                    Ok(_) => {}
                    Err(e) => {
                        println!("{} {:#?}", e, archive);
                    }
                }

                return Ok(buf);
            }
        }

        Err(Error::new(
            ErrorKind::NotFound,
            "File not found in mpq chain",
        ))
    }

    pub fn list(&mut self) -> Result<Vec<String>, Error> {
        let mut contents: HashSet<String> = HashSet::new();

        for mut archive in &mut self.chain.iter_mut() {
            if let Ok(file) = archive.open_file("(listfile)") {
                let mut buf: Vec<u8> = vec![0; file.size() as usize];

                match file.read(&mut archive, &mut buf) {
                    Ok(_) => {}
                    Err(e) => return Err(e),
                };

                let archive_string = match String::from_utf8(buf) {
                    Ok(v) => v,
                    Err(_) => return Err(Error::new(ErrorKind::InvalidData, "Utf8Error")),
                };

                contents.extend(
                    archive_string
                        .lines()
                        .map(String::from)
                        .collect::<Vec<String>>(),
                );
            }
        }

        Ok(contents.into_iter().collect::<Vec<String>>())
    }

    pub fn read_to_string(&mut self, filename: &str) -> Result<String, Error> {
        match self.read(filename) {
            Ok(buf) => match String::from_utf8(buf) {
                Ok(v) => Ok(v),
                Err(_) => Err(Error::new(ErrorKind::InvalidData, "Utf8Error")),
            },
            Err(e) => Err(e),
        }
    }

    // extract file from archive to the local filesystem
    pub fn extract<P: AsRef<Path>>(&mut self, filename: &str, path: P) -> Result<usize, Error> {
        for mut archive in &mut self.chain.iter_mut() {
            let file = match archive.open_file(filename) {
                Ok(f) => f,
                Err(_) => continue
            };

            return file.extract(archive, path);
        }

        Err(Error::new(
            ErrorKind::NotFound,
            "File not found in mpq chain",
        ))
    }
}
