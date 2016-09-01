
use std::fmt;
use std::fs;
use std::io::prelude::*;
use std::io::{Error, ErrorKind};
use std::io::SeekFrom;
use std::mem;
use std::path::Path;
use byteorder::{ByteOrder, LittleEndian};
use crypt::{decrypt,hash_string};
use compression::decompress;

const ID_MPQ: u32 = 0x1A51504D; // 'MPQ\x1A'
const HEADER_SIZE: usize = 0x44;

const FILE_IMPLODE:     u32 = 0x00000100; // implode method by pkware compression library
const FILE_COMPRESS:    u32 = 0x00000200; // compress methods by multiple methods
const FILE_ENCRYPTED:   u32 = 0x00010000; // file is encrypted
const FILE_PATCH_FILE:  u32 = 0x00100000; // file is a patch file. file data begins with patchinfo struct
const FILE_SINGLE_UNIT: u32 = 0x01000000; // file is stored as single unit

#[derive(Debug)]
struct Header {
    magic: u32,
    header_size: u32,
    archive_size: u32,
    format_version: u16, // 0 = Original, 1 = Extended
    block_size: u16,
    hash_table_offset: u32,
    block_table_offset: u32,
    hash_table_count: u32,
    block_table_count: u32,
    // Header v2
    extended_offset: u64,
    hash_table_offset_high: u16,
    block_table_offset_high: u16,
}

impl Header {
    pub fn new(src: &[u8; HEADER_SIZE]) ->  Result<Header, Error> {
        let magic = LittleEndian::read_u32(src);

        if magic != ID_MPQ {
            return Err(Error::new(ErrorKind::InvalidData, "Not a valid MPQ archive"));
        }

        Ok(Header {
            magic: magic,
            header_size: LittleEndian::read_u32(&src[0x04..]),
            archive_size: LittleEndian::read_u32(&src[0x08..]),
            format_version: LittleEndian::read_u16(&src[0x0C..]),
            block_size: LittleEndian::read_u16(&src[0x0E..]),
            hash_table_offset: LittleEndian::read_u32(&src[0x10..]),
            block_table_offset: LittleEndian::read_u32(&src[0x14..]),
            hash_table_count: LittleEndian::read_u32(&src[0x18..]),
            block_table_count: LittleEndian::read_u32(&src[0x1C..]),
            extended_offset: LittleEndian::read_u64(&src[0x20..]),
            hash_table_offset_high: LittleEndian::read_u16(&src[0x28..]),
            block_table_offset_high: LittleEndian::read_u16(&src[0x2A..]),
        })
    }
}

#[derive(Debug)]
struct Hash {
    /// file name hash part A
    hash_a: u32,
    /// file name hash part B
    hash_b: u32,
    /// language of file using windows LANGID type
    locale: u16,
    /// platform file is used for
    platform: u16,
    /// index into the block table of file
    block_index: u32,
}

impl Hash {
    pub fn new(src: &[u8]) -> Hash {
        Hash {
            hash_a: LittleEndian::read_u32(src),
            hash_b: LittleEndian::read_u32(&src[4..]),
            locale: LittleEndian::read_u16(&src[8..]),
            platform: LittleEndian::read_u16(&src[10..]),
            block_index: LittleEndian::read_u32(&src[12..]),
        }
    }
}

#[derive(Debug)]
struct Block {
    /// offset of the beginning of the file data, relative to the beginning of the archive
    offset: u32,
    /// compressed file size
    packed_size: u32,
    /// uncompressed file size
    unpacked_size: u32,
    /// flags for file
    flags: u32,
}

impl Block {
    pub fn new(src: &[u8]) -> Block {
        Block {
            offset: LittleEndian::read_u32(src),
            packed_size: LittleEndian::read_u32(&src[0x4..]),
            unpacked_size: LittleEndian::read_u32(&src[0x8..]),
            flags: LittleEndian::read_u32(&src[0xC..]),
        }
    }
}

pub struct Archive {
    file: fs::File,
    header: Header,
    hash_table: Vec<Hash>,
    block_table: Vec<Block>,
    block_size: u32, // default size of single file sector
}

impl Archive {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Archive, Error> {
        let mut file = try!(fs::File::open(path));

        let mut buffer:[u8; HEADER_SIZE] = [0; HEADER_SIZE];

        try!(file.read_exact(&mut buffer));

        let header = try!(Header::new(&buffer));

        // read hash table
        let mut hash_buff: Vec<u8> = vec![0; (header.hash_table_count as usize) * mem::size_of::<Hash>()];
        let mut hash_table: Vec<Hash> = Vec::with_capacity(header.hash_table_count as usize);

        try!(file.seek(SeekFrom::Start(header.hash_table_offset as u64)));

        try!(file.read_exact(&mut hash_buff));

        decrypt(&mut hash_buff, hash_string("(hash table)", 0x300));

        for x in 0..header.hash_table_count {
            hash_table.push(Hash::new(&hash_buff[x as usize * mem::size_of::<Hash>()..]));
        }

        // read block table
        let mut block_buff: Vec<u8> = vec![0; (header.block_table_count as usize) * mem::size_of::<Block>()];
        let mut block_table: Vec<Block> = Vec::with_capacity(header.block_table_count as usize);

        try!(file.seek(SeekFrom::Start(header.block_table_offset as u64)));

        try!(file.read_exact(&mut block_buff));

        decrypt(&mut block_buff, hash_string("(block table)", 0x300));

        for x in 0..header.block_table_count {
            block_table.push(Block::new(&block_buff[x as usize * mem::size_of::<Block>()..]));
        }

        let block_size = 512 << header.block_size;

        Ok(Archive {
            file: file,
            header: header,
            hash_table: hash_table,
            block_table: block_table,
            block_size: block_size,
        })
    }

    pub fn open_file(&self, filename: &str) -> Result<File, Error> {
        let start_index = (hash_string(filename, 0x0) & (self.header.hash_table_count - 1)) as usize;
        let mut hash;

        for i in start_index..self.hash_table.len() {
            hash = &self.hash_table[i];

            if hash.hash_a == hash_string(filename, 0x100) && hash.hash_b == hash_string(filename, 0x200) {
                return Ok(File::new(filename, i));
            }
        }

        Err(Error::new(ErrorKind::NotFound, filename))
    }
}

impl fmt::Debug for Archive {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{{\nfile: {:#?},\nheader: {:#?}\nsector_size:{}\n}}" , self.file, self.header, self.block_size)
    }
}

#[derive(Debug)]
pub struct File {
    name: String,
    index: usize,
}

impl File {
    pub fn new(name: &str, index: usize) -> File {
        File {
            name: String::from(name),
            index: index
        }
    }

    pub fn size(&self, archive: &Archive) -> u32 {
        let hash = &archive.hash_table[self.index];
        let block = &archive.block_table[hash.block_index as usize];

        block.unpacked_size
    }

    // read data from file
    pub fn read(&self, archive: &mut Archive, buf: &mut [u8]) -> Result<u32, Error> {
        let hash = &archive.hash_table[self.index];
        let block = &archive.block_table[hash.block_index as usize];

        if block.flags & FILE_PATCH_FILE != 0 {
            return Err(Error::new(ErrorKind::Other, "Patch file not supported"));
        } else if block.flags & FILE_SINGLE_UNIT != 0 { // file is single block file
            return Err(Error::new(ErrorKind::Other, "Single unit file not supported"));
        } else { // read as sector based MPQ file
            try!(self.read_blocks(&mut archive.file, &block, buf));
        }

        Ok(0)
    }

    fn read_blocks(&self, file: &mut fs::File, block: &Block, out_buf: &mut [u8]) -> Result<u64, Error> {
        let mut sector_buff: Vec<u8> = vec![0; 4];
        let mut sector_offsets: Vec<u32> = Vec::new();

        try!(file.seek(SeekFrom::Start(block.offset as u64)));

        loop {
            try!(file.read_exact(&mut sector_buff));

            let offset = LittleEndian::read_u32(&sector_buff);

            if block.packed_size == offset {
                break;
            }

            sector_offsets.push(offset);
        }

        let mut read:u64 = 0;
        for i in 0..sector_offsets.len()-1 {
            let sector_offset = sector_offsets[i];
            let sector_size   = sector_offsets[i+1] - sector_offset;

            let mut in_buff: Vec<u8> = vec![0; sector_size as usize];

            try!(file.seek(SeekFrom::Start(block.offset as u64 + sector_offset as u64)));
            try!(file.read_exact(&mut in_buff));

            if block.flags & FILE_ENCRYPTED != 0 {
                return Err(Error::new(ErrorKind::Other, "Block encryption not supported"));
            }

            if block.flags & FILE_IMPLODE != 0 {
                return Err(Error::new(ErrorKind::Other, "PKware compression not supported"));
            }

            if block.flags & FILE_COMPRESS != 0 {
                let size = try!(decompress(&mut in_buff, &mut out_buf[read as usize..]));

                read += size;
            } else {
                return Err(Error::new(ErrorKind::Other, "Block is not compressed")); // FixMe: should just copy bytes into out_buf
            }

        }

        Ok(read)
    }

    // extract file from archive to the local filesystem
    pub fn extract<P: AsRef<Path>>(&self, archive: &mut Archive, path: P) -> Result<bool, Error> {
        let mut buf: Vec<u8> = vec![0; self.size(&archive) as usize];

        try!(self.read(archive, &mut buf));

        if path.as_ref().exists() {
            return Err(Error::new(ErrorKind::AlreadyExists, "File already exists"));
        }

        let mut file = fs::OpenOptions::new().create(true).write(true).open(&self.name).unwrap();

        try!(file.write(&buf));

        Ok(true)
    }
}
