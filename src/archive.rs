
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

const HEADER_SIZE: usize = 44;
//const USER_HEADER_SIZE: usize = 16;

const ID_MPQA: &'static [u8] = b"MPQ\x1A";
const ID_MPQB: &'static [u8] = b"MPQ\x1B";

const FILE_IMPLODE:     u32 = 0x00000100; // implode method by pkware compression library
const FILE_COMPRESS:    u32 = 0x00000200; // compress methods by multiple methods
const FILE_ENCRYPTED:   u32 = 0x00010000; // file is encrypted
const FILE_PATCH_FILE:  u32 = 0x00100000; // file is a patch file. file data begins with patchinfo struct
const FILE_SINGLE_UNIT: u32 = 0x01000000; // file is stored as single unit

#[derive(Debug)]
struct Header {
    magic: [u8; 4],
    header_size: u32,
    archive_size: u32,
    format_version: u16, // 0 = Original, 1 = Extended
    sector_size_shift: u16,
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
    pub fn new(src: &[u8; HEADER_SIZE]) -> Result<Header, Error> {
        Ok(Header {
            magic: [src[0], src[1], src[2], src[3]],
            header_size: LittleEndian::read_u32(&src[0x04..]),
            archive_size: LittleEndian::read_u32(&src[0x08..]),
            format_version: LittleEndian::read_u16(&src[0x0C..]),
            sector_size_shift: LittleEndian::read_u16(&src[0x0E..]),
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
struct UserDataHeader {
    magic: [u8; 4],
    user_data_size: u32,
    header_offset: u32,
    user_data_header_size: u32,
}

impl UserDataHeader {
    pub fn new(src: &[u8]) -> Result<UserDataHeader, Error> {
        Ok(UserDataHeader {
            magic: [src[0], src[1], src[2], src[3]],
            user_data_size: LittleEndian::read_u32(&src[0x4..]),
            header_offset: LittleEndian::read_u32(&src[0x8..]),
            user_data_header_size: LittleEndian::read_u32(&src[0xC..]),
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
    sector_size: u32,
    offset: u64,
}

impl Archive {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Archive, Error> {
        let mut file = try!(fs::File::open(path));
        let mut buffer:[u8; HEADER_SIZE] = [0; HEADER_SIZE];
        let mut offset:u64 = 0;

        loop  {
            try!(file.seek(SeekFrom::Start(offset)));

            try!(file.read_exact(&mut buffer));

            if buffer.starts_with(&ID_MPQA) {
                break;
            }

            if buffer.starts_with(&ID_MPQB) {

                let user_data_header = try!(UserDataHeader::new(&buffer));

                offset += user_data_header.header_offset as u64;

                try!(file.seek(SeekFrom::Start(offset)));

                try!(file.read_exact(&mut buffer));

                if !buffer.starts_with(&ID_MPQA) {
                    return Err(Error::new(ErrorKind::InvalidData, "Not a valid MPQ archive"));
                }

                break;
            }

            offset += 0x200;
        }

        let header = try!(Header::new(&buffer));

        // read hash table
        let mut hash_buff: Vec<u8> = vec![0; (header.hash_table_count as usize) * mem::size_of::<Hash>()];
        let mut hash_table: Vec<Hash> = Vec::with_capacity(header.hash_table_count as usize);

        try!(file.seek(SeekFrom::Start(header.hash_table_offset as u64 + offset)));

        try!(file.read_exact(&mut hash_buff));

        decrypt(&mut hash_buff, hash_string("(hash table)", 0x300));

        for x in 0..header.hash_table_count {
            hash_table.push(Hash::new(&hash_buff[x as usize * mem::size_of::<Hash>()..]));
        }

        // read block table
        let mut block_buff: Vec<u8> = vec![0; (header.block_table_count as usize) * mem::size_of::<Block>()];
        let mut block_table: Vec<Block> = Vec::with_capacity(header.block_table_count as usize);

        try!(file.seek(SeekFrom::Start(header.block_table_offset as u64 + offset)));

        try!(file.read_exact(&mut block_buff));

        decrypt(&mut block_buff, hash_string("(block table)", 0x300));

        for x in 0..header.block_table_count {
            block_table.push(Block::new(&block_buff[x as usize * mem::size_of::<Block>()..]));
        }

        let sector_size = 512 << header.sector_size_shift;

        Ok(Archive {
            file: file,
            header: header,
            hash_table: hash_table,
            block_table: block_table,
            sector_size: sector_size,
            offset: offset
        })
    }

    pub fn open_file(&self, filename: &str) -> Result<File, Error> {
        let start_index = (hash_string(filename, 0x0) & (self.header.hash_table_count - 1)) as usize;
        let mut hash;

        let hash_a = hash_string(filename, 0x100);
        let hash_b = hash_string(filename, 0x200);

        for i in start_index..self.hash_table.len() {
            hash = &self.hash_table[i];

            if hash.hash_a == hash_a && hash.hash_b == hash_b {
                return Ok(File::new(filename, i));
            }
        }

        Err(Error::new(ErrorKind::NotFound, filename))
    }
}

impl fmt::Debug for Archive {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{{\nfile: {:#?},\nheader: {:#?}\nsector_size:{}\n}}" , self.file, self.header, self.sector_size)
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
    pub fn read(&self, archive: &mut Archive, buf: &mut [u8]) -> Result<u64, Error> {
        let hash = &archive.hash_table[self.index];
        let block = &archive.block_table[hash.block_index as usize];

        if block.flags & FILE_PATCH_FILE != 0 {
            return Err(Error::new(ErrorKind::Other, "Patch file not supported"));
        } else if block.flags & FILE_SINGLE_UNIT != 0 { // file is single block file
            return self.read_block(block.packed_size as usize, &mut archive.file, archive.offset, &block, buf);
        } else { // read as sector based MPQ file
            return self.read_blocks(&mut archive.file, archive.offset, &block, buf, archive.sector_size);
        }
    }

    fn read_blocks(&self, file: &mut fs::File, offset: u64, block: &Block, out_buf: &mut [u8], sector_size: u32) -> Result<u64, Error> {
        let mut sector_buff: Vec<u8> = vec![0; 4];
        let mut sector_offsets: Vec<u32> = Vec::new();

        try!(file.seek(SeekFrom::Start(block.offset as u64 + offset)));

        let num_sectors = (block.unpacked_size / sector_size) + 1;

        for _ in 0..num_sectors + 1 {
            try!(file.read_exact(&mut sector_buff));

            sector_offsets.push(LittleEndian::read_u32(&sector_buff));
        }

        let mut read:u64 = 0;
        for i in 0..sector_offsets.len()-1 {
            let sector_offset = sector_offsets[i];
            let sector_size   = sector_offsets[i+1] - sector_offset;

            read += try!(self.read_block(sector_size as usize, file, sector_offset as u64, block, &mut out_buf[read as usize..]));
        }

        Ok(read)
    }

    fn read_block(&self, buff_size: usize, file: &mut fs::File, offset: u64, block: &Block, out_buf: &mut [u8]) -> Result<u64, Error> {
        let mut in_buff: Vec<u8> = vec![0; buff_size];

        try!(file.seek(SeekFrom::Start(block.offset as u64 + offset)));

        try!(file.read_exact(&mut in_buff));

        if block.flags & FILE_ENCRYPTED != 0 {
            return Err(Error::new(ErrorKind::Other, "Block encryption not supported"));
        }

        if block.flags & FILE_IMPLODE != 0 {
            return Err(Error::new(ErrorKind::Other, "PKware compression not supported"));
        }

        if block.flags & FILE_COMPRESS != 0 {
            return decompress(&mut in_buff, out_buf);
        } else {
            for (dst, src) in out_buf.iter_mut().zip(&in_buff) {
                *dst = *src
            }

            return Ok(block.unpacked_size as u64)
        }
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
