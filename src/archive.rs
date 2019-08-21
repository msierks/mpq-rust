use crate::compression::*;
use crate::crypt::{decrypt, hash_string};
use adler32::RollingAdler32;
use byteorder::{ByteOrder, LittleEndian};
use std::fmt;
use std::fs;
use std::io::prelude::*;
use std::io::SeekFrom;
use std::io::{Error, ErrorKind};
use std::mem;
use std::path::Path;

const HEADER_SIZE_V1: usize = 0x20;
//const HEADER_SIZE_V2: usize = 0x2C;
//const HEADER_SIZE_V3: usize = 0x44;
//const HEADER_SIZE_V4: usize = 0xD0;
const USER_HEADER_SIZE: usize = 16;

const ID_MPQA: &[u8] = b"MPQ\x1A";
const ID_MPQB: &[u8] = b"MPQ\x1B";

const FILE_IMPLODE: u32 = 0x00000100; // implode method by pkware compression library
const FILE_COMPRESS: u32 = 0x00000200; // compress methods by multiple methods
const FILE_ENCRYPTED: u32 = 0x00010000; // file is encrypted
const FILE_FIX_KEY: u32 = 0x00020000; // file decryption key is altered according to position of file in archive
const FILE_PATCH_FILE: u32 = 0x00100000; // file is a patch file. file data begins with patchinfo struct
const FILE_SINGLE_UNIT: u32 = 0x01000000; // file is stored as single unit
const FILE_SECTOR_CRC: u32 = 0x04000000;
const FILE_COMPRESS_MASK: u32 = 0x0000FF00;

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
    // ToDo: Header v3 and v4
}

impl Header {
    pub fn new(src: &[u8; HEADER_SIZE_V1]) -> Header {
        Header {
            magic: [src[0], src[1], src[2], src[3]],
            header_size: LittleEndian::read_u32(&src[0x04..]),
            archive_size: LittleEndian::read_u32(&src[0x08..]),
            format_version: LittleEndian::read_u16(&src[0x0C..]),
            sector_size_shift: LittleEndian::read_u16(&src[0x0E..]),
            hash_table_offset: LittleEndian::read_u32(&src[0x10..]),
            block_table_offset: LittleEndian::read_u32(&src[0x14..]),
            hash_table_count: LittleEndian::read_u32(&src[0x18..]),
            block_table_count: LittleEndian::read_u32(&src[0x1C..]),
            extended_offset: 0,
            hash_table_offset_high: 0,
            block_table_offset_high: 0,
        }
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
    pub fn new(src: &[u8]) -> UserDataHeader {
        UserDataHeader {
            magic: [src[0], src[1], src[2], src[3]],
            user_data_size: LittleEndian::read_u32(&src[0x4..]),
            header_offset: LittleEndian::read_u32(&src[0x8..]),
            user_data_header_size: LittleEndian::read_u32(&src[0xC..]),
        }
    }
}

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
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
    user_data_header: Option<UserDataHeader>,
    hash_table: Vec<Hash>,
    block_table: Vec<Block>,
    sector_size: u32,
    offset: u64,
}

impl Archive {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Archive, Error> {
        let mut file = fs::File::open(path)?;
        let mut buffer: [u8; HEADER_SIZE_V1] = [0; HEADER_SIZE_V1];
        let mut offset: u64 = 0;
        let mut user_data_header = None;

        loop {
            file.seek(SeekFrom::Start(offset))?;

            file.read_exact(&mut buffer)?;

            if buffer.starts_with(ID_MPQA) {
                break;
            }

            if buffer.starts_with(ID_MPQB) {
                let header = UserDataHeader::new(&buffer);

                offset += u64::from(header.header_offset);

                file.seek(SeekFrom::Start(offset))?;

                file.read_exact(&mut buffer)?;

                if !buffer.starts_with(ID_MPQA) {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "Not a valid MPQ archive",
                    ));
                }

                user_data_header = Some(header);

                break;
            }

            offset += 0x200;
        }

        let header = Header::new(&buffer);

        // read hash table
        let mut hash_buff: Vec<u8> =
            vec![0; (header.hash_table_count as usize) * mem::size_of::<Hash>()];
        let mut hash_table: Vec<Hash> = Vec::with_capacity(header.hash_table_count as usize);

        file.seek(SeekFrom::Start(
            u64::from(header.hash_table_offset) + offset,
        ))?;

        file.read_exact(&mut hash_buff)?;

        decrypt(&mut hash_buff, hash_string("(hash table)", 0x300));

        for x in 0..header.hash_table_count {
            hash_table.push(Hash::new(&hash_buff[x as usize * mem::size_of::<Hash>()..]));
        }

        // read block table
        let mut block_buff: Vec<u8> =
            vec![0; (header.block_table_count as usize) * mem::size_of::<Block>()];
        let mut block_table: Vec<Block> = Vec::with_capacity(header.block_table_count as usize);

        file.seek(SeekFrom::Start(
            u64::from(header.block_table_offset) + offset,
        ))?;

        file.read_exact(&mut block_buff)?;

        decrypt(&mut block_buff, hash_string("(block table)", 0x300));

        for x in 0..header.block_table_count {
            block_table.push(Block::new(
                &block_buff[x as usize * mem::size_of::<Block>()..],
            ));
        }

        let sector_size = 512 << header.sector_size_shift;

        Ok(Archive {
            file,
            header,
            user_data_header,
            hash_table,
            block_table,
            sector_size,
            offset,
        })
    }

    pub fn open_file(&mut self, filename: &str) -> Result<File, Error> {
        let start_index =
            (hash_string(filename, 0x0) & (self.header.hash_table_count - 1)) as usize;
        let mut hash;

        let hash_a = hash_string(filename, 0x100);
        let hash_b = hash_string(filename, 0x200);
        let mut file_key = 0;

        for i in start_index..self.hash_table.len() {
            hash = &self.hash_table[i];

            if hash.hash_a == hash_a && hash.hash_b == hash_b {
                let block = &self.block_table[hash.block_index as usize];
                let mut sector_offsets: Vec<u32> = Vec::new();
                let mut sector_checksums: Vec<u32> = Vec::new();

                // file if encrypted, generate decryption key
                if block.flags & FILE_ENCRYPTED != 0 {
                    match filename.split(&['\\', '/'][..]).last() {
                        Some(basename) => file_key = hash_string(basename, 0x300),
                        None => {
                            return Err(Error::new(
                                ErrorKind::Other,
                                "Unable to extract filename from path",
                            ));
                        }
                    }

                    // fix decryption key
                    if block.flags & FILE_FIX_KEY != 0 {
                        file_key = (file_key + (block.offset as u32)) ^ block.unpacked_size;
                    }
                }

                // block split into sectors, read sector offsets
                if block.flags & FILE_SINGLE_UNIT == 0 {
                    // FixMe: handle empty files, packed and unpacked size should be 0

                    let num_sectors = ((block.unpacked_size - 1) / self.sector_size) + 1;

                    let mut sector_buff: Vec<u8> = vec![0; ((num_sectors as usize) + 1) * 4];

                    self.file
                        .seek(SeekFrom::Start(u64::from(block.offset) + self.offset))?;
                    self.file.read_exact(&mut sector_buff)?;

                    if block.flags & FILE_ENCRYPTED != 0 {
                        decrypt(&mut sector_buff, file_key - 1);
                    }

                    let mut x = 0;
                    while x < sector_buff.len() - 3 {
                        sector_offsets.push(LittleEndian::read_u32(&sector_buff[x..]));
                        x += 4;
                    }

                    // load sector checksums
                    if block.flags & FILE_COMPRESS != 0 && block.flags & FILE_SECTOR_CRC != 0 {
                        let mut buff: Vec<u8> = vec![0; 4];

                        self.file.read_exact(&mut buff)?;

                        let last_offset = LittleEndian::read_u32(&buff);
                        let checksum_offset = sector_offsets[num_sectors as usize];
                        let sector_size = last_offset - checksum_offset;
                        let expected_size = num_sectors * mem::size_of::<u32>() as u32;

                        // is checksum sector the expected size
                        if sector_size == expected_size {
                            self.file.seek(SeekFrom::Start(
                                u64::from(block.offset) + u64::from(checksum_offset),
                            ))?;

                            for _ in 0..num_sectors {
                                self.file.read_exact(&mut buff)?;

                                sector_checksums.push(LittleEndian::read_u32(&buff));
                            }
                        }
                    }
                }

                return Ok(File {
                    name: String::from(filename),
                    hash: hash.clone(),
                    block: block.clone(),
                    sector_offsets,
                    sector_checksums,
                    file_key,
                });
            }
        }

        Err(Error::new(ErrorKind::NotFound, filename))
    }

    pub fn read_user_data(&mut self) -> Result<Option<Vec<u8>>, Error> {
        match self.user_data_header {
            Some(ref header) => {
                let mut buf: Vec<u8> = vec![0; header.user_data_size as usize];

                self.file.seek(SeekFrom::Start(USER_HEADER_SIZE as u64))?;
                self.file.read_exact(&mut buf)?;

                Ok(Some(buf))
            }
            None => Ok(None),
        }
    }
}

impl fmt::Debug for Archive {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{{\nfile: {:#?},\nheader: {:#?}\nsector_size:{}\n}}",
            self.file, self.header, self.sector_size
        )
    }
}

#[derive(Debug)]
pub struct File {
    name: String,
    hash: Hash,
    block: Block,
    sector_offsets: Vec<u32>,
    sector_checksums: Vec<u32>,
    file_key: u32,
}

impl File {
    pub fn size(&self) -> u32 {
        self.block.unpacked_size
    }

    // read data from file
    pub fn read(&self, archive: &mut Archive, buf: &mut [u8]) -> Result<usize, Error> {
        if self.block.flags & FILE_PATCH_FILE != 0 {
            Err(Error::new(ErrorKind::Other, "Patch file not supported"))
        } else if self.block.flags & FILE_SINGLE_UNIT != 0 {
            // file is single block file
            self.read_single_unit_file(
                self.block.packed_size as usize,
                &mut archive.file,
                archive.offset,
                buf,
            )
        } else {
            // read as sector based MPQ file
            self.read_sector_file(archive, buf)
        }
    }

    fn read_sector_file(&self, archive: &mut Archive, out: &mut [u8]) -> Result<usize, Error> {
        let mut buff: Vec<u8> = vec![0; archive.sector_size as usize];
        let mut read: usize = 0;

        if self.block.flags & FILE_COMPRESS_MASK != 0 {
            for i in 0..self.sector_offsets.len() - 1 {
                let sector_offset = self.sector_offsets[i];
                let sector_size = self.sector_offsets[i + 1] - sector_offset;

                let mut in_buf: &mut [u8] = &mut buff[0..sector_size as usize];
                let mut out_buf: &mut [u8] = &mut out[read..];

                archive.file.seek(SeekFrom::Start(
                    u64::from(self.block.offset) + u64::from(sector_offset) + archive.offset,
                ))?;

                archive.file.read_exact(in_buf)?;

                if self.block.flags & FILE_ENCRYPTED != 0 {
                    decrypt(&mut in_buf, self.file_key + i as u32);
                }

                // checksum verification
                if !self.sector_checksums.is_empty() && self.sector_checksums[i] != 0 {
                    let mut adler = RollingAdler32::from_value(0);

                    adler.update_buffer(in_buf);

                    if self.sector_checksums[i] != adler.hash() {
                        return Err(Error::new(ErrorKind::Other, "Sector checksum error"));
                    }
                }

                if self.block.flags & FILE_COMPRESS != 0 {
                    if in_buf.len() == archive.sector_size as usize || in_buf.len() == out_buf.len()
                    {
                        for (dst, src) in out_buf.iter_mut().zip(in_buf) {
                            *dst = *src;
                            read += 1;
                        }
                    } else {
                        read += decompress(in_buf, &mut out_buf)?;
                    }
                } else if self.block.flags & FILE_IMPLODE != 0 {
                    if in_buf.len() == archive.sector_size as usize || in_buf.len() == out_buf.len()
                    {
                        for (dst, src) in out_buf.iter_mut().zip(in_buf) {
                            *dst = *src;
                            read += 1;
                        }
                    } else {
                        read += explode(in_buf, &mut out_buf)?;
                    }
                }
            }
        } else {
            archive.file.seek(SeekFrom::Start(
                u64::from(self.block.offset) + archive.offset,
            ))?;
            archive.file.read_exact(out)?;

            read = out.len();
        }

        Ok(read)
    }

    fn read_single_unit_file(
        &self,
        buff_size: usize,
        file: &mut fs::File,
        offset: u64,
        out_buf: &mut [u8],
    ) -> Result<usize, Error> {
        let mut in_buff: Vec<u8> = vec![0; buff_size];

        file.seek(SeekFrom::Start(u64::from(self.block.offset) + offset))?;

        file.read_exact(&mut in_buff)?;

        if self.block.flags & FILE_ENCRYPTED != 0 {
            decrypt(&mut in_buff, self.file_key);
        }

        if self.block.flags & FILE_COMPRESS != 0 && out_buf.len() > in_buff.len() {
            decompress(&mut in_buff, out_buf)
        } else if self.block.flags & FILE_IMPLODE != 0 {
            explode(&mut in_buff, out_buf)
        } else {
            for (dst, src) in out_buf.iter_mut().zip(&in_buff) {
                *dst = *src
            }

            Ok(self.block.unpacked_size as usize)
        }
    }

    // extract file from archive to the local filesystem
    pub fn extract<P: AsRef<Path>>(&self, archive: &mut Archive, path: P) -> Result<usize, Error> {
        let mut buf: Vec<u8> = vec![0; self.size() as usize];

        self.read(archive, &mut buf)?;

        fs::create_dir_all(path.as_ref().parent().unwrap())?;

        if path.as_ref().exists() {
            return Err(Error::new(ErrorKind::AlreadyExists, "File already exists"));
        }

        let mut file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(&path)
            .unwrap();

        file.write(&buf)
    }
}
