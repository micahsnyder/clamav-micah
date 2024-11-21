use std::{
    ffi::{CStr, CString},
    fs::File,
    io::{prelude::*, BufReader},
    os::raw::c_char,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use flate2::read::GzDecoder;
use hex;
use log::{debug, warn};
use tar::Archive;

use crate::{
    ffi_util::FFIError,
    sys,
    {rrf_call, validate_str_param},
    codesign,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    // #[error("Error signing data: {0}")]
    // SignError(#[from] openssl::error::ErrorStack),
    #[error("Error parsing CVD file: {0}")]
    Parse(String),

    #[error("Incorrect digital signature")]
    InvalidDigitalSignature,

    #[error("Can't verify: {0}")]
    CannotVerify(String),

    #[error("Signature verification failed")]
    VerifyFailed,

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

pub struct CVD {
    pub time_creation: SystemTime,
    pub version: u32,
    pub num_sigs: u32,
    pub min_flevel: u32,
    pub rsa_dsig: Option<String>,
    pub md5: Option<Vec<u8>>,
    pub builder: String,
    pub file: File,
    pub path: PathBuf,
}

impl CVD {
    pub fn new(
        time_creation: SystemTime,
        version: u32,
        num_sigs: u32,
        min_flevel: u32,
        rsa_dsig: Option<String>,
        md5: Option<Vec<u8>>,
        builder: String,
        path: PathBuf,
    ) -> Self {
        let file = File::open(&path).unwrap();
        Self {
            time_creation,
            version,
            num_sigs,
            min_flevel,
            rsa_dsig,
            md5,
            builder,
            file,
            path,
        }
    }

    pub fn from_file(file_path: &Path) -> Result<Self, Error> {
        let file = File::open(file_path)
            .map_err(|_| Error::Parse(format!("Failed to open file: {:?}", file_path)))?;
        let mut reader = BufReader::new(&file);

        // read the 512 byte header
        let mut header = [0; 512];
        reader
            .read_exact(&mut header)
            .map_err(|_| Error::Parse("File is smaller than 512-byte CVD header".to_string()))?;

        let mut fields = header.split(|&n| n == b':');

        let magic = fields
            .next()
            .ok_or_else(|| Error::Parse("Invalid CVD file".to_string()))?;
        if magic != b"ClamAV-VDB" {
            return Err(Error::Parse(
                "Invalid CVD file: First field does not match magic bytes for CVD file".to_string(),
            ));
        }

        let time_bytes = fields
            .next()
            .ok_or_else(|| Error::Parse("Invalid CVD file: Missing creation time".to_string()))?;
        let time_str = std::str::from_utf8(time_bytes)
            .map_err(|_| Error::Parse("Time string is not valid unicode".to_string()))?;
        let time_seconds: u64 = time_str
            .parse()
            .map_err(|_| Error::Parse("Time string is not an unsigned integer".to_string()))?;
        let time_creation = SystemTime::UNIX_EPOCH + Duration::from_secs(time_seconds);

        let version_bytes = fields
            .next()
            .ok_or_else(|| Error::Parse("Invalid CVD file: Missing version".to_string()))?;
        let version_str = std::str::from_utf8(version_bytes)
            .map_err(|_| Error::Parse("Version string is not valid unicode".to_string()))?;
        let version: u32 = version_str
            .parse()
            .map_err(|_| Error::Parse("Version string is not an unsigned integer".to_string()))?;

        let num_sigs_bytes = fields.next().ok_or_else(|| {
            Error::Parse("Invalid CVD file: Missing number of signatures".to_string())
        })?;
        let num_sigs_str = std::str::from_utf8(num_sigs_bytes)
            .map_err(|_| Error::Parse("Signature Count string is not valid unicode".to_string()))?;
        let num_sigs: u32 = num_sigs_str
            .parse()
            .map_err(|_| Error::Parse("Signature count is not an unsigned integer".to_string()))?;

        let min_flevel_bytes = fields.next().ok_or_else(|| {
            Error::Parse("Invalid CVD file: Missing minimum feature level".to_string())
        })?;
        let min_flevel_str = std::str::from_utf8(min_flevel_bytes).map_err(|_| {
            Error::Parse("Minimum Functionality Level string is not valid unicode".to_string())
        })?;
        let min_flevel: u32 = min_flevel_str.parse().map_err(|_| {
            Error::Parse("Minimum Functionality Level is not an unsigned integer".to_string())
        })?;

        let md5_bytes = fields.next().ok_or_else(|| {
            Error::Parse(
                "Invalid CVD file: Missing MD5 hash field for the compressed archive".to_string(),
            )
        })?;
        let md5_str = std::str::from_utf8(md5_bytes)
            .map_err(|_| Error::Parse("MD5 hash string is not valid unicode".to_string()))?;
        let md5: Option<Vec<u8>> = if md5_str.len() != 32 {
            debug!("MD5 hash string is not 32 characters long. It may be empty");
            None
        } else {
            match hex::decode(md5_str) {
                Ok(md5) => Some(md5),
                Err(e) => {
                    debug!("MD5 hash string is not valid hex: {}", e);
                    None
                }
            }
        };

        let rsa_dsig_bytes = fields.next().ok_or_else(|| {
            Error::Parse("Invalid CVD file: Missing minimum feature level".to_string())
        })?;
        let rsa_dsig_str = std::str::from_utf8(rsa_dsig_bytes)
            .map_err(|_| {
                Error::Parse(
                    "MD5-based RSA digital signature string is not valid unicode".to_string(),
                )
            })?
            .to_string();

        // the rsa dsig field might be empty or like just 'x'
        let rsa_dsig = if rsa_dsig_str.len() > 1 {
            None
        } else {
            Some(rsa_dsig_str)
        };

        let builder_bytes = fields
            .next()
            .ok_or_else(|| Error::Parse("Invalid CVD file: Missing builder string".to_string()))?;
        let builder = std::str::from_utf8(builder_bytes)
            .map_err(|_| Error::Parse("Builder string is not valid unicode".to_string()))?
            .to_string();

        Ok(Self {
            time_creation,
            version,
            num_sigs,
            min_flevel,
            rsa_dsig,
            md5,
            builder,
            file,
            path: file_path.to_path_buf(),
        })
    }

    pub fn unpack_to(&mut self, path: &Path) -> Result<(), Error> {
        debug!("Unpacking CVD file to {:?}", path);

        // skip the 512 byte header
        self.file
            .seek(std::io::SeekFrom::Start(512))
            .map_err(|_| Error::Parse("Failed to seek past CVD header".to_string()))?;

        let mut file_bytes = Vec::<u8>::new();
        let bytes_read = self
            .file
            .read_to_end(&mut file_bytes)
            .map_err(|_| Error::Parse("Failed to read CVD file".to_string()))?;

        debug!("Read {} bytes from CVD file", bytes_read);

        let mut archive = tar::Archive::new(GzDecoder::new(file_bytes.as_slice()));
        archive
            .entries()
            .map_err(|e| {
                Error::Parse(format!(
                    "Failed to enumerate files in signature archive: {}",
                    e.to_string()
                ))
            })?
            .filter_map(|e| e.ok())
            .map(|mut entry| -> Result<PathBuf, Error> {
                let filepath = entry.path().map_err(|e| {
                    Error::Parse(format!(
                        "Failed to get path for file in signature archive: {}",
                        e.to_string()
                    ))
                })?;
                let filename = filepath.file_name().ok_or_else(|| {
                    Error::Parse("Failed to get filename from archive entry".to_string())
                })?;
                let destination_filepath = path.join(filename);
                entry.unpack(&destination_filepath).map_err(|e| {
                    Error::Parse(format!(
                        "Failed to unpack file from signature archive: {}",
                        e.to_string()
                    ))
                })?;
                Ok(destination_filepath)
            })
            .filter_map(|e| e.ok())
            .for_each(|x| println!("> {}", x.display()));

        Ok(())
    }

    pub fn verify_rsa_dsig(&mut self) -> Result<bool, Error> {
        let mut file_bytes = Vec::<u8>::new();

        self.file
            .seek(std::io::SeekFrom::Start(512))
            .map_err(|_| Error::Parse("Failed to seek past CVD header".to_string()))?;

        let bytes_read = self
            .file
            .read_to_end(&mut file_bytes)
            .map_err(|_| Error::Parse("Failed to read CVD file".to_string()))?;

        debug!("Read {} bytes from CVD file", bytes_read);

        let digest = md5::compute(&file_bytes);
        let calculated_md5 = digest.as_slice();

        debug!("MD5 hash: {:?}", calculated_md5);

        if let Some(md5) = &self.md5 {
            if calculated_md5 != &md5[..] {
                warn!("MD5 hash does not match the expected hash");
                return Ok(false);
            }
        } else {
            debug!("MD5 hash is not present in the CVD file");
        }

        if let Some(rsa_dsig) = &self.rsa_dsig {
            debug!("RSA digital signature: {:?}", rsa_dsig);

            // cli_versig2 will expect dsig to be a null-terminated string
            let dsig_cstring = CString::new(rsa_dsig.as_bytes()).map_err(|_| {
                Error::Parse("Failed to convert RSA digital signature to CString".to_string())
            })?;

            // Verify cdiff
            let versig_result =
                unsafe { sys::cli_versig(calculated_md5.as_ptr(), dsig_cstring.as_ptr()) };

            debug!("verify_rsa_dsig: cli_versig() result = {}", versig_result);
            if versig_result != 0 {
                warn!("RSA digital signature verification failed");
                return Err(Error::InvalidDigitalSignature);
            }

            debug!("RSA digital signature verification succeeded");
        } else {
            warn!("RSA digital signature is not present in the CVD file");
            return Ok(false);
        }

        Ok(true)
    }

    pub fn verify(&mut self, certs_directory: &Path, disable_md5: bool) -> Result<(), Error> {

        let ext_sign_fileext = if let Some(ext) = self.path.extension() {
            format!(".{}.sign", ext.to_string_lossy())
        } else {
            ".sign".to_string()
        };
        let ext_sign_filepath = self.path.with_extension(ext_sign_fileext);

        match File::open(&ext_sign_filepath) {
            Ok(ext_sig_file) => {
                debug!("External signature file exists: {:?}", ext_sign_filepath);


            }
            Err(_) => {
                debug!("External signature file does not exist: {:?}", ext_sign_filepath);
            }
        }

        if !disable_md5 {
            self.verify_rsa_dsig()?;
        }

        Ok(())
    }
}
