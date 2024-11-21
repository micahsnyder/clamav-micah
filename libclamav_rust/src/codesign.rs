use std::{
    ffi::CStr,
    fs::File,
    io::{prelude::*, BufReader},
    os::raw::c_char,
    path::Path,
};

use clam_sigutil::{self, SigType};
use clam_sigutil::{signature::digital_sig::DigitalSig, Signature};

use log::warn;

use crate::{
    ffi_util::FFIError,
    sys, {rrf_call, validate_str_param},
};

/// C interface for checking if there's an external signature on a file that we can verify.
/// Handles all the unsafe ffi stuff.
///
/// # Safety
///
/// No parameters may be NULL
#[export_name = "cli_check_if_file_signed"]
pub unsafe extern "C" fn cli_check_if_file_signed(
    signed_file_path_str: *const c_char,
    certs_directory_str: *const c_char,
    file_signature: *mut sys::file_signature_t,
    err: *mut *mut FFIError,
) -> bool {
    let signed_file_path_str = validate_str_param!(signed_file_path_str);
    let certs_directory_str = validate_str_param!(certs_directory_str);

    let signed_file_path = match Path::new(signed_file_path_str).canonicalize() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error canonicalizing path: {:?}", e);
            return 1;
        }
    };

    let certs_directory = match Path::new(certs_directory_str).canonicalize() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error canonicalizing path: {:?}", e);
            return 1;
        }
    };

    rrf_call!(check_if_file_signed(
        err = err,
        &signed_file_path,
        &certs_directory
    ))
}

/// Checks if a file is signed.
/// Returns true if the file is signed, false otherwise.
fn check_if_file_signed(signed_file_path: &Path, certs_directory: &Path) -> bool {
    let signature_file_path =
        signed_file_path.with_extension(format!("{}.{}", signed_file_path.extension(), "sign"));

    if signature_file_path.exists() {
        return true;
    }

    false
}

/// C interface for verifying a file signature.
/// Handles all the unsafe ffi stuff.
///
/// # Safety
///
/// No parameters may be NULL
#[export_name = "cli_verify_file_signature"]
pub unsafe extern "C" fn cli_verify_file_signature(
    digital_signature: Box<DigitalSig>,
    err: *mut *mut FFIError,
) -> u32 {
    rrf_call!(verify_signed_file(
        err = err,
        &signed_file_path,
        &certs_directory
    ))
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Can't verify: {0}")]
    CannotVerify(String),

    #[error("Signature verification failed")]
    VerifyFailed,

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Verifies a signed file.
fn verify_signed_file(signed_file_path: &Path, certs_directory: &Path) -> Result<(), Error> {
    let signature_file_path = signed_file_path.with_extension(".sign");

    let signature_file: File = File::open(&signature_file_path)?;

    let signed_file: File = File::open(&signed_file_path)?;

    let mut reader = BufReader::new(signature_file);

    for (index, line) in reader.lines().enumerate() {
        // Skip empty lines
        let line = line?.trim();
        if line.is_empty() {
            continue;
        }

        // Skip lines starting with '#'
        if line.starts_with('#') {
            continue;
        }

        // Convert line to bytes, which is preferred by our signature parser.
        let data = line.as_bytes();

        match clam_sigutil::signature::parse_from_cvd_with_meta(
            SigType::DigitalSignature,
            &data.into(),
        ) {
            Ok((sig, meta)) => {
                let sig = sig.downcast::<DigitalSig>().unwrap();

                let mut signed_file = signed_file.try_clone()?;
                let mut buf = vec![];
                signed_file.read_to_end(&mut buf)?;

                let pub_key = certs_directory.join("clamav.pem");

                if sig.verify(&buf, &meta).is_ok() {
                    return Ok(());
                } else {
                    warn!(
                        "Signature verification failed for signature at line {}",
                        index
                    );
                    return Err(Error::VerifyFailed);
                }
            }
            Err(e) => {
                eprintln!("Error parsing signature: {:?}", e);
                return Err(Error::CannotVerify(e.to_string()));
            }
        };
    }

    return Err(Error::CannotVerify(
        "Unable to verify any signatures".to_string(),
    ));
}

// fn process_sigs<F: Read>(opt: &Opt, sig_type: SigType, fh: &mut F) -> Result<()> {
//     let start = Instant::now();
//     let mut n_records = 0;
//     let mut line_no = 0;
//     let mut sigbuf = vec![];
//     let mut err_count = 0;

//     let mut fh = BufReader::new(fh);

//     if opt.verbose {
//         println!();
//     }
//     loop {
//         sigbuf.clear();
//         if fh.read_until(b'\n', &mut sigbuf)? == 0 {
//             break;
//         };
//         line_no += 1;
//         if sigbuf.starts_with(b"#") {
//             // comment
//             continue;
//         }
//         let sigbuf = if let Some(sigbuf) = sigbuf.strip_suffix(b"\r\n") {
//             sigbuf
//         } else if let Some(sigbuf) = sigbuf.strip_suffix(b"\n") {
//             sigbuf
//         } else {
//             return Err(anyhow!("missing final newline or CRLF"));
//         };
//         n_records += 1;

//         if opt.print_orig {
//             println!(
//                 " < {}",
//                 str::from_utf8(sigbuf).unwrap_or("!!! Not Unicode !!!")
//             );
//         }
//         let sigbuf = sigbuf.into();
//         match clam_sigutil::signature::parse_from_cvd_with_meta(sig_type, &sigbuf) {
//             Ok((sig, sigmeta)) => {
//                 if opt.dump_debug_long {
//                     println!(" * {:#?} f_level{:?}", sig, sig.computed_feature_level());
//                 } else if opt.dump_debug {
//                     println!(" * {:?} f_level{:?}", sig, sig.computed_feature_level());
//                 }
//                 if opt.print_features {
//                     println!(" > {:?}", sig.features());
//                 }

//                 if opt.validate {
//                     if let Err(e) = sig.validate(&sigmeta) {
//                         eprintln!(
//                             "Signature on line {line_no} failed validation:\n  {sigbuf}\n  Error: {e}\n"
//                         );
//                         err_count += 1;
//                     }
//                 }

//                 if opt.check_export {
//                     // Note: This naively compares the two signatures after
//                     // downcasing to suppress issues with different case of hex
//                     // values (a-f/A-F)
//                     let exported = sig.to_sigbytes().unwrap();
//                     if str::from_utf8(exported.as_bytes()).unwrap().to_lowercase()
//                         != str::from_utf8(sigbuf.as_bytes()).unwrap().to_lowercase()
//                     {
//                         eprintln!("Export mismatch:");
//                         eprintln!(" < {sigbuf}");
//                         eprintln!(" > {exported}");
//                     }
//                 }
//             }
//             Err(e) => {
//                 if !matches!(
//                     e,
//                     clam_sigutil::signature::FromSigBytesParseError::UnsupportedSigType
//                 ) {
//                     eprintln!("Unable to process line {line_no}:\n  {sigbuf}\n  Error: {e}\n");
//                     err_count += 1;
//                 }
//             }
//         }
//     }

//     let elapsed = start.elapsed();
//     if n_records > 0 {
//         if opt.verbose {
//             println!(
//                 " - {} records in {:?} ({:?}/record)",
//                 n_records,
//                 elapsed,
//                 Duration::from_nanos((elapsed.as_nanos() / n_records).try_into()?)
//             );
//         }
//     } else {
//         eprintln!(" - no records");
//     }
//     if err_count > 0 {
//         return Err(anyhow!("{} errors encountered", err_count));
//     }
//     Ok(())
// }
