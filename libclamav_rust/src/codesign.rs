use std::{
    fs::File,
    io::{prelude::*, BufReader},
    path::{Path, PathBuf},
};

use openssl::{
    pkcs7::{Pkcs7, Pkcs7Flags},
    pkey::{PKey, Private},
    stack,
    stack::Stack,
    x509::{store::X509StoreBuilder, X509},
};

use clam_sigutil::{
    sigbytes::{AppendSigBytes, SigBytes}, signature::{digital_sig::DigitalSig, parse_from_cvd_with_meta}, SigType, Signature
};

use log::{debug, error, warn};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Can't verify: {0}")]
    CannotVerify(String),

    #[error("Signature verification failed")]
    VerifyFailed,

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Error signing data: {0}")]
    SignError(#[from] openssl::error::ErrorStack),

    #[error("Error converting digital signature to .sign file line: {0}")]
    SigBytesError(#[from] clam_sigutil::signature::ToSigBytesError),

    #[error("Error verifying signature: {0}")]
    InvalidDigitalSignature(String),

    #[error(
        "Incorrect public key, does not match any serial number in the signature's signers chain"
    )]
    IncorrectPublicKey,
}

/// Verifies a signed file.
pub fn verify_signed_file(
    signed_file_path: &Path,
    signature_file_path: &Path,
    certs_directory: &Path,
) -> Result<(), Error> {
    let signature_file: File = File::open(&signature_file_path)?;

    let mut signed_file: File = File::open(&signed_file_path)?;

    let mut file_data = Vec::<u8>::new();
    let read_result = signed_file.read_to_end(&mut file_data);
    if let Err(e) = read_result {
        return Err(Error::CannotVerify(format!("Error reading file: {}", e)));
    }

    let reader = BufReader::new(signature_file);

    for (index, line) in reader.lines().enumerate() {
        // First line should be "#clamsign-MAJOR.MINOR"
        if index == 0 {
            let line = line?;
            if !line.starts_with("#clamsign") {
                return Err(Error::CannotVerify(
                    "Unsupported signature file format, expected first line start with '#clamsign-1.0'".to_string(),
                ));
            }

            // Check clamsign version
            let version = line.split('-').nth(1).unwrap();
            if version != "1.0" {
                return Err(Error::CannotVerify(
                    "Unsupported signature file version, expected '1.0'".to_string(),
                ));
            }

            continue;
        }

        // Skip empty lines
        let line = line?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Skip lines starting with '#'
        if line.starts_with('#') {
            continue;
        }

        // Convert line to bytes, which is preferred by our signature parser.
        let data = line.as_bytes();

        match parse_from_cvd_with_meta(SigType::DigitalSignature, &data.into()) {
            Ok((sig, _meta)) => {
                let sig = sig.downcast::<DigitalSig>().unwrap();

                sig.validate(&_meta).map_err(|e| {
                    Error::CannotVerify(format!(
                        "{:?}:{}: Invalid signature: {}",
                        signature_file_path, index, e
                    ))
                })?;

                match *sig {
                    DigitalSig::Pkcs7(pkcs7) => {
                        // Try to verify with each certificate in the certs directory.
                        for cert in certs_directory.read_dir()? {
                            let cert = cert?;
                            let cert_path = cert.path();

                            let verifier = Verifier::new(&cert_path)?;
                            match verifier.verify(&file_data, &pkcs7) {
                                Ok(()) => {
                                    return Ok(());
                                }
                                Err(Error::InvalidDigitalSignature(m)) => {
                                    warn!(
                                        "Invalid digital signature for {:?}: {}",
                                        signed_file_path, m
                                    );
                                    return Err(Error::InvalidDigitalSignature(m));
                                }
                                Err(e) => {
                                    debug!(
                                        "Error verifying signature with {:?}: {:?}",
                                        cert_path, e
                                    );

                                    // Try the next certificate
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!(
                    "{:?}:{}: Error parsing signature: {}",
                    signature_file_path, index, e
                );
                return Err(Error::CannotVerify(e.to_string()));
            }
        };
    }

    return Err(Error::CannotVerify(
        "Unable to verify any digital signatures".to_string(),
    ));
}

pub struct Signer {
    cert: X509,
    certs: Stack<X509>,
    key: PKey<Private>,
}

impl Signer {
    pub fn new(
        key_path: &Path,
        cert_path: &Path,
        intermediate_cert_paths: Vec<&Path>,
    ) -> Result<Self, Error> {
        let mut certs: Stack<X509> = Stack::new()?;

        let cert_bytes = std::fs::read(cert_path)?;
        let cert = X509::from_pem(&cert_bytes)?;
        debug!("Signing certificate: {:?}", cert);
        certs.push(cert.clone())?;

        let signing_key_bytes = std::fs::read(key_path)?;
        let key = PKey::private_key_from_pem(&signing_key_bytes)?;
        debug!("Signing key: {:?}", key);

        for intermediate_cert_path in intermediate_cert_paths {
            let intermediate_cert_bytes = std::fs::read(intermediate_cert_path)?;
            let intermediate_cert = X509::from_pem(&intermediate_cert_bytes)?;
            debug!("Intermediate certificate: {:?}", &intermediate_cert);
            certs.push(intermediate_cert)?;
        }

        Ok(Signer { cert, certs, key })
    }

    pub fn sign(&self, data: &[u8]) -> Result<Pkcs7, Error> {
        let flags = Pkcs7Flags::DETACHED | Pkcs7Flags::BINARY;

        Pkcs7::sign(&self.cert, &self.key, &self.certs, data, flags)
            .map_err(|e| Error::SignError(e))
    }
}

pub struct Verifier {
    root_ca: X509,
}

impl Verifier {
    pub fn new(root_ca_path: &Path) -> Result<Self, Error> {
        let root_ca_bytes = std::fs::read(root_ca_path)?;
        let root_ca: X509 = X509::from_pem(&root_ca_bytes)?;

        Ok(Verifier { root_ca })
    }

    pub fn verify(&self, data: &[u8], pkcs7: &Pkcs7) -> Result<(), Error> {
        let certs = stack::Stack::new()?;

        let flags = Pkcs7Flags::DETACHED | Pkcs7Flags::BINARY;

        // Get the certs from the pkcs7 pkcs7
        let signers = pkcs7
            .signers(&certs, flags)
            .map_err(|_| Error::InvalidDigitalSignature("No signers found".to_string()))?;

        // Check each cert in the pkcs7 chain to see if it matches the root CA
        // If we can't find a matching serial number, then we can't verify the pkcs7 signature.
        // That doesn't mean the signature is invalid, only that we don't have the required public key to verify it.
        for cert in signers {
            let subject = cert.subject_name();
            let issuer = cert.issuer_name();
            let serial = cert.serial_number();
            let serial_num = serial.to_bn()?;
            let serial_string = serial_num.to_dec_str()?;
            debug!("Subject: {:?}", subject);
            debug!("Issuer: {:?}", issuer);
            debug!("Serial: {:?}", serial_string);

            if self.root_ca.serial_number() == serial {
                // found a matching serial number in the pkcs7 cert chain for the provided root CA.
                // We can verify the signature.

                // create store with root CA
                let mut store_builder = X509StoreBuilder::new().expect("should succeed");
                store_builder
                    .add_cert(self.root_ca.clone())
                    .expect("should succeed");
                let store = store_builder.build();

                // verify signature
                let mut output = Vec::new();
                let result = pkcs7.verify(&certs, &store, Some(data), Some(&mut output), flags);

                match result {
                    Ok(()) => {
                        debug!("Signature verified");
                        return Ok(());
                    }
                    Err(e) => {
                        eprintln!("Error verifying signature: {}", e);
                        return Err(Error::InvalidDigitalSignature(e.to_string()));
                    }
                }
            }
        }

        Err(Error::IncorrectPublicKey)
    }
}

pub fn sign_file(
    target_file_path: &Path,
    signature_file_path: &Path,
    signing_cert_path: &Path,
    intermediate_cert_paths: Vec<&Path>,
    signing_key_path: &Path,
) -> Result<(), Error> {
    let signer = Signer::new(signing_key_path, signing_cert_path, intermediate_cert_paths)?;

    let data = std::fs::read(target_file_path)?;
    let pkcs7 = signer.sign(&data)?;
    let signature = DigitalSig::Pkcs7(pkcs7);
    let mut sig_bytes: SigBytes = SigBytes::new();
    signature.append_sigbytes(&mut sig_bytes)?;

    // If the signature file already exists, open it and append the signature to it.
    let mut writer = if signature_file_path.exists() {
        let mut writer = std::io::BufWriter::new(std::fs::OpenOptions::new().append(true).open(signature_file_path)?);
        // Seek to the end of the file
        writer.seek(std::io::SeekFrom::End(0))?;
        // Write a newline before the signature
        writer.write(b"\n")?;

        writer
    } else {
        // Create the signature file if it doesn't exist.
        let mut writer = std::io::BufWriter::new(std::fs::File::create(signature_file_path)?);
        writer.write(b"#clamsign-1.0\n")?;

        writer
    };

    writer.write(sig_bytes.as_bytes())?;

    // Write a newline after the signature
    writer.write(b"\n")?;

    Ok(())
}

pub fn verify_file(
    target_file_path: PathBuf,
    signature_file_path: PathBuf,
    root_ca_path: PathBuf,
) -> Result<(), Error> {
    // Default signature file is the target file with the .p7s extension
    let signature_bytes = std::fs::read(signature_file_path)?;
    let signature = Pkcs7::from_pem(&signature_bytes)?;

    let data = std::fs::read(target_file_path)?;

    let verifier = Verifier::new(&root_ca_path)?;
    let result = verifier.verify(&data, &signature);

    match result {
        Ok(()) => {
            debug!("Signature is valid");
            Ok(())
        }
        Err(e) => {
            error!("Signature is invalid: {e}");
            Err(e)
        }
    }
}
