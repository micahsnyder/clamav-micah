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
    signature::{digital_sig::DigitalSig, parse_from_cvd_with_meta},
    SigType, Signature,
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

    #[error("Error verifying signature: {0}")]
    InvalidDigitalSignature(String),

    #[error(
        "Incorrect public key, does not match any serial number in the signature's signers chain"
    )]
    IncorrectPublicKey,
}

/// Verifies a signed file.
pub fn verify_signed_file(signed_file_path: &Path, signature_file_path: &Path, certs_directory: &Path) -> Result<(), Error> {
    let signature_file: File = File::open(&signature_file_path)?;

    let mut signed_file: File = File::open(&signed_file_path)?;

    let mut file_data = Vec::<u8>::new();
    let read_result = signed_file.read_to_end(&mut file_data);
    if let Err(e) = read_result {
        return Err(Error::CannotVerify(format!("Error reading file: {}", e)));
    }

    let reader = BufReader::new(signature_file);

    for (index, line) in reader.lines().enumerate() {
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
                    Error::CannotVerify(format!("{:?}:{}: Invalid signature: {}", signature_file_path, index, e))
                })?;

                match *sig {
                    DigitalSig::Pkcs7(pkcs7) => {
                        // Try to verify with each certificate in the certs directory.
                        for cert in certs_directory.read_dir()? {
                            let cert = cert?;
                            let cert_path = cert.path();
                            let cert = File::open(&cert_path)?;

                            let mut cert = BufReader::new(cert);
                            let mut cert_data = vec![];
                            cert.read_to_end(&mut cert_data)?;

                            let verifier = Verifier::new(&cert_data);
                            match verifier.verify(&file_data, &pkcs7) {
                                Ok(()) => {
                                    return Ok(());
                                }
                                Err(Error::InvalidDigitalSignature(m)) => {
                                    warn!("Invalid digital signature for {:?}: {}", signed_file_path, m);
                                    return Err(Error::InvalidDigitalSignature(m));
                                }
                                Err(e) => {
                                    debug!("Error verifying signature with {:?}: {:?}", cert_path, e);

                                    // Try the next certificate
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("{:?}:{}: Error parsing signature: {}", signature_file_path, index, e);
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
    pub fn new(signing_cert: &[u8], intermediates: Vec<Vec<u8>>, signing_key: &[u8]) -> Self {
        let cert = X509::from_pem(signing_cert).unwrap();

        debug!("Signing certificate: {:?}", cert);

        let key = PKey::private_key_from_pem(signing_key).unwrap();

        debug!("Signing key: {:?}", key);

        let mut certs: Stack<X509> = Stack::new().unwrap();
        certs.push(cert.clone()).unwrap();

        for intermediate in intermediates {
            let intermediate_cert = X509::from_pem(&intermediate).unwrap();

            debug!("Intermediate certificate: {:?}", &intermediate_cert);

            certs.push(intermediate_cert).unwrap();
        }

        Signer { cert, certs, key }
    }

    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        let flags = Pkcs7Flags::DETACHED | Pkcs7Flags::BINARY;

        // sign data
        let pkcs7_result = Pkcs7::sign(&self.cert, &self.key, &self.certs, data, flags);
        let pkcs7 = match pkcs7_result {
            Ok(pkcs7) => pkcs7,
            Err(e) => return Err(Error::SignError(e)),
        };

        pkcs7.to_pem().map_err(|e| Error::SignError(e))
    }
}

pub struct Verifier {
    root_ca: X509,
}

impl Verifier {
    pub fn new(root_ca: &[u8]) -> Self {
        let root_ca: X509 = X509::from_pem(root_ca).unwrap();

        Verifier { root_ca }
    }

    pub fn verify(&self, data: &[u8], pkcs7: &Pkcs7) -> Result<(), Error> {
        let certs = stack::Stack::new().unwrap();

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
            let serial_num = serial.to_bn().unwrap();
            let serial_string = serial_num.to_dec_str().unwrap();
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
    target_file_path: PathBuf,
    signature_file_path: Option<PathBuf>,
    signing_cert_path: PathBuf,
    intermediate_cert_path: Vec<PathBuf>,
    signing_key_path: PathBuf,
) {
    let cert = std::fs::read(signing_cert_path);
    let cert = match cert {
        Ok(cert) => cert,
        Err(e) => {
            error!("Unable to read signing certificate: {e}");
            return;
        }
    };

    let mut intermediates = Vec::new();
    for intermediate_cert_path in intermediate_cert_path {
        let intermediate_cert = std::fs::read(intermediate_cert_path);
        let intermediate_cert = match intermediate_cert {
            Ok(intermediate_cert) => intermediate_cert,
            Err(e) => {
                error!("Unable to read intermediate certificate: {e}");
                return;
            }
        };
        intermediates.push(intermediate_cert);
    }

    let pkey = std::fs::read(signing_key_path);
    let pkey = match pkey {
        Ok(pkey) => pkey,
        Err(e) => {
            error!("Unable to read signing private key: {e}");
            return;
        }
    };

    let data = std::fs::read(&target_file_path);
    let data = match data {
        Ok(data) => data,
        Err(e) => {
            error!("Unable to read target file: {e}");
            return;
        }
    };

    let signer = Signer::new(&cert, intermediates, &pkey);
    let signature = signer.sign(&data).unwrap();

    // Default signature file is the target file with the .p7s extension
    let signature_file_path = signature_file_path.unwrap_or_else(|| {
        let mut new = target_file_path.clone();
        let new = new.as_mut_os_string();
        new.push(".p7s");
        PathBuf::from(new.as_os_str())
    });
    debug!("Writing signature to {:?}", signature_file_path);

    let signature_file = std::fs::File::create(&signature_file_path);
    let signature_file = match signature_file {
        Ok(signature_file) => signature_file,
        Err(e) => {
            error!("Unable to create signature file: {e}");
            return;
        }
    };

    let mut writer = std::io::BufWriter::new(signature_file);
    let write_result = writer.write(&signature);
    match write_result {
        Ok(_) => {}
        Err(e) => {
            error!("Unable to write signature to file: {e}");
            return;
        }
    }
}

pub fn verify_file(
    target_file_path: PathBuf,
    signature_file_path: Option<PathBuf>,
    root_ca_path: PathBuf,
) {
    let root_ca = std::fs::read(root_ca_path);
    let root_ca = match root_ca {
        Ok(root_ca) => root_ca,
        Err(e) => {
            error!("Unable to read root CA certificate: {e}");
            return;
        }
    };

    // Default signature file is the target file with the .p7s extension
    let signature_file_path = signature_file_path.unwrap_or_else(|| {
        let mut new = target_file_path.clone();
        let new = new.as_mut_os_string();
        new.push(".p7s");
        PathBuf::from(new.as_os_str())
    });
    debug!("Reading signature to {:?}", signature_file_path);

    let signature = std::fs::read(signature_file_path);
    let signature = match signature {
        Ok(signature) => signature,
        Err(e) => {
            error!("Unable to read signature file: {e}");
            return;
        }
    };

    let data = std::fs::read(target_file_path);
    let data = match data {
        Ok(data) => data,
        Err(e) => {
            error!("Unable to read target file: {e}");
            return;
        }
    };

    let signature = Pkcs7::from_pem(&signature).unwrap();

    let verifier = Verifier::new(&root_ca);
    let result = verifier.verify(&data, &signature);

    match result {
        Ok(()) => {
            debug!("Signature is valid");
        }
        Err(e) => {
            error!("Signature is invalid: {e}");
        }
    }
}
