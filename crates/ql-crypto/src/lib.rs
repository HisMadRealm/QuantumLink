//! Hybrid post-quantum cryptographic primitives for QuantumLink.

#![forbid(unsafe_code)]

use std::fmt;

use ed25519_dalek::{Signature as Ed25519Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use oqs::{
    kem::{Algorithm as KemAlgorithm, Kem},
    sig::{Algorithm as SigAlgorithm, Sig},
};
use ql_core::{QuantumLinkError, QuantumLinkResult};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha3::{Digest as Sha3Digest, Sha3_256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

const HYBRID_KEM_SALT: &[u8] = b"QuantumLink-HybridKEM-v1";
const HYBRID_KEM_INFO: &[u8] = b"kem";
const HYBRID_KEM_SECRET_LEN: usize = 32;
const ED25519_SECRET_LEN: usize = 32;
const ED25519_SIGNATURE_LEN: usize = 64;
const MLKEM768_PUBLIC_KEY_LEN: usize = 1_184;
const MLKEM768_CIPHERTEXT_LEN: usize = 1_088;
const MLDSA65_PUBLIC_KEY_LEN: usize = 1_952;
const MLDSA65_SIGNATURE_LEN: usize = 3_309;

/// A hybrid keypair combining X25519 and ML-KEM-768.
///
/// The combined scheme is secure if either the classical or post-quantum
/// component remains unbroken.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HybridKemKeypair {
    x25519_secret: [u8; HYBRID_KEM_SECRET_LEN],
    x25519_public: [u8; HYBRID_KEM_SECRET_LEN],
    mlkem768_secret: Vec<u8>,
    mlkem768_public: Vec<u8>,
}

impl fmt::Debug for HybridKemKeypair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HybridKemKeypair([REDACTED])")
    }
}

/// The public half of a `HybridKemKeypair`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HybridKemPublicKey {
    /// X25519 public key bytes.
    pub x25519: [u8; HYBRID_KEM_SECRET_LEN],
    /// ML-KEM-768 public key bytes.
    #[serde(with = "serde_bytes")]
    pub mlkem768: Vec<u8>,
}

/// A hybrid ciphertext produced by encapsulation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HybridCiphertext {
    /// Ephemeral X25519 public key bytes.
    pub x25519_ephemeral_pk: [u8; HYBRID_KEM_SECRET_LEN],
    /// ML-KEM-768 ciphertext bytes.
    #[serde(with = "serde_bytes")]
    pub mlkem768_ct: Vec<u8>,
}

/// The derived hybrid shared secret.
#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct HybridSharedSecret([u8; HYBRID_KEM_SECRET_LEN]);

impl fmt::Debug for HybridSharedSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HybridSharedSecret([REDACTED])")
    }
}

impl AsRef<[u8]> for HybridSharedSecret {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl HybridSharedSecret {
    /// Returns the shared secret bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; HYBRID_KEM_SECRET_LEN] {
        &self.0
    }
}

impl HybridKemKeypair {
    /// Generates a fresh hybrid KEM keypair.
    ///
    /// # Errors
    ///
    /// Returns an error if ML-KEM-768 is unavailable or key generation fails.
    #[must_use]
    pub fn generate() -> QuantumLinkResult<Self> {
        let mut x25519_secret = [0_u8; HYBRID_KEM_SECRET_LEN];
        OsRng.fill_bytes(&mut x25519_secret);
        let x25519_secret_key = StaticSecret::from(x25519_secret);
        let x25519_public = X25519PublicKey::from(&x25519_secret_key).to_bytes();

        let kem = mlkem768()?;
        let (public_key, secret_key) = kem.keypair().map_err(|error| {
            QuantumLinkError::Crypto(format!("ML-KEM-768 keypair failed: {error}"))
        })?;

        Ok(Self {
            x25519_secret,
            x25519_public,
            mlkem768_secret: secret_key.into_vec(),
            mlkem768_public: public_key.into_vec(),
        })
    }

    /// Returns the serializable public key portion of this hybrid KEM keypair.
    #[must_use]
    pub fn public_key(&self) -> HybridKemPublicKey {
        HybridKemPublicKey {
            x25519: self.x25519_public,
            mlkem768: self.mlkem768_public.clone(),
        }
    }
}

/// Encapsulates a hybrid shared secret for a recipient.
///
/// Shared secret derivation is:
/// `HKDF-SHA3-256(x25519_ss || mlkem768_ss, salt = "QuantumLink-HybridKEM-v1", info = b"kem")`.
///
/// # Errors
///
/// Returns an error if the recipient key is malformed or an encapsulation step fails.
#[must_use]
pub fn hybrid_kem_encapsulate(
    recipient_pk: &HybridKemPublicKey,
) -> QuantumLinkResult<(HybridCiphertext, HybridSharedSecret)> {
    let kem = mlkem768()?;
    validate_mlkem768_public_key(recipient_pk.mlkem768.as_slice())?;

    let mut ephemeral_secret_bytes = [0_u8; HYBRID_KEM_SECRET_LEN];
    OsRng.fill_bytes(&mut ephemeral_secret_bytes);
    let ephemeral_secret = StaticSecret::from(ephemeral_secret_bytes);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret).to_bytes();
    let recipient_x25519 = X25519PublicKey::from(recipient_pk.x25519);
    let classical_secret = ephemeral_secret
        .diffie_hellman(&recipient_x25519)
        .as_bytes()
        .to_vec();

    let recipient_mlkem_pk = kem
        .public_key_from_bytes(recipient_pk.mlkem768.as_slice())
        .ok_or_else(|| {
            QuantumLinkError::Crypto("invalid ML-KEM-768 public key length".to_owned())
        })?;
    let (mlkem_ciphertext, mlkem_secret) =
        kem.encapsulate(&recipient_mlkem_pk).map_err(|error| {
            QuantumLinkError::Crypto(format!("ML-KEM-768 encapsulation failed: {error}"))
        })?;

    let shared_secret = derive_hybrid_secret(classical_secret.as_slice(), mlkem_secret.as_ref())?;

    Ok((
        HybridCiphertext {
            x25519_ephemeral_pk: ephemeral_public,
            mlkem768_ct: mlkem_ciphertext.into_vec(),
        },
        shared_secret,
    ))
}

/// Decapsulates a hybrid shared secret with the provided keypair.
///
/// # Errors
///
/// Returns an error if the ciphertext is malformed or decapsulation fails.
#[must_use]
pub fn hybrid_kem_decapsulate(
    keypair: &HybridKemKeypair,
    ct: &HybridCiphertext,
) -> QuantumLinkResult<HybridSharedSecret> {
    validate_mlkem768_ciphertext(ct.mlkem768_ct.as_slice())?;

    let x25519_secret = StaticSecret::from(keypair.x25519_secret);
    let ephemeral_public = X25519PublicKey::from(ct.x25519_ephemeral_pk);
    let classical_secret = x25519_secret
        .diffie_hellman(&ephemeral_public)
        .as_bytes()
        .to_vec();

    let kem = mlkem768()?;
    let mlkem_secret_key = kem
        .secret_key_from_bytes(keypair.mlkem768_secret.as_slice())
        .ok_or_else(|| {
            QuantumLinkError::Crypto("invalid ML-KEM-768 secret key length".to_owned())
        })?;
    let ciphertext = kem
        .ciphertext_from_bytes(ct.mlkem768_ct.as_slice())
        .ok_or_else(|| {
            QuantumLinkError::Crypto("invalid ML-KEM-768 ciphertext length".to_owned())
        })?;
    let mlkem_secret = kem
        .decapsulate(&mlkem_secret_key, &ciphertext)
        .map_err(|error| {
            QuantumLinkError::Crypto(format!("ML-KEM-768 decapsulation failed: {error}"))
        })?;

    derive_hybrid_secret(classical_secret.as_slice(), mlkem_secret.as_ref())
}

/// A hybrid signing key combining Ed25519 and ML-DSA-65.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HybridSigningKey {
    ed25519_secret: [u8; ED25519_SECRET_LEN],
    ed25519_public: [u8; HYBRID_KEM_SECRET_LEN],
    mldsa65_secret: Vec<u8>,
    mldsa65_public: Vec<u8>,
}

impl fmt::Debug for HybridSigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HybridSigningKey([REDACTED])")
    }
}

/// Serializable hybrid signing key material for local offline CA storage.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct HybridSigningKeyFile {
    /// Ed25519 secret key bytes.
    pub ed25519_secret: [u8; ED25519_SECRET_LEN],
    /// Ed25519 public key bytes.
    pub ed25519_public: [u8; HYBRID_KEM_SECRET_LEN],
    /// ML-DSA-65 secret key bytes.
    #[serde(with = "serde_bytes")]
    pub mldsa65_secret: Vec<u8>,
    /// ML-DSA-65 public key bytes.
    #[serde(with = "serde_bytes")]
    pub mldsa65_public: Vec<u8>,
}

/// The public verification key for hybrid signatures.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HybridVerifyingKey {
    /// Ed25519 public key bytes.
    pub ed25519: [u8; HYBRID_KEM_SECRET_LEN],
    /// ML-DSA-65 public key bytes.
    #[serde(with = "serde_bytes")]
    pub mldsa65: Vec<u8>,
}

/// A hybrid signature that requires both Ed25519 and ML-DSA verification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HybridSignature {
    /// Ed25519 signature bytes.
    #[serde(with = "ed25519_signature_bytes")]
    pub ed25519: [u8; ED25519_SIGNATURE_LEN],
    /// ML-DSA-65 signature bytes.
    #[serde(with = "serde_bytes")]
    pub mldsa65: Vec<u8>,
}

impl HybridSigningKey {
    /// Generates a fresh hybrid signing key.
    ///
    /// # Errors
    ///
    /// Returns an error if ML-DSA-65 is unavailable or key generation fails.
    #[must_use]
    pub fn generate() -> QuantumLinkResult<Self> {
        let mut ed25519_secret = [0_u8; ED25519_SECRET_LEN];
        getrandom::getrandom(&mut ed25519_secret).map_err(|error| {
            QuantumLinkError::Crypto(format!(
                "OS randomness unavailable for Ed25519 key generation: {error}"
            ))
        })?;
        let ed25519_signing_key = SigningKey::from_bytes(&ed25519_secret);
        let ed25519_public = ed25519_signing_key.verifying_key().to_bytes();

        let sig = mldsa65()?;
        let (public_key, secret_key) = sig.keypair().map_err(|error| {
            QuantumLinkError::Crypto(format!("ML-DSA-65 keypair failed: {error}"))
        })?;

        Ok(Self {
            ed25519_secret,
            ed25519_public,
            mldsa65_secret: secret_key.into_vec(),
            mldsa65_public: public_key.into_vec(),
        })
    }

    /// Returns the public verification key for this hybrid signing key.
    #[must_use]
    pub fn verifying_key(&self) -> HybridVerifyingKey {
        HybridVerifyingKey {
            ed25519: self.ed25519_public,
            mldsa65: self.mldsa65_public.clone(),
        }
    }

    /// Exports signing-key material for local encrypted or filesystem-backed storage.
    #[must_use]
    pub fn export_secret(&self) -> HybridSigningKeyFile {
        HybridSigningKeyFile {
            ed25519_secret: self.ed25519_secret,
            ed25519_public: self.ed25519_public,
            mldsa65_secret: self.mldsa65_secret.clone(),
            mldsa65_public: self.mldsa65_public.clone(),
        }
    }

    /// Reconstructs a hybrid signing key from serialized secret material.
    pub fn import_secret(mut key_file: HybridSigningKeyFile) -> QuantumLinkResult<Self> {
        let ed25519_public = SigningKey::from_bytes(&key_file.ed25519_secret)
            .verifying_key()
            .to_bytes();
        if ed25519_public != key_file.ed25519_public {
            return Err(QuantumLinkError::Crypto(
                "Ed25519 public key does not match the stored secret key".to_owned(),
            ));
        }

        let sig = mldsa65()?;
        let _ = sig
            .secret_key_from_bytes(key_file.mldsa65_secret.as_slice())
            .ok_or_else(|| {
                QuantumLinkError::Crypto("invalid ML-DSA-65 secret key length".to_owned())
            })?;
        let _ = sig
            .public_key_from_bytes(key_file.mldsa65_public.as_slice())
            .ok_or_else(|| {
                QuantumLinkError::Crypto("invalid ML-DSA-65 public key length".to_owned())
            })?;

        Ok(Self {
            ed25519_secret: key_file.ed25519_secret,
            ed25519_public: key_file.ed25519_public,
            mldsa65_secret: std::mem::take(&mut key_file.mldsa65_secret),
            mldsa65_public: std::mem::take(&mut key_file.mldsa65_public),
        })
    }

    /// Signs a message with both Ed25519 and ML-DSA-65.
    ///
    /// # Errors
    ///
    /// Returns an error if the ML-DSA-65 signing step fails.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> QuantumLinkResult<HybridSignature> {
        let ed25519_signing_key = SigningKey::from_bytes(&self.ed25519_secret);
        let ed25519_signature = ed25519_signing_key.sign(message).to_bytes();

        let sig = mldsa65()?;
        let mldsa_secret = sig
            .secret_key_from_bytes(self.mldsa65_secret.as_slice())
            .ok_or_else(|| {
                QuantumLinkError::Crypto("invalid ML-DSA-65 secret key length".to_owned())
            })?;
        let mldsa_signature = sig.sign(message, &mldsa_secret).map_err(|error| {
            QuantumLinkError::Crypto(format!("ML-DSA-65 signing failed: {error}"))
        })?;

        Ok(HybridSignature {
            ed25519: ed25519_signature,
            mldsa65: mldsa_signature.into_vec(),
        })
    }
}

impl HybridVerifyingKey {
    /// Verifies a hybrid signature.
    ///
    /// # Errors
    ///
    /// Returns an error if either the Ed25519 or ML-DSA-65 component is invalid.
    pub fn verify(&self, message: &[u8], sig: &HybridSignature) -> QuantumLinkResult<()> {
        validate_mldsa65_public_key(self.mldsa65.as_slice())?;
        validate_mldsa65_signature(sig.mldsa65.as_slice())?;

        let ed25519_verifying_key = VerifyingKey::from_bytes(&self.ed25519).map_err(|error| {
            QuantumLinkError::Crypto(format!("invalid Ed25519 verifying key: {error}"))
        })?;
        let ed25519_signature = Ed25519Signature::from_bytes(&sig.ed25519);
        ed25519_verifying_key
            .verify(message, &ed25519_signature)
            .map_err(|error| {
                QuantumLinkError::Auth(format!("Ed25519 verification failed: {error}"))
            })?;

        let mldsa = mldsa65()?;
        let public_key = mldsa
            .public_key_from_bytes(self.mldsa65.as_slice())
            .ok_or_else(|| {
                QuantumLinkError::Crypto("invalid ML-DSA-65 public key length".to_owned())
            })?;
        let signature = mldsa
            .signature_from_bytes(sig.mldsa65.as_slice())
            .ok_or_else(|| {
                QuantumLinkError::Crypto("invalid ML-DSA-65 signature length".to_owned())
            })?;
        mldsa
            .verify(message, &signature, &public_key)
            .map_err(|error| {
                QuantumLinkError::Auth(format!("ML-DSA-65 verification failed: {error}"))
            })
    }

    /// Returns a 32-byte fingerprint for use in pairing flows.
    #[must_use]
    pub fn fingerprint(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(self.ed25519);
        hasher.update(self.mldsa65.as_slice());
        hasher.finalize().into()
    }
}

fn mlkem768() -> QuantumLinkResult<Kem> {
    oqs::init();
    Kem::new(KemAlgorithm::MlKem768)
        .map_err(|error| QuantumLinkError::Crypto(format!("ML-KEM-768 unavailable: {error}")))
}

fn mldsa65() -> QuantumLinkResult<Sig> {
    oqs::init();
    Sig::new(SigAlgorithm::MlDsa65)
        .map_err(|error| QuantumLinkError::Crypto(format!("ML-DSA-65 unavailable: {error}")))
}

fn derive_hybrid_secret(
    classical_secret: &[u8],
    pq_secret: &[u8],
) -> QuantumLinkResult<HybridSharedSecret> {
    let mut combined_secret = Vec::with_capacity(classical_secret.len() + pq_secret.len());
    combined_secret.extend_from_slice(classical_secret);
    combined_secret.extend_from_slice(pq_secret);

    let hkdf = Hkdf::<Sha3_256>::new(Some(HYBRID_KEM_SALT), combined_secret.as_slice());
    let mut output = [0_u8; HYBRID_KEM_SECRET_LEN];
    hkdf.expand(HYBRID_KEM_INFO, &mut output)
        .map_err(|error| QuantumLinkError::Crypto(format!("HKDF expansion failed: {error}")))?;
    combined_secret.zeroize();

    Ok(HybridSharedSecret(output))
}

fn validate_mlkem768_public_key(public_key: &[u8]) -> QuantumLinkResult<()> {
    if public_key.len() == MLKEM768_PUBLIC_KEY_LEN {
        Ok(())
    } else {
        Err(QuantumLinkError::Crypto(format!(
            "invalid ML-KEM-768 public key length: expected {MLKEM768_PUBLIC_KEY_LEN}, got {}",
            public_key.len()
        )))
    }
}

fn validate_mlkem768_ciphertext(ciphertext: &[u8]) -> QuantumLinkResult<()> {
    if ciphertext.len() == MLKEM768_CIPHERTEXT_LEN {
        Ok(())
    } else {
        Err(QuantumLinkError::Crypto(format!(
            "invalid ML-KEM-768 ciphertext length: expected {MLKEM768_CIPHERTEXT_LEN}, got {}",
            ciphertext.len()
        )))
    }
}

fn validate_mldsa65_public_key(public_key: &[u8]) -> QuantumLinkResult<()> {
    if public_key.len() == MLDSA65_PUBLIC_KEY_LEN {
        Ok(())
    } else {
        Err(QuantumLinkError::Crypto(format!(
            "invalid ML-DSA-65 public key length: expected {MLDSA65_PUBLIC_KEY_LEN}, got {}",
            public_key.len()
        )))
    }
}

fn validate_mldsa65_signature(signature: &[u8]) -> QuantumLinkResult<()> {
    if signature.len() == MLDSA65_SIGNATURE_LEN {
        Ok(())
    } else {
        Err(QuantumLinkError::Crypto(format!(
            "invalid ML-DSA-65 signature length: expected {MLDSA65_SIGNATURE_LEN}, got {}",
            signature.len()
        )))
    }
}

mod ed25519_signature_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    use super::ED25519_SIGNATURE_LEN;

    pub fn serialize<S>(
        bytes: &[u8; ED25519_SIGNATURE_LEN],
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; ED25519_SIGNATURE_LEN], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        if bytes.len() != ED25519_SIGNATURE_LEN {
            return Err(serde::de::Error::invalid_length(
                bytes.len(),
                &"an Ed25519 signature with 64 bytes",
            ));
        }

        let mut signature = [0_u8; ED25519_SIGNATURE_LEN];
        signature.copy_from_slice(bytes.as_slice());
        Ok(signature)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use super::{
        hybrid_kem_decapsulate, hybrid_kem_encapsulate, HybridCiphertext, HybridKemKeypair,
        HybridSigningKey,
    };
    use sha2::{Digest, Sha256};
    use zeroize::Zeroize;

    const EXPECTED_MLKEM768_KAT_HASH: &str =
        "5352539586b6c3df58be6158a6250aeff402bd73060b0a3de68850ac074c17c3";

    #[test]
    fn hybrid_kem_roundtrip() {
        let keypair = HybridKemKeypair::generate().unwrap();
        let public_key = keypair.public_key();

        let (ciphertext, shared_secret_enc) = hybrid_kem_encapsulate(&public_key).unwrap();
        let shared_secret_dec = hybrid_kem_decapsulate(&keypair, &ciphertext).unwrap();

        assert_eq!(shared_secret_enc.as_ref(), shared_secret_dec.as_ref());
    }

    #[test]
    fn hybrid_kem_rejects_tampered_x25519_ct() {
        let keypair = HybridKemKeypair::generate().unwrap();
        let public_key = keypair.public_key();
        let (mut ciphertext, shared_secret_enc) = hybrid_kem_encapsulate(&public_key).unwrap();
        ciphertext.x25519_ephemeral_pk[0] ^= 0x01;

        match hybrid_kem_decapsulate(&keypair, &ciphertext) {
            Ok(shared_secret_dec) => {
                assert_ne!(shared_secret_enc.as_ref(), shared_secret_dec.as_ref())
            }
            Err(_) => {}
        }
    }

    #[test]
    fn hybrid_kem_rejects_tampered_mlkem_ct() {
        let keypair = HybridKemKeypair::generate().unwrap();
        let public_key = keypair.public_key();
        let (mut ciphertext, shared_secret_enc) = hybrid_kem_encapsulate(&public_key).unwrap();
        ciphertext.mlkem768_ct[0] ^= 0x01;

        match hybrid_kem_decapsulate(&keypair, &ciphertext) {
            Ok(shared_secret_dec) => {
                assert_ne!(shared_secret_enc.as_ref(), shared_secret_dec.as_ref())
            }
            Err(_) => {}
        }
    }

    #[test]
    fn hybrid_sig_roundtrip() {
        let signing_key = HybridSigningKey::generate().unwrap();
        let verifying_key = signing_key.verifying_key();
        let message = b"quantumlink hybrid signature roundtrip";
        let signature = signing_key.sign(message).unwrap();

        verifying_key.verify(message, &signature).unwrap();
    }

    #[test]
    fn hybrid_sig_rejects_tampered_message() {
        let signing_key = HybridSigningKey::generate().unwrap();
        let verifying_key = signing_key.verifying_key();
        let signature = signing_key.sign(b"original message").unwrap();

        assert!(verifying_key
            .verify(b"tampered message", &signature)
            .is_err());
    }

    #[test]
    fn hybrid_sig_rejects_tampered_ed25519() {
        let signing_key = HybridSigningKey::generate().unwrap();
        let verifying_key = signing_key.verifying_key();
        let message = b"ed25519 tamper";
        let mut signature = signing_key.sign(message).unwrap();
        signature.ed25519[0] ^= 0x01;

        assert!(verifying_key.verify(message, &signature).is_err());
    }

    #[test]
    fn hybrid_sig_rejects_tampered_mldsa() {
        let signing_key = HybridSigningKey::generate().unwrap();
        let verifying_key = signing_key.verifying_key();
        let message = b"mldsa tamper";
        let mut signature = signing_key.sign(message).unwrap();
        signature.mldsa65[0] ^= 0x01;

        assert!(verifying_key.verify(message, &signature).is_err());
    }

    #[test]
    fn hybrid_signing_key_secret_roundtrip() {
        let signing_key = HybridSigningKey::generate().unwrap();
        let exported = signing_key.export_secret();
        let restored = HybridSigningKey::import_secret(exported).unwrap();
        let message = b"restore secret key";
        let signature = restored.sign(message).unwrap();

        restored
            .verifying_key()
            .verify(message, &signature)
            .unwrap();
    }

    #[test]
    fn keypair_zeroizes_on_drop() {
        let mut keypair = HybridKemKeypair::generate().unwrap();
        let _ = std::hint::black_box(&keypair);

        keypair.zeroize();

        assert!(keypair.x25519_secret.iter().all(|byte| *byte == 0));
        assert!(keypair.x25519_public.iter().all(|byte| *byte == 0));
        assert!(keypair.mlkem768_secret.iter().all(|byte| *byte == 0));
        assert!(keypair.mlkem768_public.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn mlkem768_kat_vector() {
        let helper = build_kat_helper();
        let output = Command::new(&helper).arg("ML-KEM-768").output().unwrap();
        assert!(output.status.success());

        let mut hasher = Sha256::new();
        hasher.update(output.stdout);
        let digest = format!("{:x}", hasher.finalize());

        assert_eq!(digest, EXPECTED_MLKEM768_KAT_HASH);
    }

    fn build_kat_helper() -> PathBuf {
        let out_dir = locate_oqs_out_dir();
        let liboqs_tests = locate_liboqs_tests_dir();
        let liboqs_root = liboqs_tests.parent().unwrap().to_path_buf();
        let helper_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/test-artifacts");
        fs::create_dir_all(&helper_dir).unwrap();
        let helper_include_dir = helper_dir.join("include/oqs");
        fs::create_dir_all(&helper_include_dir).unwrap();
        fs::copy(
            liboqs_root.join("src/common/rand/rand_nist.h"),
            helper_include_dir.join("rand_nist.h"),
        )
        .unwrap();
        fs::copy(
            liboqs_root.join("src/common/sha3/sha3.h"),
            helper_include_dir.join("sha3.h"),
        )
        .unwrap();
        fs::copy(
            liboqs_root.join("src/common/aes/aes.h"),
            helper_include_dir.join("aes.h"),
        )
        .unwrap();

        let binary_path = helper_dir.join("kat_kem_helper");
        let status = Command::new("cc")
            .arg(liboqs_tests.join("kat_kem.c"))
            .arg(liboqs_tests.join("test_helpers.c"))
            .arg(liboqs_root.join("src/common/rand/rand_nist.c"))
            .arg(out_dir.join("lib/liboqs.a"))
            .arg("-I")
            .arg(helper_dir.join("include"))
            .arg("-I")
            .arg(out_dir.join("include"))
            .arg("-I")
            .arg(&liboqs_tests)
            .arg("-I")
            .arg(liboqs_root.join("src"))
            .arg("-I")
            .arg(liboqs_root.join("src/common"))
            .arg("-I")
            .arg(liboqs_root.join("src/common/rand"))
            .arg("-I")
            .arg(liboqs_root.join("src/common/sha3"))
            .arg("-o")
            .arg(&binary_path)
            .status()
            .unwrap();
        assert!(status.success());

        binary_path
    }

    fn locate_oqs_out_dir() -> PathBuf {
        let build_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/build");
        for entry in fs::read_dir(build_root).unwrap() {
            let path = entry.unwrap().path().join("out");
            if path.join("include/oqs/oqs.h").exists() && path.join("lib/liboqs.a").exists() {
                return path;
            }
        }

        panic!("failed to locate oqs-sys build output");
    }

    fn locate_liboqs_tests_dir() -> PathBuf {
        let cargo_registry = Path::new(&std::env::var("HOME").unwrap()).join(".cargo/registry/src");
        for registry_root in fs::read_dir(cargo_registry).unwrap() {
            let candidate = registry_root
                .unwrap()
                .path()
                .join("oqs-sys-0.10.1+liboqs-0.12.0/liboqs/tests");
            if candidate.join("kat_kem.c").exists() {
                return candidate;
            }
        }

        panic!("failed to locate vendored liboqs tests directory");
    }

    #[test]
    fn hybrid_ciphertext_roundtrip_serde() {
        let keypair = HybridKemKeypair::generate().unwrap();
        let public_key = keypair.public_key();
        let (ciphertext, _) = hybrid_kem_encapsulate(&public_key).unwrap();

        let encoded = serde_json::to_vec(&ciphertext).unwrap();
        let decoded: HybridCiphertext = serde_json::from_slice(&encoded).unwrap();

        assert_eq!(ciphertext, decoded);
    }
}
