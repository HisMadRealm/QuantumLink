//! Pairing flows for QuantumLink devices.

#![forbid(unsafe_code)]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ql_core::{
	CertificateAuthority, DeviceCertificate, DeviceIdentity, KeyStorageLayout,
	QuantumLinkError, QuantumLinkResult, RevocationList,
};
use ql_crypto::{HybridSignature, HybridVerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use spake2::{Ed25519Group, Identity, Password, Spake2};
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

const QR_SCHEME: &str = "ql";
const QR_HOST: &str = "pair";
const SETUP_KEY_PREFIX: &str = "qlsk1";

const WORMHOLE_LEFT_WORDS: [&str; 64] = [
	"amber", "anchor", "apple", "aster", "atlas", "bamboo", "beacon", "birch", "bison",
	"blade", "blossom", "bluejay", "canyon", "cedar", "cipher", "clover", "comet", "coral",
	"cosmos", "cricket", "crystal", "dawn", "delta", "ember", "falcon", "fern", "fjord",
	"forest", "galaxy", "garden", "glacier", "granite", "guitar", "harbor", "hazel", "horizon",
	"island", "jasmine", "juniper", "lantern", "meadow", "meteor", "mist", "nebula", "oasis",
	"onyx", "orbit", "orchid", "otter", "phoenix", "pine", "prairie", "quartz", "raven",
	"river", "saffron", "sage", "sunrise", "tiger", "topaz", "violet", "willow", "zenith", "zephyr",
];

const WORMHOLE_RIGHT_WORDS: [&str; 64] = [
	"acorn", "arrow", "badger", "brook", "cabin", "canopy", "cardinal", "cascade", "castle",
	"circle", "cloud", "cobalt", "coyote", "drift", "echo", "elm", "feather", "field",
	"firefly", "flint", "gale", "geyser", "glow", "grove", "harvest", "heron", "hollow",
	"iris", "ivory", "lagoon", "leaf", "lilac", "lunar", "marble", "monsoon", "moon",
	"mountain", "nebula", "nectar", "nova", "ocean", "opal", "pebble", "petal", "reef",
	"ridge", "rook", "shadow", "shell", "signal", "solstice", "sparrow", "spruce", "stone",
	"stream", "summit", "thunder", "tidal", "trail", "valley", "voyage", "wave", "wind",
	"winter",
];

const EMOJI_WORDS: [&str; 64] = [
	"otter", "falcon", "maple", "rocket", "snowflake", "comet", "lantern", "ocean", "tiger",
	"sunrise", "honeybee", "anchor", "willow", "piano", "volcano", "pepper", "crown", "violet",
	"sapphire", "harbor", "saturn", "river", "peppermint", "firefly", "mountain", "prism",
	"starfish", "forest", "cactus", "skylark", "acorn", "thunder", "seashell", "orbit", "mercury",
	"glacier", "phoenix", "raindrop", "topaz", "dolphin", "snowy", "meadow", "cobalt", "almond",
	"feather", "nebula", "orchid", "ember", "quartz", "aurora", "marigold", "cricket", "lighthouse",
	"raven", "lotus", "granite", "jasmine", "moonbeam", "cedar", "solstice", "tidal", "zenith", "zephyr",
	"coral",
];

/// Signed device certificate exchanged during enrollment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedDeviceCertificate {
	/// Unsigned certificate body.
	pub certificate: DeviceCertificate,
	/// Human-readable issuer name for UI surfaces.
	pub issuer_name: String,
	/// Unix timestamp when the certificate was issued.
	pub issued_at: u64,
	/// Hybrid CA signature over the certificate body.
	pub signature: HybridSignature,
}

impl SignedDeviceCertificate {
	/// Verifies the signed certificate against the trusted authority and revocation state.
	pub fn verify(
		&self,
		authority: &CertificateAuthority,
		verifying_key: &HybridVerifyingKey,
		revocations: &RevocationList,
		now: u64,
	) -> QuantumLinkResult<CertificateVerificationReport> {
		if self.certificate.issuer_fingerprint != authority.fingerprint {
			return Err(QuantumLinkError::Auth(
				"certificate issuer fingerprint does not match the trusted authority".to_owned(),
			));
		}

		verifying_key.verify(&certificate_signing_message(&self.certificate)?, &self.signature)?;

		Ok(CertificateVerificationReport {
			serial: self.certificate.serial.clone(),
			device_name: self.certificate.device_name.clone(),
			issuer_fingerprint: self.certificate.issuer_fingerprint.clone(),
			valid_signature: true,
			valid_at_time: self.certificate.is_valid_at(now),
			revoked: revocations.is_revoked(&self.certificate.serial),
			expires_at: self.certificate.valid_until,
		})
	}

	/// Projects the signed certificate into a local device identity view.
	#[must_use]
	pub fn device_identity(&self, storage: KeyStorageLayout) -> DeviceIdentity {
		DeviceIdentity {
			certificate: self.certificate.clone(),
			storage,
		}
	}
}

/// Trust bundle exchanged after pairing completes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnrollmentBundle {
	/// Trusted certificate authority metadata.
	pub authority: CertificateAuthority,
	/// Trusted CA verifying key used to validate the device certificate.
	pub verifying_key: HybridVerifyingKey,
	/// Enrolled device certificate bundle.
	pub device: SignedDeviceCertificate,
	/// Current revocation snapshot distributed with the enrollment.
	pub revocations: RevocationList,
	/// Unix timestamp when the bundle was exported.
	pub exported_at: u64,
}

impl EnrollmentBundle {
	/// Verifies the enrollment bundle using its embedded trust anchor.
	pub fn verify(&self, now: u64) -> QuantumLinkResult<CertificateVerificationReport> {
		self.device
			.verify(&self.authority, &self.verifying_key, &self.revocations, now)
	}

	/// Projects the enrolled device into a local device identity view.
	#[must_use]
	pub fn device_identity(&self, storage: KeyStorageLayout) -> DeviceIdentity {
		self.device.device_identity(storage)
	}
}

/// Verification result for a signed device certificate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertificateVerificationReport {
	/// Stable certificate serial identifier.
	pub serial: String,
	/// Human-readable device name.
	pub device_name: String,
	/// Issuer fingerprint bound into the certificate.
	pub issuer_fingerprint: String,
	/// Whether the cryptographic signature verified.
	pub valid_signature: bool,
	/// Whether the certificate is currently inside its validity window.
	pub valid_at_time: bool,
	/// Whether the certificate serial appears in the revocation snapshot.
	pub revoked: bool,
	/// Unix timestamp when the certificate expires.
	pub expires_at: u64,
}

/// Pairing-side role used to derive distinct mailbox identities from one rendezvous id.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PairingRole {
	/// Device that initiates the pairing flow.
	Initiator,
	/// Device that responds to the pairing flow.
	Responder,
}

impl PairingRole {
	/// Returns the wire representation used in mailbox identities.
	#[must_use]
	pub fn as_str(self) -> &'static str {
		match self {
			Self::Initiator => "initiator",
			Self::Responder => "responder",
		}
	}

	/// Parses a pairing role from CLI or transport text.
	pub fn parse(value: &str) -> QuantumLinkResult<Self> {
		match value.trim().to_ascii_lowercase().as_str() {
			"initiator" => Ok(Self::Initiator),
			"responder" => Ok(Self::Responder),
			other => Err(QuantumLinkError::Pairing(format!(
				"invalid pairing role: {other}; expected initiator or responder"
			))),
		}
	}
}

/// Shared mailbox identity derived from a rendezvous id and pairing role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingMailboxIdentity {
	pairing_id: String,
	role: PairingRole,
}

impl PairingMailboxIdentity {
	/// Builds a mailbox identity for one side of the pairing flow.
	pub fn new(pairing_id: impl Into<String>, role: PairingRole) -> QuantumLinkResult<Self> {
		let pairing_id = pairing_id.into();
		if pairing_id.trim().is_empty() {
			return Err(QuantumLinkError::Pairing(
				"pairing mailbox identity must not be empty".to_owned(),
			));
		}

		Ok(Self { pairing_id, role })
	}

	/// Returns the signal-mailbox auth token for this participant.
	#[must_use]
	pub fn token(&self) -> String {
		format!("{}:{}", self.pairing_id, self.role.as_str())
	}

	/// Returns the pairing role.
	#[must_use]
	pub fn role(&self) -> PairingRole {
		self.role
	}
}

/// Typed payload exchanged through the pairing mailbox.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PairingMailboxPayload {
	/// SPAKE2 message bytes used during remote pairing.
	Spake2Message(#[serde(with = "serde_bytes")] Vec<u8>),
	/// Enrollment bundle handed off after pairing succeeds.
	EnrollmentBundle(EnrollmentBundle),
}

impl PairingMailboxPayload {
	/// Encodes the payload for signal-mailbox transport.
	pub fn encode(&self) -> QuantumLinkResult<Vec<u8>> {
		serde_json::to_vec(self).map_err(|error| {
			QuantumLinkError::Pairing(format!("failed to serialize mailbox payload: {error}"))
		})
	}

	/// Decodes a signal-mailbox payload into a typed pairing message.
	pub fn decode(bytes: &[u8]) -> QuantumLinkResult<Self> {
		serde_json::from_slice(bytes).map_err(|error| {
			QuantumLinkError::Pairing(format!("failed to decode mailbox payload: {error}"))
		})
	}

	/// Returns the enrollment bundle if this payload carries one.
	pub fn into_enrollment_bundle(self) -> QuantumLinkResult<EnrollmentBundle> {
		match self {
			Self::EnrollmentBundle(bundle) => Ok(bundle),
			Self::Spake2Message(_) => Err(QuantumLinkError::Pairing(
				"mailbox payload did not contain an enrollment bundle".to_owned(),
			)),
		}
	}
}

/// QR code payload exchanged during in-person pairing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QrPairingOffer {
	/// Peer WireGuard public key.
	pub wg_public_key: [u8; 32],
	/// Rosenpass public key fingerprint.
	pub rosenpass_fingerprint: String,
	/// Rendezvous endpoint or mailbox host for the second phase.
	pub rendezvous: String,
	/// Ephemeral public key used to bootstrap the authenticated exchange.
	pub ephemeral_public_key: Vec<u8>,
	/// Unix timestamp after which the QR code is invalid.
	pub expires_at: u64,
}

impl QrPairingOffer {
	/// Encodes the pairing offer as a `ql://pair?...` URI.
	///
	/// # Errors
	///
	/// Returns an error if the rendezvous host cannot be encoded as a valid URL.
	pub fn to_uri(&self) -> QuantumLinkResult<String> {
		let mut url = Url::parse("ql://pair").map_err(|error| {
			QuantumLinkError::Pairing(format!("invalid QR pairing base URL: {error}"))
		})?;
		url.query_pairs_mut()
			.append_pair("wgkey", &URL_SAFE_NO_PAD.encode(self.wg_public_key))
			.append_pair("rpfp", &self.rosenpass_fingerprint)
			.append_pair("rendezvous", &self.rendezvous)
			.append_pair("ephkey", &URL_SAFE_NO_PAD.encode(&self.ephemeral_public_key))
			.append_pair("expires", &self.expires_at.to_string());
		Ok(url.to_string())
	}

	/// Parses a `ql://pair?...` URI into a QR pairing offer.
	///
	/// # Errors
	///
	/// Returns an error if required fields are missing or malformed.
	pub fn from_uri(uri: &str) -> QuantumLinkResult<Self> {
		let url = Url::parse(uri)
			.map_err(|error| QuantumLinkError::Pairing(format!("invalid QR pairing URI: {error}")))?;
		if url.scheme() != QR_SCHEME || url.host_str() != Some(QR_HOST) {
			return Err(QuantumLinkError::Pairing(
				"QR pairing URI must use ql://pair".to_owned(),
			));
		}

		let params = url.query_pairs().collect::<std::collections::HashMap<_, _>>();
		let wg_public_key = decode_fixed_base64_32(
			params
				.get("wgkey")
				.ok_or_else(|| QuantumLinkError::Pairing("QR pairing URI missing wgkey".to_owned()))?,
		)?;
		let ephemeral_public_key = URL_SAFE_NO_PAD
			.decode(
				params.get("ephkey").ok_or_else(|| {
					QuantumLinkError::Pairing("QR pairing URI missing ephkey".to_owned())
				})?.as_bytes(),
			)
			.map_err(|error| {
				QuantumLinkError::Pairing(format!("invalid QR ephemeral key encoding: {error}"))
			})?;

		Ok(Self {
			wg_public_key,
			rosenpass_fingerprint: params
				.get("rpfp")
				.ok_or_else(|| {
					QuantumLinkError::Pairing("QR pairing URI missing rpfp".to_owned())
				})?
				.to_string(),
			rendezvous: params
				.get("rendezvous")
				.ok_or_else(|| {
					QuantumLinkError::Pairing("QR pairing URI missing rendezvous".to_owned())
				})?
				.to_string(),
			ephemeral_public_key,
			expires_at: params
				.get("expires")
				.ok_or_else(|| {
					QuantumLinkError::Pairing("QR pairing URI missing expires".to_owned())
				})?
				.parse::<u64>()
				.map_err(|error| {
					QuantumLinkError::Pairing(format!("invalid QR expires value: {error}"))
				})?,
		})
	}

	/// Returns whether the QR offer has expired relative to `now_unix`.
	#[must_use]
	pub fn is_expired(&self, now_unix: u64) -> bool {
		now_unix >= self.expires_at
	}
}

/// Human-readable wormhole pairing code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WormholeCode(String);

impl WormholeCode {
	/// Generates a new code like `542-garden-orbit`.
	#[must_use]
	pub fn generate() -> Self {
		let random = Uuid::new_v4();
		let bytes = random.as_bytes();
		let number = u16::from_be_bytes([bytes[0], bytes[1]]) % 1024;
		let left = WORMHOLE_LEFT_WORDS[(bytes[2] as usize) % WORMHOLE_LEFT_WORDS.len()];
		let right = WORMHOLE_RIGHT_WORDS[(bytes[3] as usize) % WORMHOLE_RIGHT_WORDS.len()];
		Self(format!("{number}-{left}-{right}"))
	}

	/// Parses and normalizes a user-entered wormhole code.
	///
	/// # Errors
	///
	/// Returns an error if the code does not match the expected `number-word-word` format.
	pub fn parse(code: &str) -> QuantumLinkResult<Self> {
		let normalized = code.trim().to_ascii_lowercase();
		let mut parts = normalized.split('-');
		let Some(number_part) = parts.next() else {
			return Err(invalid_wormhole_code());
		};
		let Some(left_part) = parts.next() else {
			return Err(invalid_wormhole_code());
		};
		let Some(right_part) = parts.next() else {
			return Err(invalid_wormhole_code());
		};
		if parts.next().is_some() {
			return Err(invalid_wormhole_code());
		}

		let number = number_part.parse::<u16>().map_err(|_| invalid_wormhole_code())?;
		if number >= 1024
			|| !WORMHOLE_LEFT_WORDS.contains(&left_part)
			|| !WORMHOLE_RIGHT_WORDS.contains(&right_part)
		{
			return Err(invalid_wormhole_code());
		}

		Ok(Self(format!("{number}-{left_part}-{right_part}")))
	}

	/// Returns the normalized textual form.
	#[must_use]
	pub fn as_str(&self) -> &str {
		&self.0
	}
}

/// Single-use setup key for adding a device to an existing mesh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupKey {
	/// Random opaque token.
	pub token: String,
	/// Unix timestamp after which the key is invalid.
	pub expires_at: u64,
}

impl SetupKey {
	/// Generates a new setup key with the requested TTL.
	#[must_use]
	pub fn generate(ttl: Duration) -> Self {
		let now = unix_timestamp(SystemTime::now());
		let token = URL_SAFE_NO_PAD.encode(Uuid::new_v4().as_bytes());
		Self {
			token,
			expires_at: now.saturating_add(ttl.as_secs()),
		}
	}

	/// Encodes the setup key for UI or CLI transport.
	#[must_use]
	pub fn encode(&self) -> String {
		format!("{SETUP_KEY_PREFIX}.{}.{}", self.expires_at, self.token)
	}

	/// Parses a serialized setup key.
	///
	/// # Errors
	///
	/// Returns an error if the setup key format is invalid.
	pub fn decode(encoded: &str) -> QuantumLinkResult<Self> {
		let mut parts = encoded.split('.');
		if parts.next() != Some(SETUP_KEY_PREFIX) {
			return Err(QuantumLinkError::Pairing("invalid setup key prefix".to_owned()));
		}
		let expires_at = parts
			.next()
			.ok_or_else(|| QuantumLinkError::Pairing("setup key missing expiry".to_owned()))?
			.parse::<u64>()
			.map_err(|error| QuantumLinkError::Pairing(format!("invalid setup key expiry: {error}")))?;
		let token = parts
			.next()
			.ok_or_else(|| QuantumLinkError::Pairing("setup key missing token".to_owned()))?
			.to_owned();
		if parts.next().is_some() || token.is_empty() {
			return Err(QuantumLinkError::Pairing("invalid setup key format".to_owned()));
		}

		Ok(Self { token, expires_at })
	}

	/// Returns whether the key is expired relative to `now_unix`.
	#[must_use]
	pub fn is_expired(&self, now_unix: u64) -> bool {
		now_unix >= self.expires_at
	}
}

/// Shared secret derived from the wormhole pairing PAKE.
#[derive(Debug, Clone)]
pub struct PairingSharedSecret(Zeroizing<Vec<u8>>);

impl PairingSharedSecret {
	/// Returns the raw session secret bytes.
	#[must_use]
	pub fn as_bytes(&self) -> &[u8] {
		self.0.as_slice()
	}

	/// Derives five stable emoji-verification words from the shared secret.
	#[must_use]
	pub fn emoji_verification(&self) -> [String; 5] {
		emoji_verification(self.as_bytes())
	}
}

/// Symmetric SPAKE2 state for magic-wormhole pairing.
#[derive(Debug, PartialEq, Eq)]
pub struct WormholePairingSession {
	state: Spake2<Ed25519Group>,
}

impl WormholePairingSession {
	/// Starts a symmetric SPAKE2 exchange from a wormhole code and rendezvous identifier.
	///
	/// # Errors
	///
	/// Returns an error if the code format is invalid.
	pub fn start(code: &str, rendezvous_id: &str) -> QuantumLinkResult<(Self, Vec<u8>)> {
		let code = WormholeCode::parse(code)?;
		if rendezvous_id.trim().is_empty() {
			return Err(QuantumLinkError::Pairing(
				"wormhole rendezvous_id must not be empty".to_owned(),
			));
		}

		let password = Password::new(code.as_str().as_bytes());
		let identity = Identity::new(rendezvous_id.as_bytes());
		let (state, outbound_message) =
			Spake2::<Ed25519Group>::start_symmetric(&password, &identity);
		Ok((Self { state }, outbound_message))
	}

	/// Completes a symmetric SPAKE2 exchange.
	///
	/// # Errors
	///
	/// Returns an error if the inbound SPAKE2 message is malformed.
	pub fn finish(self, inbound_message: &[u8]) -> QuantumLinkResult<PairingSharedSecret> {
		let shared_secret = self.state.finish(inbound_message).map_err(|error| {
			QuantumLinkError::Pairing(format!("SPAKE2 pairing failed: {error}"))
		})?;
		Ok(PairingSharedSecret(Zeroizing::new(shared_secret)))
	}
}

fn decode_fixed_base64_32(input: &str) -> QuantumLinkResult<[u8; 32]> {
	let bytes = URL_SAFE_NO_PAD
		.decode(input.as_bytes())
		.map_err(|error| QuantumLinkError::Pairing(format!("invalid base64 field: {error}")))?;
	bytes.try_into().map_err(|_| {
		QuantumLinkError::Pairing("expected a 32-byte base64 field".to_owned())
	})
}

fn invalid_wormhole_code() -> QuantumLinkError {
	QuantumLinkError::Pairing(
		"wormhole code must match number-word-word using the QuantumLink word list".to_owned(),
	)
}

fn unix_timestamp(now: SystemTime) -> u64 {
	now.duration_since(UNIX_EPOCH)
		.unwrap_or_default()
		.as_secs()
}

fn emoji_verification(shared_secret: &[u8]) -> [String; 5] {
	let digest = Sha256::digest(shared_secret);
	std::array::from_fn(|index| {
		let value = digest[index] as usize % EMOJI_WORDS.len();
		EMOJI_WORDS[value].to_owned()
	})
}

fn certificate_signing_message(certificate: &DeviceCertificate) -> QuantumLinkResult<Vec<u8>> {
	serde_json::to_vec(certificate).map_err(|error| {
		QuantumLinkError::Config(format!("failed to serialize certificate: {error}"))
	})
}

#[cfg(test)]
mod tests {
	use std::time::Duration;

	use base64::engine::general_purpose::URL_SAFE_NO_PAD;
	use base64::Engine as _;
	use ql_core::{CertificateAuthority, DeviceCertificate, RevocationList, RevocationRecord};
	use ql_crypto::HybridSigningKey;

	use super::{
		EnrollmentBundle, PairingMailboxIdentity, PairingMailboxPayload, PairingRole,
		QrPairingOffer, SetupKey, SignedDeviceCertificate, WormholeCode,
		WormholePairingSession,
	};

	#[test]
	fn qr_pairing_offer_roundtrips_through_uri() {
		let offer = QrPairingOffer {
			wg_public_key: [7_u8; 32],
			rosenpass_fingerprint: "4cf0d7c1b62c0d93".to_owned(),
			rendezvous: "relay.example.test/mailbox/123".to_owned(),
			ephemeral_public_key: vec![1, 2, 3, 4, 5, 6],
			expires_at: 1_900_000_000,
		};

		let uri = offer.to_uri().unwrap();
		let decoded = QrPairingOffer::from_uri(&uri).unwrap();

		assert_eq!(decoded, offer);
		assert!(!decoded.is_expired(1_800_000_000));
	}

	#[test]
	fn wormhole_code_normalizes_and_validates() {
		let code = WormholeCode::parse("42-GARDEN-NEBULA").unwrap();
		assert_eq!(code.as_str(), "42-garden-nebula");
		assert!(WormholeCode::parse("2048-garden-nebula").is_err());
		assert!(WormholeCode::generate().as_str().split('-').count() == 3);
	}

	#[test]
	fn setup_key_roundtrips_and_expires() {
		let key = SetupKey::generate(Duration::from_secs(60));
		let encoded = key.encode();
		let decoded = SetupKey::decode(&encoded).unwrap();

		assert_eq!(decoded, key);
		assert!(!decoded.is_expired(decoded.expires_at.saturating_sub(1)));
		assert!(decoded.is_expired(decoded.expires_at));
	}

	#[test]
	fn wormhole_spake2_roundtrip_derives_matching_secret() {
		let code = "542-guitar-nebula";
		let rendezvous = "self-hosted-mailbox-session-123";

		let (alice, alice_msg) = WormholePairingSession::start(code, rendezvous).unwrap();
		let (bob, bob_msg) = WormholePairingSession::start(code, rendezvous).unwrap();

		let alice_secret = alice.finish(&bob_msg).unwrap();
		let bob_secret = bob.finish(&alice_msg).unwrap();

		assert_eq!(alice_secret.as_bytes(), bob_secret.as_bytes());
		assert_eq!(
			alice_secret.emoji_verification(),
			bob_secret.emoji_verification()
		);
	}

	#[test]
	fn enrollment_bundle_verifies_signed_certificate() {
		let signing_key = HybridSigningKey::generate().unwrap();
		let verifying_key = signing_key.verifying_key();
		let authority = CertificateAuthority {
			name: "Home Mesh".to_owned(),
			fingerprint: URL_SAFE_NO_PAD.encode(verifying_key.fingerprint()),
			created_at: 1_700_000_000,
		};
		let certificate = DeviceCertificate {
			serial: "cert-123".to_owned(),
			device_name: "Laptop".to_owned(),
			overlay_ip: "10.42.0.20".parse().unwrap(),
			groups: vec!["personal".to_owned()],
			wg_public_key: [7_u8; 32],
			rosenpass_fingerprint: "rp-fingerprint".to_owned(),
			issuer_fingerprint: authority.fingerprint.clone(),
			valid_from: 1_700_000_100,
			valid_until: 1_700_086_500,
		};
		let signed = SignedDeviceCertificate {
			certificate: certificate.clone(),
			issuer_name: authority.name.clone(),
			issued_at: 1_700_000_100,
			signature: signing_key
				.sign(&super::certificate_signing_message(&certificate).unwrap())
				.unwrap(),
		};
		let bundle = EnrollmentBundle {
			authority,
			verifying_key,
			device: signed,
			revocations: RevocationList::default(),
			exported_at: 1_700_000_150,
		};

		let report = bundle.verify(1_700_000_200).unwrap();
		assert!(report.valid_signature);
		assert!(report.valid_at_time);
		assert!(!report.revoked);
	}

	#[test]
	fn enrollment_bundle_reports_revoked_certificate() {
		let signing_key = HybridSigningKey::generate().unwrap();
		let verifying_key = signing_key.verifying_key();
		let authority = CertificateAuthority {
			name: "Home Mesh".to_owned(),
			fingerprint: URL_SAFE_NO_PAD.encode(verifying_key.fingerprint()),
			created_at: 1_700_000_000,
		};
		let certificate = DeviceCertificate {
			serial: "cert-123".to_owned(),
			device_name: "Laptop".to_owned(),
			overlay_ip: "10.42.0.20".parse().unwrap(),
			groups: vec!["personal".to_owned()],
			wg_public_key: [7_u8; 32],
			rosenpass_fingerprint: "rp-fingerprint".to_owned(),
			issuer_fingerprint: authority.fingerprint.clone(),
			valid_from: 1_700_000_100,
			valid_until: 1_700_086_500,
		};
		let signed = SignedDeviceCertificate {
			certificate: certificate.clone(),
			issuer_name: authority.name.clone(),
			issued_at: 1_700_000_100,
			signature: signing_key
				.sign(&super::certificate_signing_message(&certificate).unwrap())
				.unwrap(),
		};
		let bundle = EnrollmentBundle {
			authority,
			verifying_key,
			device: signed,
			revocations: RevocationList {
				issued_at: 1_700_000_300,
				entries: vec![RevocationRecord {
					certificate_serial: "cert-123".to_owned(),
					reason: "lost device".to_owned(),
					revoked_at: 1_700_000_300,
				}],
			},
			exported_at: 1_700_000_350,
		};

		let report = bundle.verify(1_700_000_400).unwrap();
		assert!(report.revoked);
	}

	#[test]
	fn pairing_mailbox_identity_derives_distinct_tokens() {
		let initiator = PairingMailboxIdentity::new("mailbox-123", PairingRole::Initiator).unwrap();
		let responder = PairingMailboxIdentity::new("mailbox-123", PairingRole::Responder).unwrap();

		assert_eq!(initiator.token(), "mailbox-123:initiator");
		assert_eq!(responder.token(), "mailbox-123:responder");
		assert_ne!(initiator.token(), responder.token());
	}

	#[test]
	fn pairing_mailbox_payload_roundtrips_enrollment_bundle() {
		let signing_key = HybridSigningKey::generate().unwrap();
		let verifying_key = signing_key.verifying_key();
		let authority = CertificateAuthority {
			name: "Home Mesh".to_owned(),
			fingerprint: URL_SAFE_NO_PAD.encode(verifying_key.fingerprint()),
			created_at: 1_700_000_000,
		};
		let certificate = DeviceCertificate {
			serial: "cert-123".to_owned(),
			device_name: "Laptop".to_owned(),
			overlay_ip: "10.42.0.20".parse().unwrap(),
			groups: vec!["personal".to_owned()],
			wg_public_key: [7_u8; 32],
			rosenpass_fingerprint: "rp-fingerprint".to_owned(),
			issuer_fingerprint: authority.fingerprint.clone(),
			valid_from: 1_700_000_100,
			valid_until: 1_700_086_500,
		};
		let signed = SignedDeviceCertificate {
			certificate: certificate.clone(),
			issuer_name: authority.name.clone(),
			issued_at: 1_700_000_100,
			signature: signing_key
				.sign(&super::certificate_signing_message(&certificate).unwrap())
				.unwrap(),
		};
		let bundle = EnrollmentBundle {
			authority,
			verifying_key,
			device: signed,
			revocations: RevocationList::default(),
			exported_at: 1_700_000_150,
		};

		let encoded = PairingMailboxPayload::EnrollmentBundle(bundle.clone())
			.encode()
			.unwrap();
		let decoded = PairingMailboxPayload::decode(&encoded)
			.unwrap()
			.into_enrollment_bundle()
			.unwrap();

		assert_eq!(decoded, bundle);
	}
}
