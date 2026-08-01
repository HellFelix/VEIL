//! Ed25519 identity: public keys and the on-disk static keypair.

use std::fmt;
use std::fs;
use std::path::Path;
use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::SigningKey;
use rustls_pki_types::SubjectPublicKeyInfoDer;

use crate::Error;

/// Bytes in an Ed25519 public key.
const KEY_LEN: usize = 32;

/// The prefix every Ed25519 `SubjectPublicKeyInfo` starts with.
///
/// From [RFC 8410 §4](https://www.rfc-editor.org/rfc/rfc8410#section-4): a
/// `SEQUENCE` wrapping the `id-Ed25519` algorithm identifier and a `BIT STRING`
/// holding the key. For Ed25519 the encoding is fixed, so recognising it is a
/// prefix comparison rather than a parse, and VEIL needs no ASN.1 dependency.
const SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// Total length of an Ed25519 `SubjectPublicKeyInfo`.
const SPKI_LEN: usize = SPKI_PREFIX.len() + KEY_LEN;

/// The prefix of a PKCS#8 v1 private key holding an Ed25519 seed.
///
/// From [RFC 8410 §7](https://www.rfc-editor.org/rfc/rfc8410#section-7). Fixed
/// for the same reason as [`SPKI_PREFIX`].
const PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/// An Ed25519 public key, and therefore a peer's identity.
///
/// Rendered as `ed25519:<base64>` everywhere it is shown: config, logs, UI.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PublicKey([u8; KEY_LEN]);

impl PublicKey {
    /// Wraps raw key bytes.
    pub const fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// The raw key bytes.
    pub const fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Reads a key out of a DER `SubjectPublicKeyInfo`.
    ///
    /// Returns `None` for anything that is not an Ed25519 SPKI of exactly the
    /// expected length. Total and bounds-checked: this runs on bytes an
    /// unauthenticated peer chose, so it may not panic (invariant 7).
    pub fn from_spki(der: &[u8]) -> Option<Self> {
        if der.len() != SPKI_LEN || der[..SPKI_PREFIX.len()] != SPKI_PREFIX {
            return None;
        }

        let mut key = [0u8; KEY_LEN];
        key.copy_from_slice(&der[SPKI_PREFIX.len()..]);
        Some(Self(key))
    }

    /// Encodes this key as a DER `SubjectPublicKeyInfo`.
    pub fn to_spki(self) -> [u8; SPKI_LEN] {
        let mut der = [0u8; SPKI_LEN];
        der[..SPKI_PREFIX.len()].copy_from_slice(&SPKI_PREFIX);
        der[SPKI_PREFIX.len()..].copy_from_slice(&self.0);
        der
    }

    /// Encodes this key as an owned [`SubjectPublicKeyInfoDer`] for rustls.
    pub fn to_spki_der(self) -> SubjectPublicKeyInfoDer<'static> {
        SubjectPublicKeyInfoDer::from(self.to_spki().to_vec())
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ed25519:{}", BASE64.encode(self.0))
    }
}

/// Shows the same `ed25519:<base64>` form as [`Display`](fmt::Display), so a
/// key logged with `?` is still recognisable against `peers.toml`.
impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl FromStr for PublicKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let encoded = s
            .strip_prefix("ed25519:")
            .ok_or_else(|| Error::MalformedKey("expected an \"ed25519:\" prefix".into()))?;

        let decoded = BASE64
            .decode(encoded)
            .map_err(|e| Error::MalformedKey(format!("invalid base64: {e}")))?;

        let bytes: [u8; KEY_LEN] = decoded.try_into().map_err(|v: Vec<u8>| {
            Error::MalformedKey(format!("expected {KEY_LEN} key bytes, got {}", v.len()))
        })?;

        Ok(Self(bytes))
    }
}

/// A long-term Ed25519 keypair, loaded from or written to disk.
///
/// The private half is zeroized when the keypair is dropped.
pub struct StaticKeypair {
    signing: SigningKey,
}

impl StaticKeypair {
    /// Generates a fresh keypair from the operating system's entropy source.
    ///
    /// Reads the seed straight from the OS rather than through a userspace
    /// generator, and returns the failure instead of panicking on it: a key
    /// generated from degraded entropy is worse than no key.
    pub fn generate() -> Result<Self, Error> {
        use rand::TryRng as _;

        let mut seed = zeroize::Zeroizing::new([0u8; KEY_LEN]);
        rand::rngs::SysRng
            .try_fill_bytes(seed.as_mut())
            .map_err(|e| Error::Entropy(e.to_string()))?;

        Ok(Self {
            signing: SigningKey::from_bytes(&seed),
        })
    }

    /// Loads a keypair from a PKCS#8 file, requiring mode `0600`.
    ///
    /// A key readable by anyone else is refused rather than warned about
    /// (invariant 10): the caller cannot honour a guarantee the filesystem has
    /// already broken.
    pub fn from_file(path: &Path) -> Result<Self, Error> {
        let meta = fs::metadata(path)?;
        let mode = permissions_mode(&meta);
        if mode & 0o077 != 0 {
            return Err(Error::KeyPermissions {
                path: path.display().to_string(),
                mode,
            });
        }

        Self::from_pkcs8(&fs::read(path)?)
    }

    /// Writes the private key to `path` with mode `0600`.
    ///
    /// The mode is set as the file is created, so there is no window in which
    /// the key exists at the process umask.
    pub fn save(&self, path: &Path) -> Result<(), Error> {
        let der = self.to_pkcs8();
        write_private(path, &der)?;
        Ok(())
    }

    /// Parses a PKCS#8 v1 Ed25519 private key.
    pub fn from_pkcs8(der: &[u8]) -> Result<Self, Error> {
        let seed: [u8; KEY_LEN] = der
            .strip_prefix(&PKCS8_PREFIX[..])
            .and_then(|rest| rest.try_into().ok())
            .ok_or_else(|| Error::MalformedKey("not a PKCS#8 v1 Ed25519 private key".into()))?;

        Ok(Self {
            signing: SigningKey::from_bytes(&seed),
        })
    }

    /// Encodes the private key as PKCS#8 v1 DER, the form rustls parses.
    pub fn to_pkcs8(&self) -> zeroize::Zeroizing<Vec<u8>> {
        let mut der = Vec::with_capacity(PKCS8_PREFIX.len() + KEY_LEN);
        der.extend_from_slice(&PKCS8_PREFIX);
        der.extend_from_slice(self.signing.as_bytes());
        zeroize::Zeroizing::new(der)
    }

    /// The public half of this keypair.
    pub fn public(&self) -> PublicKey {
        PublicKey(self.signing.verifying_key().to_bytes())
    }
}

impl fmt::Debug for StaticKeypair {
    /// Prints the public half only; the private half never reaches a log.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StaticKeypair")
            .field("public", &self.public())
            .finish_non_exhaustive()
    }
}

// No `Drop` impl: `ed25519_dalek::SigningKey` is `ZeroizeOnDrop`, so the
// private half is already wiped when this struct is dropped.

#[cfg(unix)]
fn permissions_mode(meta: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    meta.permissions().mode() & 0o777
}

#[cfg(unix)]
fn write_private(path: &Path, contents: &[u8]) -> Result<(), Error> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_and_parse_round_trip() {
        let key = StaticKeypair::generate().expect("keygen").public();
        let rendered = key.to_string();

        assert!(rendered.starts_with("ed25519:"));
        assert_eq!(rendered.parse::<PublicKey>().expect("parses"), key);
    }

    #[test]
    fn spki_round_trips() {
        let key = StaticKeypair::generate().expect("keygen").public();
        assert_eq!(PublicKey::from_spki(&key.to_spki()), Some(key));
    }

    #[test]
    fn malformed_spki_is_rejected_without_panicking() {
        let valid = StaticKeypair::generate()
            .expect("keygen")
            .public()
            .to_spki();

        assert_eq!(PublicKey::from_spki(&[]), None, "empty");
        assert_eq!(PublicKey::from_spki(&valid[..SPKI_LEN - 1]), None, "short");

        let mut long = valid.to_vec();
        long.push(0);
        assert_eq!(PublicKey::from_spki(&long), None, "long");

        let mut wrong_prefix = valid;
        wrong_prefix[0] ^= 0xff;
        assert_eq!(PublicKey::from_spki(&wrong_prefix), None, "wrong prefix");

        // Every truncation of a valid SPKI must be a rejection, not a panic.
        for n in 0..valid.len() {
            assert_eq!(PublicKey::from_spki(&valid[..n]), None);
        }
    }

    #[test]
    fn malformed_text_is_rejected() {
        for bad in ["", "ed25519", "abcdef", "ed25519:!!!!", "ed25519:AAAA"] {
            assert!(bad.parse::<PublicKey>().is_err(), "{bad} should not parse");
        }
    }

    #[test]
    fn pkcs8_round_trips() {
        let original = StaticKeypair::generate().expect("keygen");
        let restored = StaticKeypair::from_pkcs8(&original.to_pkcs8()).expect("parses");
        assert_eq!(restored.public(), original.public());
    }

    #[test]
    fn malformed_pkcs8_is_rejected() {
        assert!(StaticKeypair::from_pkcs8(&[]).is_err());
        assert!(StaticKeypair::from_pkcs8(&[0u8; 48]).is_err());
    }

    #[test]
    fn saved_key_is_written_with_mode_600_and_reloads() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("private.key");

        let original = StaticKeypair::generate().expect("keygen");
        original.save(&path).expect("saves");

        let meta = fs::metadata(&path).expect("metadata");
        assert_eq!(permissions_mode(&meta), 0o600);

        let loaded = StaticKeypair::from_file(&path).expect("loads");
        assert_eq!(loaded.public(), original.public());
    }

    #[test]
    fn loose_permissions_are_refused() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("private.key");
        StaticKeypair::generate()
            .expect("keygen")
            .save(&path)
            .expect("saves");

        for mode in [0o644, 0o640, 0o604, 0o666, 0o777] {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("chmod");
            let err = StaticKeypair::from_file(&path).expect_err("must refuse");
            assert!(
                matches!(err, Error::KeyPermissions { .. }),
                "mode {mode:o} gave {err:?}"
            );
        }
    }

    #[test]
    fn debug_never_shows_private_material() {
        let keypair = StaticKeypair::generate().expect("keygen");
        let rendered = format!("{keypair:?}");
        let secret = BASE64.encode(keypair.to_pkcs8().as_slice());

        assert!(rendered.contains(&keypair.public().to_string()));
        assert!(!rendered.contains(&secret));
    }
}
