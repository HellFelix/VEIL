//! The `peers.toml` peer store.
//!
//! Parse only: the file is read once at startup. `SIGHUP` reload, diffing
//! against live sessions and generation bumping arrive at M3, which is why
//! [`PeerFile::generation`] is currently fixed.

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::str::FromStr as _;

use ipnet::IpNet;
use serde::Deserialize;
use veil_crypto::{KeyWhitelist, PublicKey, VerifiedPeer};

use crate::Error;

/// One entry from `peers.toml`.
///
/// The full shape from `plan.md` §6.4 is parsed even though only [`name`], the
/// key and [`enabled`] are consulted yet, so that a file written today stays
/// valid once addresses and ACLs go live at M4 and M6.
///
/// [`name`]: Peer::name
/// [`enabled`]: Peer::enabled
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    /// Operator-facing name, unique within the file.
    pub name: String,
    /// The peer's identity, and the only thing authentication checks.
    pub public_key: PublicKey,
    /// Static IPv4 assignment, or `None` to allocate from the pool. Unused until M4.
    pub ipv4: Option<Ipv4Addr>,
    /// Static IPv6 assignment, or `None` to allocate from the pool. Unused until M4.
    pub ipv6: Option<Ipv6Addr>,
    /// Prefixes this peer may reach. Unused until M6.
    pub allowed: Vec<IpNet>,
    /// Whether the peer may hold a session. A disabled peer is never returned
    /// from [`PeerFile::lookup`], so this is revocation across a restart.
    pub enabled: bool,
    /// Whether the peer may reach the admin UI. Unused until M12.
    pub admin: bool,
}

/// The parsed contents of `peers.toml`.
#[derive(Debug, Clone)]
pub struct PeerFile {
    peers: Vec<Peer>,
    by_key: HashMap<PublicKey, usize>,
}

impl PeerFile {
    /// Reads and validates `peers.toml`.
    ///
    /// Fails on malformed TOML, an unparseable key or prefix, a duplicate
    /// public key, or a duplicate name. Parsing the file completely before
    /// accepting any of it is what lets M3 keep the previous generation live
    /// when a reload fails.
    pub fn load(path: &Path) -> Result<Self, Error> {
        let text = std::fs::read_to_string(path).map_err(|source| Error::Read {
            path: path.display().to_string(),
            source,
        })?;

        Self::parse(&text)
    }

    /// Parses `peers.toml` content that has already been read.
    ///
    /// Separate from [`load`](Self::load) so the validation rules are testable
    /// without touching the filesystem.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let file: RawFile = toml::from_str(text)?;

        let mut peers = Vec::with_capacity(file.peer.len());
        let mut by_key = HashMap::with_capacity(file.peer.len());
        let mut names = HashSet::with_capacity(file.peer.len());

        for raw in file.peer {
            let peer = raw.into_peer()?;

            if !names.insert(peer.name.clone()) {
                return Err(Error::DuplicateName(peer.name));
            }

            if let Some(&previous) = by_key.get(&peer.public_key) {
                let other: &Peer = &peers[previous];
                return Err(Error::DuplicateKey {
                    key: peer.public_key.to_string(),
                    first: other.name.clone(),
                    second: peer.name,
                });
            }

            by_key.insert(peer.public_key, peers.len());
            peers.push(peer);
        }

        Ok(Self { peers, by_key })
    }

    /// Every peer in the file, including disabled ones.
    pub fn peers(&self) -> &[Peer] {
        &self.peers
    }

    /// The peer owning `key`, whether or not it is enabled.
    pub fn get(&self, key: &PublicKey) -> Option<&Peer> {
        self.by_key.get(key).and_then(|&i| self.peers.get(i))
    }

    /// Number of peers in the file, including disabled ones.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Whether the file declares no peers at all.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }
}

impl KeyWhitelist for PeerFile {
    /// Returns the peer for `key`, or `None` if it is absent or disabled.
    fn lookup(&self, key: &PublicKey) -> Option<VerifiedPeer> {
        let peer = self.get(key).filter(|peer| peer.enabled)?;

        Some(VerifiedPeer {
            key: peer.public_key,
            name: peer.name.clone(),
        })
    }

    /// Fixed until M3 adds reload; there is only ever one generation.
    fn generation(&self) -> u64 {
        0
    }
}

/// The file as TOML sees it, before keys and prefixes are parsed.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFile {
    #[serde(default)]
    peer: Vec<RawPeer>,
}

/// One `[[peer]]` table, with the typed fields still as strings.
///
/// `ipnet` is declared without its `serde` feature and `PublicKey` deliberately
/// does not implement `Deserialize`, since `plan.md` §5.2 scopes `serde` to
/// `veil-proto` and `veil-config`. Both are converted through their `FromStr`
/// impls instead, which keeps the error messages ours.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPeer {
    name: String,
    public_key: String,
    ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
    #[serde(default)]
    allowed: Vec<String>,
    #[serde(default = "enabled_by_default")]
    enabled: bool,
    #[serde(default)]
    admin: bool,
}

/// A peer with no `enabled` key is enabled; listing it is the opt-in.
fn enabled_by_default() -> bool {
    true
}

impl RawPeer {
    fn into_peer(self) -> Result<Peer, Error> {
        let public_key = self
            .public_key
            .parse::<PublicKey>()
            .map_err(|source| Error::PeerKey {
                peer: self.name.clone(),
                source,
            })?;

        let allowed = self
            .allowed
            .iter()
            .map(|prefix| {
                IpNet::from_str(prefix).map_err(|_| Error::PeerPrefix {
                    peer: self.name.clone(),
                    prefix: prefix.clone(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Peer {
            name: self.name,
            public_key,
            ipv4: self.ipv4,
            ipv6: self.ipv6,
            allowed,
            enabled: self.enabled,
            admin: self.admin,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use veil_crypto::StaticKeypair;

    fn key() -> PublicKey {
        StaticKeypair::generate().expect("keygen").public()
    }

    #[test]
    fn parses_a_two_peer_file() {
        let laptop = key();
        let phone = key();

        let text = format!(
            r#"
            [[peer]]
            name       = "laptop"
            public_key = "{laptop}"
            ipv4       = "10.44.0.2"
            ipv6       = "fd00::2"
            allowed    = ["0.0.0.0/0", "::/0"]
            admin      = true

            [[peer]]
            name       = "phone"
            public_key = "{phone}"
            allowed    = ["10.44.0.0/24"]
            "#
        );

        let file = PeerFile::parse(&text).expect("parses");
        assert_eq!(file.len(), 2);

        let found = file.get(&laptop).expect("laptop present");
        assert_eq!(found.name, "laptop");
        assert_eq!(found.ipv4, Some(Ipv4Addr::new(10, 44, 0, 2)));
        assert_eq!(found.allowed.len(), 2);
        assert!(found.admin);
        // Absent keys take their defaults rather than failing to parse.
        assert!(found.enabled);

        let found = file.get(&phone).expect("phone present");
        assert_eq!(found.ipv4, None);
        assert!(!found.admin);
    }

    #[test]
    fn lookup_honours_enabled_and_ignores_strangers() {
        let live = key();
        let revoked = key();
        let stranger = key();

        let text = format!(
            r#"
            [[peer]]
            name       = "laptop"
            public_key = "{live}"

            [[peer]]
            name       = "old-phone"
            public_key = "{revoked}"
            enabled    = false
            "#
        );

        let file = PeerFile::parse(&text).expect("parses");

        let found = file.lookup(&live).expect("enabled peer is whitelisted");
        assert_eq!(found.key, live);
        assert_eq!(found.name, "laptop");

        // Revocation across a restart: still in the file, never whitelisted.
        assert_eq!(file.lookup(&revoked), None);
        assert!(file.get(&revoked).is_some(), "still parsed, just not allowed");

        assert_eq!(file.lookup(&stranger), None);
    }

    #[test]
    fn duplicate_public_key_is_rejected() {
        // Two names for one identity would make attribution ambiguous, and
        // whichever entry lost the race would silently never apply.
        let shared = key();
        let text = format!(
            r#"
            [[peer]]
            name       = "laptop"
            public_key = "{shared}"

            [[peer]]
            name       = "phone"
            public_key = "{shared}"
            "#
        );

        match PeerFile::parse(&text) {
            Err(Error::DuplicateKey { first, second, .. }) => {
                assert_eq!(first, "laptop");
                assert_eq!(second, "phone");
            }
            other => panic!("expected a duplicate key error, got {other:?}"),
        }
    }

    #[test]
    fn duplicate_name_is_rejected() {
        let text = format!(
            r#"
            [[peer]]
            name       = "laptop"
            public_key = "{}"

            [[peer]]
            name       = "laptop"
            public_key = "{}"
            "#,
            key(),
            key()
        );

        assert!(matches!(
            PeerFile::parse(&text),
            Err(Error::DuplicateName(name)) if name == "laptop"
        ));
    }

    #[test]
    fn a_bad_key_names_the_peer_it_came_from() {
        // The whole point of parsing the key ourselves: the operator gets told
        // which line to fix, not just that the file is wrong.
        let text = r#"
            [[peer]]
            name       = "laptop"
            public_key = "ed25519:not-base64!!"
        "#;

        match PeerFile::parse(text) {
            Err(Error::PeerKey { peer, .. }) => assert_eq!(peer, "laptop"),
            other => panic!("expected a key error naming the peer, got {other:?}"),
        }
    }

    #[test]
    fn a_bad_prefix_names_the_peer_and_the_prefix() {
        let text = format!(
            r#"
            [[peer]]
            name       = "laptop"
            public_key = "{}"
            allowed    = ["10.44.0.0/99"]
            "#,
            key()
        );

        match PeerFile::parse(&text) {
            Err(Error::PeerPrefix { peer, prefix }) => {
                assert_eq!(peer, "laptop");
                assert_eq!(prefix, "10.44.0.0/99");
            }
            other => panic!("expected a prefix error, got {other:?}"),
        }
    }

    #[test]
    fn malformed_and_misspelled_files_are_rejected() {
        assert!(PeerFile::parse("this is not toml {{{").is_err());

        // `deny_unknown_fields` turns a typo into an error rather than a
        // silently ignored setting, which for `enabled` would be a security bug.
        let typo = format!(
            r#"
            [[peer]]
            name       = "laptop"
            public_key = "{}"
            enable     = false
            "#,
            key()
        );
        assert!(PeerFile::parse(&typo).is_err(), "a misspelled key must fail");
    }

    #[test]
    fn an_empty_file_parses_to_an_empty_whitelist() {
        // A server with no peers is useless but not malformed, and it must not
        // be a startup crash.
        let file = PeerFile::parse("").expect("an empty file is valid");
        assert!(file.is_empty());
        assert_eq!(file.lookup(&key()), None);
    }

    #[test]
    fn load_reads_from_disk_and_reports_a_missing_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("peers.toml");

        assert!(matches!(
            PeerFile::load(&path),
            Err(Error::Read { .. })
        ));

        let laptop = key();
        std::fs::write(
            &path,
            format!("[[peer]]\nname = \"laptop\"\npublic_key = \"{laptop}\"\n"),
        )
        .expect("write");

        let file = PeerFile::load(&path).expect("loads");
        assert!(file.lookup(&laptop).is_some());
    }
}
