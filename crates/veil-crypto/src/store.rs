//! The whitelist that decides which public keys may hold a session.

use std::collections::HashMap;

use crate::PublicKey;

/// A peer whose public key was authenticated by the TLS handshake.
///
/// Produced only by a successful whitelist lookup, so holding one is proof the
/// key was both presented and accepted. v1 discarded this and could therefore
/// not attribute, authorize or anti-spoof anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPeer {
    /// The authenticated identity.
    pub key: PublicKey,
    /// The operator-facing name from the peer store.
    pub name: String,
}

/// Answers "may this key connect, and who is it?".
///
/// `plan.md` §6.2 writes this as `PeerStore`, but §6.4 places that trait in
/// `veil-config` alongside addresses and `allowed` prefixes, which would make
/// the dependency circular. This is the key-only half that `veil-crypto` needs;
/// `veil-config`'s peer store implements it at M3.
pub trait KeyWhitelist: Send + Sync + std::fmt::Debug {
    /// Returns the peer for `key`, or `None` if it is not whitelisted.
    fn lookup(&self, key: &PublicKey) -> Option<VerifiedPeer>;

    /// Bumped whenever the underlying set changes, so callers can tell that a
    /// reload happened without diffing the contents.
    fn generation(&self) -> u64;
}

/// An in-memory whitelist, used by `veil-ctl`, the tests, and any caller that
/// has no file to reload.
#[derive(Debug, Default, Clone)]
pub struct StaticWhitelist {
    peers: HashMap<PublicKey, String>,
    generation: u64,
}

impl StaticWhitelist {
    /// An empty whitelist, which accepts nobody.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds or renames a peer, bumping the generation.
    pub fn insert(&mut self, key: PublicKey, name: impl Into<String>) {
        self.peers.insert(key, name.into());
        self.generation += 1;
    }

    /// Removes a peer, bumping the generation. Returns whether it was present.
    pub fn remove(&mut self, key: &PublicKey) -> bool {
        let removed = self.peers.remove(key).is_some();
        if removed {
            self.generation += 1;
        }
        removed
    }

    /// Number of whitelisted keys.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Whether the whitelist accepts nobody.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }
}

impl FromIterator<(PublicKey, String)> for StaticWhitelist {
    fn from_iter<I: IntoIterator<Item = (PublicKey, String)>>(iter: I) -> Self {
        let peers: HashMap<_, _> = iter.into_iter().collect();
        let generation = peers.len() as u64;
        Self { peers, generation }
    }
}

impl KeyWhitelist for StaticWhitelist {
    fn lookup(&self, key: &PublicKey) -> Option<VerifiedPeer> {
        self.peers.get(key).map(|name| VerifiedPeer {
            key: *key,
            name: name.clone(),
        })
    }

    fn generation(&self) -> u64 {
        self.generation
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StaticKeypair;

    #[test]
    fn lookup_finds_only_whitelisted_keys() {
        let known = StaticKeypair::generate().expect("keygen").public();
        let unknown = StaticKeypair::generate().expect("keygen").public();

        let mut store = StaticWhitelist::new();
        store.insert(known, "laptop");

        let found = store.lookup(&known).expect("known key is present");
        assert_eq!(found.key, known);
        assert_eq!(found.name, "laptop");
        assert_eq!(store.lookup(&unknown), None);
    }

    #[test]
    fn removal_revokes_and_bumps_the_generation() {
        let key = StaticKeypair::generate().expect("keygen").public();
        let mut store = StaticWhitelist::new();

        store.insert(key, "phone");
        let before = store.generation();

        assert!(store.remove(&key));
        assert_eq!(store.lookup(&key), None);
        assert!(store.generation() > before);

        // Removing an absent key changes nothing.
        let after = store.generation();
        assert!(!store.remove(&key));
        assert_eq!(store.generation(), after);
    }
}
