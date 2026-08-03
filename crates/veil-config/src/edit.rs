//! Editing `peers.toml` in place, preserving comments and formatting.
//!
//! [`peers`](crate::peers) reads the file; this writes it. `peers.toml` is
//! hand-edited as well as tool-edited, so edits go through
//! [`toml_edit`](https://docs.rs/toml_edit) rather than re-serializing our own
//! structs, which would delete every comment in it.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use ipnet::IpNet;
use toml_edit::{Array, ArrayOfTables, DocumentMut, Item, Table, value};
use veil_crypto::PublicKey;

use crate::{Error, Peer, PeerFile};

/// Mode for a `peers.toml` this tool creates.
///
/// Group-readable so a `veil` group can inspect the whitelist; the private key
/// next to it stays `0600`.
const NEW_FILE_MODE: u32 = 0o640;

/// The keys of a `[[peer]]` table, in the order they are written.
const CANONICAL_ORDER: [&str; 7] = [
    "name",
    "public_key",
    "ipv4",
    "ipv6",
    "allowed",
    "enabled",
    "admin",
];

/// Fields to change on an existing peer.
///
/// Every field is optional and `None` means "leave alone", so a caller can
/// change one setting without restating the rest. There is deliberately no way
/// to unset a field: remove the peer and add it again.
#[derive(Debug, Clone, Default)]
pub struct PeerChange {
    /// Rename the peer.
    pub name: Option<String>,
    /// Replace the peer's identity.
    pub public_key: Option<PublicKey>,
    /// Set the static IPv4 assignment.
    pub ipv4: Option<Ipv4Addr>,
    /// Set the static IPv6 assignment.
    pub ipv6: Option<Ipv6Addr>,
    /// Replace the list of reachable prefixes.
    pub allowed: Option<Vec<IpNet>>,
    /// Allow or forbid the peer to hold a session.
    pub enabled: Option<bool>,
    /// Grant or revoke admin access.
    pub admin: Option<bool>,
}

impl PeerChange {
    /// Whether this change would touch anything.
    pub fn is_empty(&self) -> bool {
        self.name.is_none()
            && self.public_key.is_none()
            && self.ipv4.is_none()
            && self.ipv6.is_none()
            && self.allowed.is_none()
            && self.enabled.is_none()
            && self.admin.is_none()
    }
}

/// A `peers.toml` opened for modification.
///
/// Changes are held in memory until [`save`](Self::save), which replaces the
/// file atomically.
#[derive(Debug)]
pub struct PeerEditor {
    doc: DocumentMut,
    path: PathBuf,
    current: PeerFile,
}

impl PeerEditor {
    /// Opens `peers.toml`, or starts an empty document if it does not exist.
    ///
    /// The file is parsed twice: once by `toml_edit` to keep its formatting,
    /// and once by [`PeerFile::parse`] so that an already-invalid file is
    /// refused before any edit is attempted rather than after.
    pub fn open(path: &Path) -> Result<Self, Error> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(source) => {
                return Err(Error::Read {
                    path: path.display().to_string(),
                    source,
                });
            }
        };

        let doc = text.parse::<DocumentMut>().map_err(|source| Error::Edit {
            path: path.display().to_string(),
            source,
        })?;

        Ok(Self {
            current: PeerFile::parse(&text)?,
            doc,
            path: path.to_path_buf(),
        })
    }

    /// The peers currently in the file.
    pub fn peers(&self) -> &[Peer] {
        self.current.peers()
    }

    /// Appends a peer.
    ///
    /// Rejects a name or public key already in the file, naming the peer it
    /// collides with, and leaves the document untouched when it does.
    pub fn add(&mut self, peer: &Peer) -> Result<(), Error> {
        if self.current.peers().iter().any(|p| p.name == peer.name) {
            return Err(Error::DuplicateName(peer.name.clone()));
        }

        if let Some(existing) = self.current.get(&peer.public_key) {
            return Err(Error::DuplicateKey {
                key: peer.public_key.to_string(),
                first: existing.name.clone(),
                second: peer.name.clone(),
            });
        }

        let mut table = Table::new();
        for key in CANONICAL_ORDER {
            if let Some(item) = field(peer, key) {
                table.insert(key, item);
            }
        }

        // A file of nothing but comments has no tables to attach them to, so
        // `toml_edit` holds them as the document's trailing trivia and any
        // table appended here would sort *below* them. Hoisting them onto the
        // first table keeps a freshly installed peers.toml, which is exactly
        // that shape, reading top to bottom.
        if self.tables()?.is_empty()
            && let Some(header) = self.doc.trailing().as_str()
            && !header.trim().is_empty()
        {
            let header = format!("{}\n\n", header.trim_end());
            table.decor_mut().set_prefix(header);
            self.doc.set_trailing("");
        }

        self.tables()?.push(table);
        self.reparse()
    }

    /// Applies `change` to the peer called `name`.
    pub fn set(&mut self, name: &str, change: &PeerChange) -> Result<(), Error> {
        let index = self.index_of(name)?;

        if let Some(new_name) = &change.name
            && new_name != name
            && self.current.peers().iter().any(|p| &p.name == new_name)
        {
            return Err(Error::DuplicateName(new_name.clone()));
        }

        if let Some(new_key) = &change.public_key
            && let Some(existing) = self.current.get(new_key)
            && existing.name != name
        {
            return Err(Error::DuplicateKey {
                key: new_key.to_string(),
                first: existing.name.clone(),
                second: name.to_string(),
            });
        }

        let table = self
            .tables()?
            .get_mut(index)
            .ok_or_else(|| Error::UnknownPeer(name.to_string()))?;

        // Assigning through the index preserves an existing key's position and
        // its decor; a key not yet present is appended, then sorted below.
        if let Some(v) = &change.name {
            table["name"] = value(v.as_str());
        }
        if let Some(v) = &change.public_key {
            table["public_key"] = value(v.to_string());
        }
        if let Some(v) = &change.ipv4 {
            table["ipv4"] = value(v.to_string());
        }
        if let Some(v) = &change.ipv6 {
            table["ipv6"] = value(v.to_string());
        }
        if let Some(v) = &change.allowed {
            table["allowed"] = value(prefixes(v));
        }
        if let Some(v) = change.enabled {
            table["enabled"] = value(v);
        }
        if let Some(v) = change.admin {
            table["admin"] = value(v);
        }

        table.sort_values_by(|a, _, b, _| rank(a.get()).cmp(&rank(b.get())));

        self.reparse()
    }

    /// Deletes the peer called `name`.
    ///
    /// A comment written directly above the `[[peer]]` header belongs to that
    /// table and goes with it, which is intended: the note described the peer
    /// being removed.
    pub fn remove(&mut self, name: &str) -> Result<(), Error> {
        let index = self.index_of(name)?;
        self.tables()?.remove(index);
        self.reparse()
    }

    /// Writes the file, replacing it atomically.
    ///
    /// The rendered document is parsed once more with [`PeerFile::parse`]
    /// before anything is written, so a bug in this module cannot leave a
    /// server with a whitelist it will refuse to load at startup.
    pub fn save(&self) -> Result<(), Error> {
        let text = self.doc.to_string();
        PeerFile::parse(&text)?;

        write_atomically(&self.path, &text)
    }

    /// The `[[peer]]` array, created if the document has none yet.
    fn tables(&mut self) -> Result<&mut ArrayOfTables, Error> {
        self.doc
            .entry("peer")
            .or_insert(Item::ArrayOfTables(ArrayOfTables::new()))
            .as_array_of_tables_mut()
            .ok_or_else(|| Error::NotPeerArray(self.path.display().to_string()))
    }

    /// Position of `name` in the file.
    fn index_of(&self, name: &str) -> Result<usize, Error> {
        self.current
            .peers()
            .iter()
            .position(|p| p.name == name)
            .ok_or_else(|| Error::UnknownPeer(name.to_string()))
    }

    /// Refreshes the parsed view after a mutation.
    ///
    /// Keeping `current` in step is what lets the duplicate checks above run
    /// against the file as it now stands rather than as it was opened.
    fn reparse(&mut self) -> Result<(), Error> {
        self.current = PeerFile::parse(&self.doc.to_string())?;
        Ok(())
    }
}

/// Renders one field of `peer`, or `None` when it should be omitted.
fn field(peer: &Peer, key: &str) -> Option<Item> {
    match key {
        "name" => Some(value(peer.name.as_str())),
        "public_key" => Some(value(peer.public_key.to_string())),
        "ipv4" => peer.ipv4.map(|a| value(a.to_string())),
        "ipv6" => peer.ipv6.map(|a| value(a.to_string())),
        "allowed" => (!peer.allowed.is_empty()).then(|| value(prefixes(&peer.allowed))),
        // Written only when they differ from the documented default, so a
        // generated entry stays as short as a hand-written one.
        "enabled" => (!peer.enabled).then(|| value(false)),
        "admin" => peer.admin.then(|| value(true)),
        _ => None,
    }
}

/// Renders prefixes as a TOML array of strings.
fn prefixes(nets: &[IpNet]) -> Array {
    nets.iter().map(|n| n.to_string()).collect()
}

/// Sort position of a key, so generated tables keep [`CANONICAL_ORDER`].
///
/// Unknown keys sort last rather than being dropped: `deny_unknown_fields`
/// means the file could not have parsed with one, but ordering must stay total.
fn rank(key: &str) -> usize {
    CANONICAL_ORDER
        .iter()
        .position(|k| *k == key)
        .unwrap_or(CANONICAL_ORDER.len())
}

/// Writes `text` to `path` by rename, so a crash cannot truncate the original.
///
/// Replacing a file by rename installs a *new* inode, so mode and ownership are
/// carried over deliberately. Without the ownership half, `sudo veil-ctl peer
/// add` against a user-owned `peers.toml` would hand it to `root:root` and, at
/// mode `0640`, lock the owner out of their own whitelist.
fn write_atomically(path: &Path, text: &str) -> Result<(), Error> {
    use std::io::Write as _;

    let fail = |source| Error::Write {
        path: path.display().to_string(),
        source,
    };

    let dir = path.parent().unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .unwrap_or(std::ffi::OsStr::new("peers.toml"));

    let mut temp = dir.join(format!(
        ".{}.tmp{}",
        name.to_string_lossy(),
        std::process::id()
    ));

    let existing = std::fs::metadata(path).ok();
    let mode = existing.as_ref().map_or(NEW_FILE_MODE, mode_of);

    let result = (|| -> std::io::Result<()> {
        let mut file = open_with_mode(&temp, mode)?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        drop(file);

        if let Some(existing) = &existing {
            preserve_owner(&temp, existing)?;
        }

        std::fs::rename(&temp, path)?;
        temp = PathBuf::new();

        // Durability of the rename itself, not just of the contents.
        std::fs::File::open(dir)?.sync_all()
    })();

    if !temp.as_os_str().is_empty() {
        let _ = std::fs::remove_file(&temp);
    }

    result.map_err(fail)
}

#[cfg(unix)]
fn mode_of(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    meta.permissions().mode()
}

#[cfg(not(unix))]
fn mode_of(_meta: &std::fs::Metadata) -> u32 {
    NEW_FILE_MODE
}

/// Gives `temp` the same owner as the file it is about to replace.
///
/// A no-op when they already match, which is the unprivileged case, so this
/// only does real work under `sudo`. A failure is returned rather than ignored:
/// silently changing the owner is the bug this exists to prevent.
#[cfg(unix)]
fn preserve_owner(temp: &Path, existing: &std::fs::Metadata) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let (uid, gid) = (existing.uid(), existing.gid());
    let current = std::fs::metadata(temp)?;

    if (current.uid(), current.gid()) == (uid, gid) {
        return Ok(());
    }

    std::os::unix::fs::chown(temp, Some(uid), Some(gid))
}

#[cfg(not(unix))]
fn preserve_owner(_temp: &Path, _existing: &std::fs::Metadata) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn open_with_mode(path: &Path, mode: u32) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(path)
}

#[cfg(not(unix))]
fn open_with_mode(path: &Path, _mode: u32) -> std::io::Result<std::fs::File> {
    std::fs::File::create(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use veil_crypto::StaticKeypair;

    fn key() -> PublicKey {
        StaticKeypair::generate().expect("keygen").public()
    }

    fn peer(name: &str, public_key: PublicKey) -> Peer {
        Peer {
            name: name.into(),
            public_key,
            ipv4: None,
            ipv6: None,
            allowed: Vec::new(),
            enabled: true,
            admin: false,
        }
    }

    /// A path inside a fresh temp dir, plus the dir itself so it stays alive.
    fn scratch(contents: Option<&str>) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("peers.toml");
        if let Some(text) = contents {
            std::fs::write(&path, text).expect("write");
        }
        (dir, path)
    }

    #[test]
    fn adds_to_a_file_that_does_not_exist_yet() {
        let (_dir, path) = scratch(None);
        let laptop = key();

        let mut editor = PeerEditor::open(&path).expect("absent file is fine");
        editor.add(&peer("laptop", laptop)).expect("add");
        editor.save().expect("save");

        let file = PeerFile::load(&path).expect("reloads");
        assert_eq!(file.len(), 1);
        assert_eq!(file.get(&laptop).expect("present").name, "laptop");
    }

    #[test]
    fn comments_survive_every_operation() {
        // The entire reason this module uses toml_edit instead of
        // re-serializing. If this breaks, the dependency has no justification.
        let first = key();
        let (_dir, path) = scratch(Some(&format!(
            "# VEIL whitelist, do not reformat\n\n# the boss's machine\n[[peer]]\nname = \"laptop\"\npublic_key = \"{first}\"\n"
        )));

        let mut editor = PeerEditor::open(&path).expect("open");
        editor.add(&peer("phone", key())).expect("add");
        editor.save().expect("save");

        let text = std::fs::read_to_string(&path).expect("read");
        assert!(text.contains("# VEIL whitelist, do not reformat"), "{text}");
        assert!(text.contains("# the boss's machine"), "{text}");

        let mut editor = PeerEditor::open(&path).expect("open");
        editor
            .set(
                "laptop",
                &PeerChange {
                    enabled: Some(false),
                    ..Default::default()
                },
            )
            .expect("set");
        editor.save().expect("save");

        let text = std::fs::read_to_string(&path).expect("read");
        assert!(text.contains("# VEIL whitelist, do not reformat"), "{text}");
        assert!(text.contains("# the boss's machine"), "{text}");

        let mut editor = PeerEditor::open(&path).expect("open");
        editor.remove("phone").expect("remove");
        editor.save().expect("save");

        let text = std::fs::read_to_string(&path).expect("read");
        assert!(text.contains("# VEIL whitelist, do not reformat"), "{text}");
    }

    #[test]
    fn a_comment_only_file_keeps_its_header_at_the_top() {
        // The shape install.sh writes: comments and no tables. Without the
        // hoist in `add`, toml_edit holds these as trailing trivia and the
        // first peer is emitted above them, leaving the header at the bottom.
        let (_dir, path) = scratch(Some(
            "# VEIL peer whitelist.\n# Managed with `veil-ctl peer`.\n",
        ));

        let mut editor = PeerEditor::open(&path).expect("open");
        editor.add(&peer("laptop", key())).expect("add");
        editor.add(&peer("phone", key())).expect("add");
        editor.save().expect("save");

        let text = std::fs::read_to_string(&path).expect("read");
        let header = text.find("# VEIL peer whitelist.").expect("header kept");
        let first = text.find("[[peer]]").expect("a peer was written");

        assert!(header < first, "the header must stay at the top:\n{text}");
        assert!(text.contains("# Managed with"), "{text}");
    }

    #[test]
    fn duplicates_are_refused_and_the_file_is_untouched() {
        let shared = key();
        let (_dir, path) = scratch(None);

        let mut editor = PeerEditor::open(&path).expect("open");
        editor.add(&peer("laptop", shared)).expect("add");
        editor.save().expect("save");

        let before = std::fs::read_to_string(&path).expect("read");

        let mut editor = PeerEditor::open(&path).expect("open");
        assert!(matches!(
            editor.add(&peer("laptop", key())),
            Err(Error::DuplicateName(n)) if n == "laptop"
        ));
        assert!(matches!(
            editor.add(&peer("phone", shared)),
            Err(Error::DuplicateKey { first, .. }) if first == "laptop"
        ));

        // A refused edit must not have reached the disk.
        editor.save().expect("save");
        assert_eq!(std::fs::read_to_string(&path).expect("read"), before);
    }

    #[test]
    fn set_touches_only_the_named_fields() {
        let laptop = key();
        let (_dir, path) = scratch(None);

        let mut editor = PeerEditor::open(&path).expect("open");
        editor
            .add(&Peer {
                ipv4: Some(Ipv4Addr::new(10, 44, 0, 2)),
                allowed: vec!["0.0.0.0/0".parse().expect("prefix")],
                admin: true,
                ..peer("laptop", laptop)
            })
            .expect("add");
        editor.save().expect("save");

        let mut editor = PeerEditor::open(&path).expect("open");
        editor
            .set(
                "laptop",
                &PeerChange {
                    enabled: Some(false),
                    ..Default::default()
                },
            )
            .expect("set");
        editor.save().expect("save");

        let file = PeerFile::load(&path).expect("reloads");
        let found = file.get(&laptop).expect("present");

        assert!(!found.enabled, "the named field changed");
        assert_eq!(found.ipv4, Some(Ipv4Addr::new(10, 44, 0, 2)));
        assert_eq!(found.allowed.len(), 1);
        assert!(found.admin, "unnamed fields survived");

        // Disabled means absent from the whitelist even though it is present
        // in the file, which is revocation that keeps the record.
        use veil_crypto::KeyWhitelist as _;
        assert_eq!(file.lookup(&laptop), None);
    }

    #[test]
    fn set_can_rename_and_refuses_a_taken_name() {
        let (_dir, path) = scratch(None);

        let mut editor = PeerEditor::open(&path).expect("open");
        editor.add(&peer("laptop", key())).expect("add");
        editor.add(&peer("phone", key())).expect("add");

        assert!(matches!(
            editor.set(
                "laptop",
                &PeerChange { name: Some("phone".into()), ..Default::default() }
            ),
            Err(Error::DuplicateName(n)) if n == "phone"
        ));

        editor
            .set(
                "laptop",
                &PeerChange {
                    name: Some("workstation".into()),
                    ..Default::default()
                },
            )
            .expect("rename");
        editor.save().expect("save");

        let file = PeerFile::load(&path).expect("reloads");
        assert!(file.peers().iter().any(|p| p.name == "workstation"));
        assert!(!file.peers().iter().any(|p| p.name == "laptop"));
    }

    #[test]
    fn removing_an_unknown_peer_is_an_error() {
        let (_dir, path) = scratch(None);
        let mut editor = PeerEditor::open(&path).expect("open");

        assert!(matches!(
            editor.remove("ghost"),
            Err(Error::UnknownPeer(n)) if n == "ghost"
        ));
        assert!(matches!(
            editor.set("ghost", &PeerChange::default()),
            Err(Error::UnknownPeer(_))
        ));
    }

    #[test]
    fn an_already_malformed_file_is_refused_before_editing() {
        let (_dir, path) = scratch(Some("this is not toml {{{"));
        assert!(PeerEditor::open(&path).is_err());

        // Valid TOML, invalid whitelist: caught by PeerFile::parse, not by
        // toml_edit, which is why open runs both.
        let shared = key();
        let (_dir, path) = scratch(Some(&format!(
            "[[peer]]\nname = \"a\"\npublic_key = \"{shared}\"\n\n[[peer]]\nname = \"b\"\npublic_key = \"{shared}\"\n"
        )));
        assert!(matches!(
            PeerEditor::open(&path),
            Err(Error::DuplicateKey { .. })
        ));
    }

    #[test]
    fn a_full_peer_round_trips_through_the_file() {
        let laptop = key();
        let (_dir, path) = scratch(None);

        let original = Peer {
            name: "laptop".into(),
            public_key: laptop,
            ipv4: Some(Ipv4Addr::new(10, 44, 0, 2)),
            ipv6: Some("fd00::2".parse().expect("v6")),
            allowed: vec![
                "0.0.0.0/0".parse().expect("prefix"),
                "::/0".parse().expect("prefix"),
            ],
            enabled: false,
            admin: true,
        };

        let mut editor = PeerEditor::open(&path).expect("open");
        editor.add(&original).expect("add");
        editor.save().expect("save");

        let file = PeerFile::load(&path).expect("reloads");
        assert_eq!(file.get(&laptop), Some(&original));
    }

    #[cfg(unix)]
    #[test]
    fn saving_preserves_the_existing_mode() {
        use std::os::unix::fs::PermissionsExt as _;

        let (_dir, path) = scratch(Some(""));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");

        let mut editor = PeerEditor::open(&path).expect("open");
        editor.add(&peer("laptop", key())).expect("add");
        editor.save().expect("save");

        let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "an operator's tightened mode survives");
    }

    #[cfg(unix)]
    #[test]
    fn saving_preserves_the_existing_owner() {
        // Replacing by rename installs a new inode, so ownership has to be
        // carried over explicitly. Unprivileged this can only assert that the
        // owner is unchanged; the case that actually bit was `sudo veil-ctl
        // peer add` against a user-owned file, which handed it to root:root and
        // at mode 0640 locked the owner out of their own whitelist.
        use std::os::unix::fs::MetadataExt as _;

        let (_dir, path) = scratch(Some(""));
        let before = std::fs::metadata(&path).expect("stat");

        let mut editor = PeerEditor::open(&path).expect("open");
        editor.add(&peer("laptop", key())).expect("add");
        editor.save().expect("save");

        let after = std::fs::metadata(&path).expect("stat");
        assert_eq!(
            (after.uid(), after.gid()),
            (before.uid(), before.gid()),
            "the owner must survive the rename"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_created_file_is_not_world_readable() {
        use std::os::unix::fs::PermissionsExt as _;

        let (_dir, path) = scratch(None);
        let mut editor = PeerEditor::open(&path).expect("open");
        editor.add(&peer("laptop", key())).expect("add");
        editor.save().expect("save");

        let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
        assert_eq!(mode & 0o007, 0, "world has no access: {mode:o}");
    }
}
