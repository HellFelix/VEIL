//! Daemon configuration: `server.toml` and `client.toml`.
//!
//! Each file is optional. Every field can also be given on the command line,
//! and the command line wins, so a daemon can be run entirely from flags during
//! development and entirely from `/etc/veil` in a deployment.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use veil_crypto::PublicKey;

use crate::Error;

/// Default UDP address the server listens on. QUIC is UDP.
pub const DEFAULT_LISTEN: &str = "0.0.0.0:51820";

/// Default location of this machine's private key.
pub const DEFAULT_PRIVATE_KEY: &str = "/etc/veil/private.key";

/// Default location of the server's peer whitelist.
pub const DEFAULT_PEERS: &str = "/etc/veil/peers.toml";

/// Default location of the server's own configuration.
pub const DEFAULT_SERVER_CONFIG: &str = "/etc/veil/server.toml";

/// Default location of the client's own configuration.
pub const DEFAULT_CLIENT_CONFIG: &str = "/etc/veil/client.toml";

/// Everything `veild` needs to start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerSettings {
    /// UDP address to listen on.
    pub listen: SocketAddr,
    /// The server's own key. Must be mode `0600`.
    pub private_key: PathBuf,
    /// The peer whitelist.
    pub peers: PathBuf,
}

/// Everything `veil-clientd` needs to start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientSettings {
    /// The server's UDP address.
    pub server: SocketAddr,
    /// The key this client pins the server to.
    pub server_key: PublicKey,
    /// This device's own key. Must be mode `0600`.
    pub private_key: PathBuf,
}

/// [`ServerSettings`] with every field still optional.
///
/// This is what `server.toml` deserializes into and what command line flags
/// overlay onto, so a field given in neither place falls back to its default.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PartialServerSettings {
    /// UDP address to listen on.
    pub listen: Option<SocketAddr>,
    /// Path to the server's own key.
    pub private_key: Option<PathBuf>,
    /// Path to the peer whitelist.
    pub peers: Option<PathBuf>,
}

impl PartialServerSettings {
    /// Reads `server.toml`, treating an absent file as "nothing specified".
    ///
    /// Only [`ErrorKind::NotFound`](std::io::ErrorKind::NotFound) is forgiven.
    /// A file that exists but cannot be read is a real error, because silently
    /// falling back to defaults would start a server the operator did not
    /// configure.
    pub fn load_or_default(path: &Path) -> Result<Self, Error> {
        Ok(read_optional(path)?
            .map(|text| toml::from_str(&text))
            .transpose()?
            .unwrap_or_default())
    }

    /// Overlays `cli` onto `self`, field by field. Anything set in `cli` wins.
    #[must_use]
    pub fn overlay(self, cli: Self) -> Self {
        Self {
            listen: cli.listen.or(self.listen),
            private_key: cli.private_key.or(self.private_key),
            peers: cli.peers.or(self.peers),
        }
    }

    /// Fills in the defaults for whatever is still unset.
    ///
    /// Total: every server field has a sensible default, so this cannot fail.
    #[must_use]
    pub fn finish(self) -> ServerSettings {
        ServerSettings {
            listen: self.listen.unwrap_or(default_listen()),
            private_key: self
                .private_key
                .unwrap_or_else(|| PathBuf::from(DEFAULT_PRIVATE_KEY)),
            peers: self.peers.unwrap_or_else(|| PathBuf::from(DEFAULT_PEERS)),
        }
    }
}

/// [`ClientSettings`] with every field still optional.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PartialClientSettings {
    /// The server's UDP address.
    pub server: Option<SocketAddr>,
    /// The key to pin the server to.
    pub server_key: Option<PublicKey>,
    /// Path to this device's own key.
    pub private_key: Option<PathBuf>,
}

impl PartialClientSettings {
    /// Reads `client.toml`, treating an absent file as "nothing specified".
    pub fn load_or_default(path: &Path) -> Result<Self, Error> {
        let Some(text) = read_optional(path)? else {
            return Ok(Self::default());
        };

        let raw: RawClientSettings = toml::from_str(&text)?;

        // Parsed here rather than by serde: `PublicKey` deliberately has no
        // `Deserialize` impl, since plan.md §5.2 keeps `serde` out of
        // `veil-crypto`. Same reasoning as `RawPeer` in `peers.rs`.
        let server_key = raw
            .server_key
            .map(|key| key.parse::<PublicKey>())
            .transpose()
            .map_err(|source| Error::SettingsKey {
                path: path.display().to_string(),
                source,
            })?;

        Ok(Self {
            server: raw.server,
            server_key,
            private_key: raw.private_key,
        })
    }

    /// Overlays `cli` onto `self`, field by field. Anything set in `cli` wins.
    #[must_use]
    pub fn overlay(self, cli: Self) -> Self {
        Self {
            server: cli.server.or(self.server),
            server_key: cli.server_key.or(self.server_key),
            private_key: cli.private_key.or(self.private_key),
        }
    }

    /// Fills in defaults, failing if a field with no default is still unset.
    ///
    /// `server` and `server_key` cannot be guessed, so the error names the
    /// missing field and the file it was expected in. `path` is used only for
    /// that message.
    pub fn finish(self, path: &Path) -> Result<ClientSettings, Error> {
        let missing = |field| Error::Missing {
            field,
            path: path.display().to_string(),
        };

        Ok(ClientSettings {
            server: self.server.ok_or_else(|| missing("server"))?,
            server_key: self.server_key.ok_or_else(|| missing("server_key"))?,
            private_key: self
                .private_key
                .unwrap_or_else(|| PathBuf::from(DEFAULT_PRIVATE_KEY)),
        })
    }
}

/// `client.toml` as TOML sees it, before the key is parsed.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawClientSettings {
    server: Option<SocketAddr>,
    server_key: Option<String>,
    private_key: Option<PathBuf>,
}

/// Reads a file, mapping "not found" to `None` and any other failure to an error.
fn read_optional(path: &Path) -> Result<Option<String>, Error> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(Error::Read {
            path: path.display().to_string(),
            source,
        }),
    }
}

/// The compiled-in listen address.
///
/// [`DEFAULT_LISTEN`] is a literal this crate controls, so it always parses;
/// the fallback keeps the promise anyway rather than unwrapping.
fn default_listen() -> SocketAddr {
    DEFAULT_LISTEN
        .parse()
        .unwrap_or(SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 51820)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use veil_crypto::StaticKeypair;

    fn key() -> PublicKey {
        StaticKeypair::generate().expect("keygen").public()
    }

    fn write(dir: &tempfile::TempDir, name: &str, text: &str) -> PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, text).expect("write");
        path
    }

    #[test]
    fn server_file_is_parsed_in_full() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write(
            &dir,
            "server.toml",
            r#"
            listen      = "0.0.0.0:4242"
            private_key = "/srv/veil.key"
            peers       = "/srv/peers.toml"
            "#,
        );

        let settings = PartialServerSettings::load_or_default(&path)
            .expect("loads")
            .finish();

        assert_eq!(
            settings.listen,
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 4242))
        );
        assert_eq!(settings.private_key, PathBuf::from("/srv/veil.key"));
        assert_eq!(settings.peers, PathBuf::from("/srv/peers.toml"));
    }

    #[test]
    fn unspecified_server_fields_take_their_defaults() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write(&dir, "server.toml", "listen = \"127.0.0.1:9999\"\n");

        let settings = PartialServerSettings::load_or_default(&path)
            .expect("loads")
            .finish();

        assert_eq!(settings.listen.port(), 9999);
        assert_eq!(settings.private_key, PathBuf::from(DEFAULT_PRIVATE_KEY));
        assert_eq!(settings.peers, PathBuf::from(DEFAULT_PEERS));
    }

    #[test]
    fn an_absent_file_yields_pure_defaults() {
        // This is what lets `veil-ctl serve --listen ...` work on a machine
        // with no /etc/veil at all.
        let dir = tempfile::tempdir().expect("tempdir");
        let settings = PartialServerSettings::load_or_default(&dir.path().join("nope.toml"))
            .expect("an absent file is not an error")
            .finish();

        assert_eq!(settings.listen.to_string(), DEFAULT_LISTEN);
        assert_eq!(settings.private_key, PathBuf::from(DEFAULT_PRIVATE_KEY));
    }

    #[test]
    fn the_command_line_beats_the_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write(
            &dir,
            "server.toml",
            "listen = \"0.0.0.0:1111\"\npeers = \"/from/file.toml\"\n",
        );

        let file = PartialServerSettings::load_or_default(&path).expect("loads");
        let cli = PartialServerSettings {
            listen: Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 2222))),
            ..Default::default()
        };

        let settings = file.overlay(cli).finish();

        assert_eq!(settings.listen.port(), 2222, "cli wins");
        assert_eq!(
            settings.peers,
            PathBuf::from("/from/file.toml"),
            "fields the cli did not set survive"
        );
    }

    #[test]
    fn client_file_is_parsed_in_full() {
        let dir = tempfile::tempdir().expect("tempdir");
        let expected = key();
        let path = write(
            &dir,
            "client.toml",
            &format!(
                "server = \"192.0.2.1:51820\"\nserver_key = \"{expected}\"\nprivate_key = \"/c.key\"\n"
            ),
        );

        let settings = PartialClientSettings::load_or_default(&path)
            .expect("loads")
            .finish(&path)
            .expect("complete");

        assert_eq!(settings.server.port(), 51820);
        assert_eq!(settings.server_key, expected);
        assert_eq!(settings.private_key, PathBuf::from("/c.key"));
    }

    #[test]
    fn a_missing_client_field_names_itself() {
        // The error an operator sees when install.sh's template was never
        // filled in. It has to say which line to edit.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write(&dir, "client.toml", "server = \"192.0.2.1:51820\"\n");

        let err = PartialClientSettings::load_or_default(&path)
            .expect("loads")
            .finish(&path)
            .expect_err("server_key is required");

        assert!(
            matches!(
                err,
                Error::Missing {
                    field: "server_key",
                    ..
                }
            ),
            "{err:?}"
        );
        assert!(err.to_string().contains("server_key"));

        let err = PartialClientSettings::default()
            .finish(&path)
            .expect_err("server is required");
        assert!(
            matches!(
                err,
                Error::Missing {
                    field: "server",
                    ..
                }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn a_malformed_server_key_names_the_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write(&dir, "client.toml", "server_key = \"not-a-key\"\n");

        let err = PartialClientSettings::load_or_default(&path).expect_err("must fail");
        assert!(matches!(err, Error::SettingsKey { .. }), "{err:?}");
    }

    #[test]
    fn a_misspelled_field_is_rejected() {
        // `deny_unknown_fields` matters here for the same reason it does in
        // peers.toml: a typo must not silently mean "default".
        let dir = tempfile::tempdir().expect("tempdir");

        let path = write(&dir, "server.toml", "listem = \"0.0.0.0:1\"\n");
        assert!(PartialServerSettings::load_or_default(&path).is_err());

        let path = write(&dir, "client.toml", "serverkey = \"x\"\n");
        assert!(PartialClientSettings::load_or_default(&path).is_err());
    }

    #[test]
    fn an_unreadable_file_is_still_an_error() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            let dir = tempfile::tempdir().expect("tempdir");
            let path = write(&dir, "server.toml", "listen = \"0.0.0.0:1\"\n");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).expect("chmod");

            // Root ignores permission bits, so this assertion is only
            // meaningful unprivileged.
            if std::fs::read_to_string(&path).is_err() {
                assert!(matches!(
                    PartialServerSettings::load_or_default(&path),
                    Err(Error::Read { .. })
                ));
            }
        }
    }
}
