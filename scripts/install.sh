#!/usr/bin/env bash
#
# Installs VEIL into a single directory, /etc/veil by default:
#
#   /etc/veil/bin/           veil-ctl, veild, veil-clientd
#   /etc/veil/private.key    this machine's identity, mode 0600
#   /etc/veil/server.toml    server role only
#   /etc/veil/peers.toml     server role only, the whitelist
#   /etc/veil/client.toml    client role only
#
# Everything lives under one directory so uninstalling is removing it. No
# systemd units are installed; that arrives at M14.
#
# An existing key or config file is never overwritten. Regenerating a key
# silently invalidates every peers.toml entry that references it.

set -euo pipefail

DIR=/etc/veil
# Resolved once the target is known: root for a system directory, the invoking
# user for one they already own.
OWNER=
ROLE=

info() { printf '  \033[32m•\033[0m %s\n' "$1"; }
note() { printf '  \033[33m!\033[0m %s\n' "$1"; }
fail() {
	printf '  \033[31m✗\033[0m %s\n' "$1" >&2
	exit 1
}

# Whether this user could create or write $1 without escalating. Walks up to
# the nearest existing ancestor, since $1 itself may not exist yet.
can_write() {
	local path="$1"
	while [ ! -e "$path" ]; do
		local parent
		parent="$(dirname "$path")"
		[ "$parent" != "$path" ] || return 1
		path="$parent"
	done
	[ -w "$path" ]
}

usage() {
	cat >&2 <<'EOF'
usage: install.sh (--server | --client) [--owner USER] [--dir PATH]

  --server        install the server role (server.toml + peers.toml)
  --client        install the client role (client.toml)
  --owner USER    who owns the install directory. Defaults to root for a
                  system directory, which means running the daemons with sudo.
                  Pass --owner "$USER" to run them unprivileged; nothing needs
                  capabilities yet.
  --dir PATH      install somewhere other than /etc/veil
EOF
	exit 2
}

while [ $# -gt 0 ]; do
	case "$1" in
	--server | --client)
		[ -z "$ROLE" ] || fail "give only one of --server and --client"
		ROLE="${1#--}"
		;;
	--owner)
		OWNER="${2:-}"
		[ -n "$OWNER" ] || fail "--owner needs a user"
		shift
		;;
	--dir)
		DIR="${2:-}"
		[ -n "$DIR" ] || fail "--dir needs a path"
		shift
		;;
	-h | --help) usage ;;
	*) fail "unknown argument: $1" ;;
	esac
	shift
done

[ -n "$ROLE" ] || usage

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Escalate only when the target actually needs it: /etc/veil does, a directory
# under $HOME does not, and requiring a password to write somewhere already
# writable would be theatre.
SUDO=
if [ "$(id -u)" -ne 0 ] && ! can_write "$DIR"; then
	command -v sudo >/dev/null || fail "$DIR needs root and sudo is not installed"
	SUDO=sudo
fi

# An unset --owner follows the target: root owns a system directory, and the
# invoking user owns one they could already write to.
if [ -z "$OWNER" ]; then
	if [ -n "$SUDO" ] || [ "$(id -u)" -eq 0 ]; then
		OWNER=root
	else
		OWNER="$(id -un)"
	fi
fi

id -u "$OWNER" >/dev/null 2>&1 || fail "no such user: $OWNER"

# Without escalation the only owner we can hand files to is ourselves.
if [ -z "$SUDO" ] && [ "$(id -u)" -ne 0 ] && [ "$OWNER" != "$(id -un)" ]; then
	fail "cannot install as $OWNER without root; re-run with sudo"
fi

# `install -o` is a root-only operation, so only ask for it when escalating.
own=()
if [ -n "$SUDO" ] || [ "$(id -u)" -eq 0 ]; then
	own=(-o "$OWNER" -g "$(id -gn "$OWNER")")
fi

# Run a command as the owner, which is already us when not escalating.
as_owner() {
	if [ -n "$SUDO" ]; then
		$SUDO -u "$OWNER" "$@"
	else
		"$@"
	fi
}

# 1. Build first, as the invoking user. Running cargo as root leaves
#    root-owned artefacts in target/ that the user then cannot rebuild over.
printf '\nBuilding VEIL (release)\n'
if [ -n "${SUDO_USER:-}" ] && [ "$(id -u)" -eq 0 ]; then
	sudo -u "$SUDO_USER" cargo build --release --workspace --manifest-path "$root/Cargo.toml"
else
	cargo build --release --workspace --manifest-path "$root/Cargo.toml"
fi

bin="$root/target/release"
for prog in veil-ctl veild veil-clientd; do
	[ -x "$bin/$prog" ] || fail "$prog was not built"
done

# 2. The directory tree. 0750: the private key lives here.
printf '\nInstalling into %s (owner %s)\n' "$DIR" "$OWNER"
$SUDO install -d -m 0750 "${own[@]}" "$DIR" "$DIR/bin"

# 3. The binaries.
for prog in veil-ctl veild veil-clientd; do
	$SUDO install -m 0750 "${own[@]}" "$bin/$prog" "$DIR/bin/$prog"
	info "$DIR/bin/$prog"
done

# 4. The identity. Generated once and never regenerated.
if $SUDO test -f "$DIR/private.key"; then
	info "private.key exists, keeping it"
else
	as_owner "$DIR/bin/veil-ctl" keygen --out "$DIR/private.key" >/dev/null
	info "private.key generated (mode 0600)"
fi

pubkey="$(as_owner "$DIR/bin/veil-ctl" pubkey --key "$DIR/private.key")"

# 5. Config templates, written only when absent.
write_if_absent() {
	local path="$1"
	if $SUDO test -f "$path"; then
		info "$(basename "$path") exists, keeping it"
		return
	fi
	$SUDO tee "$path" >/dev/null
	$SUDO chown "$OWNER:$(id -gn "$OWNER")" "$path"
	$SUDO chmod 0640 "$path"
	info "$(basename "$path") written"
}

if [ "$ROLE" = server ]; then
	write_if_absent "$DIR/server.toml" <<'EOF'
# VEIL server configuration.
# Every setting here can also be given on the command line, which wins.

# UDP address to listen on. QUIC is UDP: open the port accordingly.
listen = "0.0.0.0:51820"

# private_key = "/etc/veil/private.key"
# peers       = "/etc/veil/peers.toml"
EOF

	write_if_absent "$DIR/peers.toml" <<'EOF'
# VEIL peer whitelist. A peer may connect only if its public key is listed
# here and enabled. Deleting an entry, or setting enabled = false, revokes it.
#
# Managed with `veil-ctl peer add|set|remove|list`, which preserves the
# comments in this file. Hand-editing is equally fine.
EOF
else
	write_if_absent "$DIR/client.toml" <<'EOF'
# VEIL client configuration.
# Fill in both settings below, from `veil-ctl pubkey` on the server and the
# server's address. Every setting can also be given on the command line.

# server     = "203.0.113.10:51820"
# server_key = "ed25519:..."

# private_key = "/etc/veil/private.key"
EOF
fi

# 6. What to do next.
printf '\n\033[32mInstalled.\033[0m This machine'\''s public key:\n\n  %s\n\n' "$pubkey"

if [ "$OWNER" = root ]; then
	run="sudo $DIR/bin/veil-ctl"
	note "owned by root, so run the daemons with sudo:"
	printf '      %s serve\n' "$run"
	note "sudo's secure_path will not find $DIR/bin, so use the full path above"
else
	run="veil-ctl"
	info "owned by $OWNER, so the daemons run unprivileged"
	# shellcheck disable=SC2016  # $PATH stays literal: this line is copied verbatim.
	printf '\n  Add to your shell profile:\n      export PATH="$PATH:%s"\n' "$DIR/bin"
fi

if [ "$ROLE" = server ]; then
	cat <<EOF

  Next, on the server:
    1. Enrol a client, using the public key it printed when installed:
         $run peer add laptop ed25519:...
    2. Start it:
         $run serve

  QUIC is UDP. If a firewall is running, open UDP 51820.
EOF
else
	cat <<EOF

  Next, on this client:
    1. Put the key above into the server's whitelist, on the server:
         veil-ctl peer add $(hostname -s) $pubkey
    2. Fill in server and server_key in $DIR/client.toml
    3. Connect:
         $run connect
EOF
fi
