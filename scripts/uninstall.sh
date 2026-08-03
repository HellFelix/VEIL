#!/usr/bin/env bash
#
# Removes a VEIL installation.
#
# Everything VEIL owns lives in one directory, so this deletes that directory.
# That includes the private key, which is unrecoverable: a new one means
# re-enrolling this machine with every server it talks to. The contents are
# listed and confirmed first unless --yes is given.

set -euo pipefail

DIR=/etc/veil
ASSUME_YES=

info() { printf '  \033[32m•\033[0m %s\n' "$1"; }
note() { printf '  \033[33m!\033[0m %s\n' "$1"; }
fail() {
	printf '  \033[31m✗\033[0m %s\n' "$1" >&2
	exit 1
}

usage() {
	cat >&2 <<'EOF'
usage: uninstall.sh [--dir PATH] [--yes]

  --dir PATH   uninstall from somewhere other than /etc/veil
  --yes        do not ask for confirmation
EOF
	exit 2
}

while [ $# -gt 0 ]; do
	case "$1" in
	--yes | -y) ASSUME_YES=1 ;;
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

# Escalate only when the target needs it, matching install.sh: a tree the user
# already owns is removable without a password. Removing $DIR is a write to its
# parent, so both have to be writable.
needs_root() {
	[ ! -e "$DIR" ] && return 1
	[ -w "$DIR" ] && [ -w "$(dirname "$DIR")" ] && return 1
	return 0
}

SUDO=
if [ "$(id -u)" -ne 0 ] && needs_root; then
	command -v sudo >/dev/null || fail "$DIR needs root and sudo is not installed"
	SUDO=sudo
fi

# M14 has not written any units yet, so this is guarded on both systemctl and
# the units existing. Left in place so an M14 install is not orphaned by an
# older uninstall script.
removed_units=
if command -v systemctl >/dev/null 2>&1; then
	for unit in veild veil-clientd; do
		if systemctl list-unit-files "$unit.service" >/dev/null 2>&1 &&
			systemctl cat "$unit.service" >/dev/null 2>&1; then
			$SUDO systemctl disable --now "$unit.service" >/dev/null 2>&1 || true
			$SUDO rm -f "/etc/systemd/system/$unit.service"
			info "removed $unit.service"
			removed_units=1
		fi
	done
	[ -n "$removed_units" ] && $SUDO systemctl daemon-reload
fi

if [ ! -d "$DIR" ]; then
	info "$DIR does not exist, nothing to remove"
	[ -n "$removed_units" ] || info "no systemd units to remove either"
	exit 0
fi

printf '\nThis will delete %s and everything in it:\n\n' "$DIR"
$SUDO ls -la "$DIR" | sed 's/^/    /'

if $SUDO test -f "$DIR/private.key"; then
	printf '\n'
	note "private.key is included. It cannot be recovered, and this machine"
	note "will need re-enrolling with every server that whitelists it."
fi

if [ -z "$ASSUME_YES" ]; then
	printf '\nType the directory name to confirm: '
	read -r reply
	[ "$reply" = "$DIR" ] || fail "not confirmed, nothing was deleted"
fi

$SUDO rm -rf "$DIR"
printf '\n\033[32mRemoved %s.\033[0m\n' "$DIR"
