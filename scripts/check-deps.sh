#!/usr/bin/env bash
#
# Enforces the dependency policy in plan.md §5.6:
#
#   1. Every dependency a workspace member declares must be inherited with
#      `workspace = true`, never given a version of its own.
#   2. Every name it inherits must appear in the root [workspace.dependencies]
#      table, which is the normative allowlist from §5.2.
#
# Written in shell rather than Rust so that the check is not itself part of the
# dependency graph it polices.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
failures=0

fail() {
	printf '  \033[31m✗\033[0m %s\n' "$1" >&2
	failures=$((failures + 1))
}

# Names declared in the root [workspace.dependencies] table.
allowlist="$(awk '
	/^\[workspace\.dependencies\]/ { inside = 1; next }
	/^\[/                          { inside = 0 }
	inside && /^[A-Za-z0-9_-]+[[:space:]]*=/ {
		split($0, parts, "=")
		gsub(/[[:space:]]/, "", parts[1])
		print parts[1]
	}
' "$root/Cargo.toml" | sort -u)"

if [ -z "$allowlist" ]; then
	fail "the root [workspace.dependencies] table is empty or unparseable"
	exit 1
fi

for manifest in "$root"/crates/*/Cargo.toml; do
	crate="$(basename "$(dirname "$manifest")")"

	# Dependency lines from every dependency section of this member.
	deps="$(awk '
		/^\[(dependencies|dev-dependencies|build-dependencies)\]/ { inside = 1; next }
		/^\[/                                                     { inside = 0 }
		inside && /^[A-Za-z0-9_-]+/ { print }
	' "$manifest")"

	# A [dependencies.foo] sub-table would slip past the line parser above.
	if grep -qE '^\[(dev-|build-)?dependencies\.' "$manifest"; then
		fail "$crate declares a dependency sub-table; use inline \`name.workspace = true\`"
	fi

	while IFS= read -r line; do
		[ -n "$line" ] || continue
		name="${line%%[.= ]*}"

		case "$line" in
		"$name".workspace[[:space:]]*=*true* | "$name"[[:space:]]*=[[:space:]]*\{*workspace[[:space:]]*=[[:space:]]*true*) ;;
		*)
			fail "$crate declares '$name' without \`workspace = true\`"
			continue
			;;
		esac

		if ! printf '%s\n' "$allowlist" | grep -qx -- "$name"; then
			fail "$crate inherits '$name', which is not in [workspace.dependencies]"
		fi
	done <<<"$deps"
done

if [ "$failures" -gt 0 ]; then
	printf '\ndependency policy: \033[31m%d violation(s)\033[0m (see plan.md §5)\n' "$failures" >&2
	exit 1
fi

printf 'dependency policy: \033[32mok\033[0m\n'
