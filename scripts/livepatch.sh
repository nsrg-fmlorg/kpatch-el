#!/bin/bash
# Apply, inspect or remove the cumulative livepatch on an AlmaLinux or
# Rocky Linux host: one module per kernel with every fix in patches/ that
# the kernel lacks.  The module is chosen by the distribution and the
# running kernel from the table below; a kernel not in it is refused.
# Run as root.
#
# On a host running this kernel's module from an earlier repository
# (nsrg-fmlorg/kpatch-cve-2026-98432, kpatch-alma-cve-2026-99999 or
# kpatch-rocky-cve-2026-99999) or an earlier revision of this one, apply
# replaces it: the new patch takes over atomically, and the earlier
# module, then disabled, is unloaded.
#
# usage: livepatch.sh check  [module.ko]
#        livepatch.sh apply  [module.ko]
#        livepatch.sh status
#        livepatch.sh remove
#
# Or straight from GitHub, which downloads the module from the release:
#   curl -fsSL https://raw.githubusercontent.com/nsrg-fmlorg/kpatch-el/main/scripts/livepatch.sh | sudo bash -s -- apply
#
# module.ko defaults to /var/lib/livepatch/<name>.ko; when it is missing,
# apply downloads it from the kernel's release and refuses it unless its
# SHA-256 matches the table.  With SKIP_SHA256=1 and a module.ko of your
# own (built with scripts/build-local.sh), the table is not used: the
# module's vermagic must match the running kernel instead.  The CI load
# test uses this script for apply and remove.
set -uo pipefail

REPO=nsrg-fmlorg/kpatch-el

# Released, load-tested modules: distribution (the one that built the
# kernel, see DISTRO below), kernel release, SHA-256, release tag.
modules() {
	cat <<'EOF'
EOF
}

KVER=$(uname -r)
OSID=$(. /etc/os-release 2>/dev/null; echo "${ID:-}")
# The module has to match the running kernel's build, so the distribution
# is the one that built that kernel.  This used to be the ID in
# /etc/os-release alone: a host converted from one distribution to the
# other and not yet rebooted then got the other one's module, which
# passes the vermagic and SHA-256 checks, and for 47 of the 287 kernel
# versions both ship the two modules differ.  Vendor reads "AlmaLinux",
# "Rocky" (8) or "Rocky Enterprise Software Foundation" (9, 10).
case $(rpm -q --qf '%{VENDOR}' "kernel-core-$KVER" 2>/dev/null) in
AlmaLinux*) DISTRO=almalinux ;;
Rocky*) DISTRO=rocky ;;
*) DISTRO=$OSID ;;
esac
NAME=livepatch_el_r1_$(echo "${KVER%.x86_64}" | tr '.-' '__')
SYS=/sys/kernel/livepatch/$NAME
row=$(modules | awk -v d="$DISTRO" -v k="$KVER" '$1 == d && $2 == k')
SHA256=$(echo "$row" | awk '{print $3}')
TAG=$(echo "$row" | awk '{print $4}')
RELEASE_URL=https://github.com/$REPO/releases/download/$TAG/$NAME.ko

ko=${2:-/var/lib/livepatch/$NAME.ko}
fail=0
ok()  { echo "ok:   $*"; }
bad() { echo "FAIL: $*"; fail=1; }
die() { echo "FAIL: $*"; exit 1; }

# Done when transition reads 0, or when the patch's directory is gone (on
# 4.18 a disabled patch is freed at once).
wait_transition() {
	local i
	for i in $(seq 120); do
		[ -d "$SYS" ] || return 0
		[ "$(cat "$SYS/transition" 2>/dev/null)" = 0 ] && return 0
		sleep 1
	done
	return 1
}

check() {
	[ "$(id -u)" = 0 ] || bad "not root"
	if [ "${SKIP_SHA256:-}" = 1 ]; then
		echo "note: own module (SKIP_SHA256=1); the table is not used"
	elif [ -n "$row" ]; then
		ok "$DISTRO kernel $KVER has a released module ($TAG)"
	else
		bad "no released module for $DISTRO kernel $KVER (see the README for the list)"
	fi
	case $DISTRO in
	almalinux|rocky) ok "$(. /etc/os-release; echo "$NAME $VERSION_ID")" ;;
	*) bad "distribution is '$DISTRO'; these modules are for AlmaLinux and Rocky Linux" ;;
	esac
	[ "$DISTRO" = "$OSID" ] ||
		echo "note: /etc/os-release says '$OSID', but the running kernel was built by $DISTRO; using its module"
	local sb
	sb=$(mokutil --sb-state 2>/dev/null || true)
	case "$sb" in
	*enabled*) bad "Secure Boot is enabled; this unsigned module will be refused" ;;
	*disabled*) ok "Secure Boot disabled" ;;
	*) echo "note: Secure Boot state unknown (mokutil missing?)" ;;
	esac
	if [ -f "$ko" ]; then
		local vm
		vm=$(modinfo -F vermagic "$ko" 2>/dev/null)
		[ "${vm%% *}" = "$KVER" ] && ok "module vermagic $KVER" ||
			bad "module vermagic is '${vm%% *}', kernel is $KVER"
		if [ "${SKIP_SHA256:-}" != 1 ] && [ -n "$SHA256" ]; then
			[ "$(sha256sum "$ko" | cut -d' ' -f1)" = "$SHA256" ] && ok "SHA-256 matches the release" ||
				bad "SHA-256 differs from the release (self-built? set SKIP_SHA256=1)"
		fi
	elif [ "$1" = later ] && [ -n "$row" ] && [ "${SKIP_SHA256:-}" != 1 ]; then
		# "check" on its own used to fail here on every host that had
		# not applied yet, since only apply downloads.
		echo "note: no module at $ko yet; apply downloads it from $TAG and checks it"
	else
		bad "no module at $ko"
	fi
	[ -d "$SYS" ] && echo "note: $NAME is already loaded"
	stale && echo "note: $NAME is loaded as a module but is not a livepatch any more; apply and remove unload it"
	local o
	for o in $(earlier); do echo "note: earlier module $o is loaded; apply replaces it"; done
	return $fail
}

# The modules of the earlier repositories, and of earlier revisions of
# this one, that are loaded.
earlier() {
	lsmod | awk -v n="$NAME" '$1 != n && $1 ~ /^livepatch_(cve_2026_(98432|99999)|el_r[0-9]+)_/ {print $1}'
}

# This module, loaded but no longer a livepatch: something replaced it.
# An earlier repository's module does, when it is applied after this
# one; it is a replace patch too, and takes the fixes it lacks away.  remove then said "not loaded" and
# apply failed in insmod, on a module of the same name.
stale() {
	[ ! -d "$SYS" ] && [ -d "/sys/module/$NAME" ]
}

unload_stale() {
	stale || return 0
	local i
	for i in $(seq 10); do
		rmmod "$NAME" 2>/dev/null && break
		sleep 1
	done
	[ ! -d "/sys/module/$NAME" ] && ok "unloaded $NAME, which another livepatch had replaced" ||
		die "$NAME is loaded but replaced by another livepatch, and rmmod failed"
}

# A replaced patch stays loaded as a module, disabled (and on 4.18 without
# its sysfs directory); unload it.
unload_earlier() {
	local o e i
	for o in $(earlier); do
		e=$(cat "/sys/kernel/livepatch/$o/enabled" 2>/dev/null || echo gone)
		if [ "$e" = 1 ]; then
			bad "earlier module $o is still enabled; not unloading it"
			continue
		fi
		for i in $(seq 10); do
			rmmod "$o" 2>/dev/null && break
			sleep 1
		done
		[ ! -d "/sys/module/$o" ] && ok "earlier module $o replaced and unloaded" ||
			bad "earlier module $o replaced, but rmmod failed"
	done
}

status() {
	if [ ! -d "$SYS" ]; then
		echo "$NAME: not loaded"
		return 1
	fi
	echo "$NAME: enabled=$(cat "$SYS/enabled") transition=$(cat "$SYS/transition")"
	local d
	for d in "$SYS"/*/; do
		[ -d "$d" ] && echo "  object $(basename "$d")"
	done
	echo "  kernel taint: $(cat /proc/sys/kernel/tainted)"
}

fetch() {
	[ -f "$ko" ] && return 0
	[ "${SKIP_SHA256:-}" = 1 ] && die "no module at $ko (and SKIP_SHA256=1: not downloading)"
	[ -n "$row" ] || die "no released module for kernel $KVER"
	echo "downloading $RELEASE_URL"
	mkdir -p "$(dirname "$ko")"
	curl -fsSL -o "$ko.tmp" "$RELEASE_URL" || { rm -f "$ko.tmp"; die "download failed"; }
	[ "$(sha256sum "$ko.tmp" | cut -d' ' -f1)" = "$SHA256" ] ||
		{ rm -f "$ko.tmp"; die "downloaded module does not match SHA-256 $SHA256"; }
	mv "$ko.tmp" "$ko"
	ok "module saved to $ko"
}

apply() {
	fetch
	check now || die "checks failed; nothing loaded"
	[ -d "$SYS" ] && { echo "already loaded"; status; return 0; }
	unload_stale
	# Only what the kernel logs from here on is this load's doing.  The
	# whole buffer used to be searched, so a WARNING from boot made apply
	# exit 1 with the patch enabled.
	local msgs mark="livepatch.sh[$$]: loading $NAME"
	echo "$mark" > /dev/kmsg 2>/dev/null || mark=
	insmod "$ko" || die "insmod failed; see dmesg"
	wait_transition || die "transition did not finish in 120s; see dmesg"
	[ "$(cat "$SYS/enabled" 2>/dev/null)" = 1 ] || die "patch not enabled"
	msgs=$(dmesg)
	[ -n "$mark" ] && msgs=${msgs##*"$mark"}
	[[ "$msgs" == *"livepatch: '$NAME': patching complete"* ]] &&
		ok "patching complete" || bad "no 'patching complete' in dmesg"
	if grep -E 'BUG:|Oops|WARNING:' <<<"$msgs"; then
		bad "kernel messages above"
	fi
	unload_earlier
	status
	return $fail
}

remove() {
	if stale; then unload_stale; return 0; fi
	[ -d "$SYS" ] || { echo "$NAME: not loaded"; return 0; }
	echo 0 > "$SYS/enabled" || die "could not disable"
	wait_transition || die "unpatch transition did not finish in 120s"
	# Right after unpatching the module can still be busy for a moment
	# (8.8 and 8.10: rmmod failed at once, after "unpatching complete").
	local i
	for i in $(seq 10); do
		rmmod "$NAME" 2>/dev/null && break
		sleep 1
	done
	[ ! -d "/sys/module/$NAME" ] || die "rmmod failed"
	ok "removed"
}

case "${1:-}" in
check)  check later ;;
apply)  apply ;;
status) status ;;
remove) remove ;;
*) echo 'usage: livepatch.sh check|apply|status|remove [module.ko]'; exit 2 ;;
esac
