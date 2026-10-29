#!/bin/bash
# Apply, inspect or remove the livepatch for CVE-2026-98432 (and, on
# kernels without its fix, CVE-2026-99999) on an AlmaLinux or Rocky Linux
# host.  The module is chosen by the distribution and the running kernel
# from the table below; a kernel not in it is refused.  Run as root.
#
# On a host running this kernel's earlier CVE-2026-99999 module (from
# nsrg-fmlorg/kpatch-alma-cve-2026-99999 or kpatch-rocky-cve-2026-99999),
# apply replaces it: the new patch takes over atomically, and the earlier
# module, then disabled, is unloaded.
#
# usage: livepatch.sh check  [module.ko]
#        livepatch.sh apply  [module.ko]
#        livepatch.sh status
#        livepatch.sh remove
#
# Or straight from GitHub, which downloads the module from the release:
#   curl -fsSL https://raw.githubusercontent.com/nsrg-fmlorg/kpatch-cve-2026-98432/main/scripts/livepatch.sh | sudo bash -s -- apply
#
# module.ko defaults to /var/lib/livepatch/<name>.ko; when it is missing,
# apply downloads it from the kernel's release and refuses it unless its
# SHA-256 matches the table.  With SKIP_SHA256=1 and a module.ko of your
# own (built with scripts/build-local.sh), the table is not used: the
# module's vermagic must match the running kernel instead.  The CI load
# test uses this script for apply and remove.
set -uo pipefail

REPO=nsrg-fmlorg/kpatch-cve-2026-98432

# Released, load-tested modules: distribution (ID in /etc/os-release),
# kernel release, SHA-256, release tag.
modules() {
	cat <<'EOF'
EOF
}

KVER=$(uname -r)
DISTRO=$(. /etc/os-release 2>/dev/null; echo "${ID:-}")
NAME=livepatch_cve_2026_98432_$(echo "${KVER%.x86_64}" | tr '.-' '__')
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
	else
		bad "no module at $ko"
	fi
	[ -d "$SYS" ] && echo "note: $NAME is already loaded"
	local o
	for o in $(earlier); do echo "note: earlier module $o is loaded; apply replaces it"; done
	return $fail
}

# The CVE-2026-99999 modules of the earlier repositories that are loaded.
earlier() {
	lsmod | awk '$1 ~ /^livepatch_cve_2026_99999_/ {print $1}'
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
	check || die "checks failed; nothing loaded"
	[ -d "$SYS" ] && { echo "already loaded"; status; return 0; }
	insmod "$ko" || die "insmod failed; see dmesg"
	wait_transition || die "transition did not finish in 120s; see dmesg"
	[ "$(cat "$SYS/enabled" 2>/dev/null)" = 1 ] || die "patch not enabled"
	local msgs
	msgs=$(dmesg)
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
check)  check ;;
apply)  apply ;;
status) status ;;
remove) remove ;;
*) echo 'usage: livepatch.sh check|apply|status|remove [module.ko]'; exit 2 ;;
esac
