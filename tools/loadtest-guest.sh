#!/bin/bash
# Runs as root inside the test VM, booted into the target kernel.
# usage: loadtest-guest.sh <module.ko>
#
# Loads the livepatch, checks that it takes effect on vmlinux and, where
# the kernel lacks CVE-2026-99999's fix, on the three modules that part
# patches (one loaded before it, two after); probes CVE-2026-99999 before
# and after; drives the two frees CVE-2026-98432 changes with IP options
# present (tools/tcpopt.py); then disables and removes it.  With OLDKO=
# set to the kernel's earlier CVE-2026-99999 module, that one is loaded
# first, and the new one must replace it.  Prints "RESULT: PASS" or
# "RESULT: FAIL" last.
set -uo pipefail

ko=$1
fail=0
bad() { echo "FAIL: $*"; fail=1; }

# Done when transition reads 0, or when the patch's directory is gone:
# on 4.18 a disabled patch is freed at once, and the old version of this
# loop then read a missing file for 120 seconds and called it a failure.
wait_transition() {
	local i d=/sys/kernel/livepatch/$name
	for i in $(seq 120); do
		[ -d "$d" ] || return 0
		[ "$(cat "$d/transition" 2>/dev/null)" = 0 ] && return 0
		sleep 1
	done
	return 1
}

if [ "${FROM_RELEASE:-}" = 1 ]; then
	# No module is copied over: the name is the one livepatch.sh derives.
	k=$(uname -r)
	name=livepatch_cve_2026_98432_$(echo "${k%.x86_64}" | tr '.-' '__')
else
	name=$(modinfo -F name "$ko")
fi
echo "kernel:  $(uname -r)"
echo "module:  $name"
echo "vermagic $(modinfo -F vermagic "$ko")"
dmesg -C
PY=python3
command -v "$PY" >/dev/null 2>&1 || PY=/usr/libexec/platform-python

# One patched module present before the livepatch, the others after, so
# both the immediate and the module-load paths are exercised.
modprobe br_netfilter 2>/dev/null
modprobe nf_conntrack_bridge 2>/dev/null &&
	echo "nf_conntrack_bridge loaded before" ||
	echo "nf_conntrack_bridge not available (expected on 8)"

# CVE-2026-99999 on the shipped kernel, before the livepatch is applied.
# Whether the module carries that part comes from its port (NEED99999,
# set by loadtest.sh); the probe cannot tell on 10, where the frame is
# refused before the sink.  A kernel that reproduces it must have it.
before_csum=$(bash "$(dirname "$0")/csum-probe.sh" before); echo "$before_csum"
need99999=${NEED99999:-}
echo "CVE-2026-99999 part in the module: ${need99999:+yes}${need99999:-no}"
case $before_csum in
*"bad=vulnerable"*) [ -n "$need99999" ] || bad "the shipped kernel reproduces CVE-2026-99999, but the port has no fix for it" ;;
esac

# The kernel's earlier CVE-2026-99999 module, as a host that applied it
# would have it.
oldname=
if [ -n "${OLDKO:-}" ]; then
	oldname=$(modinfo -F name "$OLDKO")
	insmod "$OLDKO" || bad "earlier module $oldname did not load"
	for i in $(seq 120); do
		[ "$(cat /sys/kernel/livepatch/$oldname/transition 2>/dev/null)" = 0 ] && break
		sleep 1
	done
	echo "earlier module $oldname: enabled=$(cat /sys/kernel/livepatch/$oldname/enabled 2>/dev/null)"
fi

# Through scripts/livepatch.sh, the way a host applies it.  The module
# under test may come from any build, so its SHA-256 is not pinned here.
# FROM_RELEASE=1 instead runs the README's one-line command as published:
# the script from GitHub, the module from the release, SHA-256 checked.
if [ "${FROM_RELEASE:-}" = 1 ]; then
	curl -fsSL https://raw.githubusercontent.com/nsrg-fmlorg/kpatch-cve-2026-98432/main/scripts/livepatch.sh |
		bash -s -- apply ||
		{ bad "one-line apply failed"; dmesg | tail -20; echo "RESULT: FAIL"; exit 1; }
else
	SKIP_SHA256=1 bash "$(dirname "$0")/livepatch.sh" apply "$ko" ||
		{ bad "livepatch.sh apply failed"; dmesg | tail -20; echo "RESULT: FAIL"; exit 1; }
fi

modprobe nfnetlink_queue || bad "modprobe nfnetlink_queue"
modprobe xt_CHECKSUM || bad "modprobe xt_CHECKSUM"
sleep 2

# Replaced: the earlier patch is no longer enabled (on 4.18 its directory
# is gone at once), and livepatch.sh has unloaded its module.
if [ -n "$oldname" ]; then
	e=$(cat /sys/kernel/livepatch/$oldname/enabled 2>/dev/null || echo gone)
	echo "earlier module $oldname after apply: livepatch $e"
	case $e in 0|gone) echo "earlier module replaced" ;; *) bad "earlier module $oldname still enabled" ;; esac
	mods=$(lsmod)
	[[ $'\n'"$mods" == *$'\n'"$oldname "* ]] && bad "earlier module $oldname still loaded"
fi

# CVE-2026-98432: both functions are replaced in vmlinux.
for f in inet_sock_destruct tcp_v4_reqsk_destructor; do
	if compgen -G "/sys/kernel/livepatch/$name/vmlinux/$f,*" >/dev/null; then
		echo "function $f: patched"
	else
		bad "function $f not in the livepatch"
	fi
done

# Each patched object must have its directory.  Where the kernel has a
# per-object "patched" file (not 4.18), it must read 1; otherwise the
# modules loaded after the patch must show "applying patch" in dmesg.
# The old loop skipped objects without the file and so checked nothing
# on 4.18.
want=vmlinux
[ -n "$need99999" ] && want="$want nfnetlink_queue xt_CHECKSUM"
# Read whole, then match: "cmd | grep -q" under pipefail fails when grep
# stops early and cmd dies of SIGPIPE.
mods=$(lsmod)
[ -n "$need99999" ] && [[ $'\n'"$mods" == *$'\n'"nf_conntrack_bridge "* ]] && want="$want nf_conntrack_bridge"
msgs=$(dmesg)
for obj in $want; do
	d=/sys/kernel/livepatch/$name/$obj
	if [ ! -d "$d" ]; then
		bad "no livepatch object $obj"
	elif [ -f "$d/patched" ]; then
		p=$(cat "$d/patched")
		echo "object $obj patched=$p"
		[ "$p" = 1 ] || bad "$obj not patched"
	elif [ "$obj" = vmlinux ]; then
		[[ "$msgs" == *"livepatch: '$name': patching complete"* ]] &&
			echo "object vmlinux: patching complete" || bad "vmlinux: no 'patching complete'"
	elif [ "$obj" != nf_conntrack_bridge ]; then
		[[ "$msgs" == *"applying patch '$name' to loading module '$obj'"* ]] &&
			echo "object $obj: applied on load" || bad "$obj: no 'applying patch' message"
	else
		echo "object $obj: present (loaded before the patch)"
	fi
done

# CVE-2026-99999 again, with the livepatch applied: the frame the shipped
# kernel fragmented must now be dropped in ip_do_fragment().
after_csum=$(bash "$(dirname "$0")/csum-probe.sh" after); echo "$after_csum"
case $after_csum in
*"bad=vulnerable"*) bad "CVE-2026-99999 still reproduces with the livepatch applied" ;;
*"bad=fixed"*)
	echo "CVE-2026-99999: ip_do_fragment() now rejects the crafted frame"
	case $before_csum in
	*"bad=vulnerable"*) echo "CVE-2026-99999: reproduced on the shipped kernel, closed by the livepatch" ;;
	*) echo "note: the shipped kernel did not reproduce it ($before_csum)" ;;
	esac ;;
*) echo "note: the crafted frame did not reach ip_do_fragment on this kernel; TAP path not exercised ($after_csum)" ;;
esac

# CVE-2026-98432's two frees, with IP options present, under the livepatch.
tcpopt=$("$PY" "$(dirname "$0")/tcpopt.py" 2000 2>&1); echo "$tcpopt"
case $tcpopt in *"errors=0"*) ;; *) bad "tcpopt.py reported errors" ;; esac

# ip_do_fragment(): a 3000-byte ping over a 1500-byte MTU is fragmented.
gw=$(ip route | awk '/^default/{print $3; exit}')
if ping -c 3 -s 3000 -W 2 "$gw" >/dev/null 2>&1; then
	echo "fragmented ping to $gw: ok"
else
	echo "fragmented ping to $gw: no reply (slirp may not answer; not a failure by itself)"
fi

if dmesg | grep -E 'BUG:|Oops|WARNING:|livepatch: .*(fail|error)'; then
	bad "kernel messages above"
fi

bash "$(dirname "$0")/livepatch.sh" remove || bad "livepatch.sh remove failed"
mods=$(lsmod)
[[ $'\n'"$mods" == *$'\n'"$name "* ]] && bad "module still loaded after remove"

echo "--- dmesg"
dmesg
if [ $fail = 0 ]; then echo "RESULT: PASS"; else echo "RESULT: FAIL"; fi
exit $fail
