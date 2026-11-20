#!/bin/bash
# Runs as root inside the test VM, booted into the target kernel.
# usage: loadtest-guest.sh <module.ko>
#
# Loads the livepatch, checks that it takes effect on vmlinux and, where
# the kernel lacks CVE-2026-99999's fix, on the three modules that part
# patches (one loaded before it, two after), and on kvm and its vendor
# module (loaded after); probes CVE-2026-99999 before and after; drives
# the two frees CVE-2026-98432 changes with IP options present
# (tools/tcpopt.py), connections completed through SYN cookies
# (tools/syncookie.py, CVE-2026-99288) and a KVM guest
# (tools/kvmrun.py, CVE-2022-3344 and CVE-2026-99312); then disables and
# removes it.  With OLDKO= set to the kernel's module from
# nsrg-fmlorg/kpatch-cve-2026-98432, that one is loaded first, and the
# new one must replace it; with OLDREF= also set, that repository's own
# script must then refuse to put its module back over the new one; and
# when that module is loaded all the same, livepatch.sh must recover.
# Prints "RESULT: PASS" or "RESULT: FAIL" last.
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
	name=livepatch_el_r1_$(echo "${k%.x86_64}" | tr '.-' '__')
else
	name=$(modinfo -F name "$ko")
fi
echo "kernel:  $(uname -r)"
echo "module:  $name"
echo "vermagic $(modinfo -F vermagic "$ko")"
dmesg -C
# A warning from before the load, as a host has from boot.  livepatch.sh
# apply used to fail on it; the search at the end leaves it out.
OLDWARN='loadtest: logged before the livepatch'
echo "WARNING: $OLDWARN" > /dev/kmsg
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

# The kernel's module from the earlier repository, as a host that
# applied it would have it.
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
# SCRIPT_REF is the branch whose script is fetched (main unless the
# workflow runs on another).
RAW=https://raw.githubusercontent.com/nsrg-fmlorg/kpatch-el/${SCRIPT_REF:-main}/scripts/livepatch.sh
apply_new() {
	if [ "${FROM_RELEASE:-}" = 1 ]; then
		curl -fsSL "$RAW" | bash -s -- apply
	else
		SKIP_SHA256=1 bash "$(dirname "$0")/livepatch.sh" apply "$ko"
	fi
}
if [ "${FROM_RELEASE:-}" = 1 ]; then
	# The README's dry run, on a host that has downloaded nothing yet.
	curl -fsSL "$RAW" | bash -s -- check || bad "one-line check failed before anything was applied"
fi
apply_new ||
	{ bad "livepatch.sh apply failed"; dmesg | tail -20; echo "RESULT: FAIL"; exit 1; }

modprobe nfnetlink_queue || bad "modprobe nfnetlink_queue"
modprobe xt_CHECKSUM || bad "modprobe xt_CHECKSUM"
# kvm and the vendor module, loaded after the patch.  The vendor module
# loads only where the VM is given VMX or SVM (-cpu host on a host with
# nested virtualization).
modprobe kvm || bad "modprobe kvm"
kvmvendor=
case $(grep -m1 -owE 'vmx|svm' /proc/cpuinfo) in
vmx) kvmvendor=kvm_intel ;;
svm) kvmvendor=kvm_amd ;;
esac
if [ -n "$kvmvendor" ]; then
	modprobe "$kvmvendor" || bad "modprobe $kvmvendor"
else
	echo "note: no VMX or SVM in this VM; the KVM vendor module and guest are not exercised"
fi
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

# CVE-2026-99288: the established-hash lookups and the two refcount
# fixes, all in vmlinux.
for f in __inet_lookup_established __inet6_lookup_established tcp_get_cookie_sock tcp_conn_request; do
	if compgen -G "/sys/kernel/livepatch/$name/vmlinux/$f,*" >/dev/null; then
		echo "function $f: patched"
	else
		bad "function $f not in the livepatch"
	fi
done
# CVE-2022-3344 and CVE-2026-99312: the vCPU reset in kvm.
if compgen -G "/sys/kernel/livepatch/$name/kvm/kvm_vcpu_reset,*" >/dev/null; then
	echo "function kvm/kvm_vcpu_reset: patched"
else
	bad "function kvm_vcpu_reset not in the livepatch"
fi

# Each patched object must have its directory.  Where the kernel has a
# per-object "patched" file (not 4.18), it must read 1; otherwise the
# modules loaded after the patch must show "applying patch" in dmesg.
# The old loop skipped objects without the file and so checked nothing
# on 4.18.
want="vmlinux kvm $kvmvendor"
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

# CVE-2026-99288: connections made from SYN cookies, over IPv4 and IPv6.
sc=$("$PY" "$(dirname "$0")/syncookie.py" 200 2>&1); echo "$sc"
case $sc in *"syncookie: v4=200/200 v6=200/200"*) ;; *) bad "syncookie.py failed" ;; esac

# CVE-2022-3344 and CVE-2026-99312: vCPUs created (reset) and freed under
# the livepatch.
if [ -n "$kvmvendor" ]; then
	kr=$("$PY" "$(dirname "$0")/kvmrun.py" 20 2>&1); echo "$kr"
	case $kr in *"runs=20 hlt=20"*) ;; *) bad "kvmrun.py failed under the livepatch" ;; esac
fi

# ip_do_fragment(): a 3000-byte ping over a 1500-byte MTU is fragmented.
gw=$(ip route | awk '/^default/{print $3; exit}')
if ping -c 3 -s 3000 -W 2 "$gw" >/dev/null 2>&1; then
	echo "fragmented ping to $gw: ok"
else
	echo "fragmented ping to $gw: no reply (slirp may not answer; not a failure by itself)"
fi

# The earlier repository's script, run on a host that has this module:
# it must refuse.  Its module is a replace patch as well, and would take
# the fixes only this module carries away.  Run only when OLDREF names
# the branch of that repository whose script knows this module.
if [ -n "$oldname" ] && [ -n "${OLDREPO:-}" ] && [ -n "${OLDREF:-}" ]; then
	if curl -fsSL "https://raw.githubusercontent.com/$OLDREPO/${OLDREF}/scripts/livepatch.sh" |
		bash -s -- apply; then
		bad "the earlier repository's script applied its module over this one"
	else
		echo "earlier script refused, as it must"
	fi
	[ "$(cat /sys/kernel/livepatch/$name/enabled 2>/dev/null)" = 1 ] ||
		bad "$name no longer enabled after the earlier script ran"
fi

# The same done by hand, as a host that ran the earlier script before it
# refused would be left: the earlier module replaces this one, which
# stays loaded as a module.  apply must unload it and take over again.
if [ -n "$oldname" ]; then
	insmod "$OLDKO" || bad "earlier module $oldname did not load over the new one"
	for i in $(seq 120); do
		[ "$(cat /sys/kernel/livepatch/$oldname/transition 2>/dev/null)" = 0 ] && break
		sleep 1
	done
	sleep 2
	mods=$(lsmod)
	[[ $'\n'"$mods" == *$'\n'"$name "* ]] && m=loaded || m=unloaded
	echo "after the earlier module took over: $name livepatch $(cat /sys/kernel/livepatch/$name/enabled 2>/dev/null || echo gone), module $m"
	apply_new || bad "apply did not recover from a replaced module"
	[ "$(cat /sys/kernel/livepatch/$name/enabled 2>/dev/null)" = 1 ] ||
		bad "$name not enabled after recovering"
	mods=$(lsmod)
	[[ $'\n'"$mods" == *$'\n'"$oldname "* ]] && bad "earlier module $oldname still loaded after recovering"
fi

if dmesg | grep -v "$OLDWARN" | grep -E 'BUG:|Oops|WARNING:|livepatch: .*(fail|error)'; then
	bad "kernel messages above"
fi

bash "$(dirname "$0")/livepatch.sh" remove || bad "livepatch.sh remove failed"
mods=$(lsmod)
[[ $'\n'"$mods" == *$'\n'"$name "* ]] && bad "module still loaded after remove"

echo "--- dmesg"
dmesg
if [ $fail = 0 ]; then echo "RESULT: PASS"; else echo "RESULT: FAIL"; fi
exit $fail
