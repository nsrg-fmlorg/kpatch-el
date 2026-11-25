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
# The parts of the port in this kernel's module (tools/loadtest.sh).
HAS=" ${HAS:-} "
has() {
	case $1 in
	kvm) [ -n "${KVMFNS:-}" ] ;;
	svm) [ -n "${SVMFNS:-}" ] ;;
	*) [[ $HAS == *" $1 "* ]] ;;
	esac
}
echo "port:$HAS"
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
# kvm and the vendor module.  Where the VM is given VMX or SVM (-cpu host
# on a host with nested virtualization) the boot has loaded both already,
# so the patch was applied to them as it was enabled; they are unloaded
# and loaded again further down.
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
fns=
has 98432 && fns="inet_sock_destruct tcp_v4_reqsk_destructor"
for f in $fns; do
	if compgen -G "/sys/kernel/livepatch/$name/vmlinux/$f,*" >/dev/null; then
		echo "function $f: patched"
	else
		bad "function $f not in the livepatch"
	fi
done

# CVE-2026-99288: the established-hash lookups and the two refcount
# fixes, all in vmlinux.
fns=
has lookup && fns="__inet_lookup_established __inet6_lookup_established"
has syncookies && fns="$fns tcp_get_cookie_sock"
has fastopen && fns="$fns tcp_conn_request"
for f in $fns; do
	if compgen -G "/sys/kernel/livepatch/$name/vmlinux/$f,*" >/dev/null; then
		echo "function $f: patched"
	else
		bad "function $f not in the livepatch"
	fi
done
# CVE-2022-3344 and CVE-2026-99312: the vCPU reset in kvm.
if ! has kvm; then
	echo "note: no KVM fix in this kernel's module"
else
	for f in $KVMFNS; do
		if compgen -G "/sys/kernel/livepatch/$name/kvm/$f,*" >/dev/null; then
			echo "function kvm/$f: patched"
		else
			bad "function $f not in the livepatch"
		fi
	done
fi

# Each patched object must have its directory.  Where the kernel has a
# per-object "patched" file (not 4.18), it must read 1; otherwise the
# modules loaded after the patch must show "applying patch" in dmesg.
# The old loop skipped objects without the file and so checked nothing
# on 4.18.
# Nothing in kvm_intel changes, so it is no object of the livepatch.
# The last 9.9 and 10.3 kernels have the network fixes, and only KVM is left.
want=
if [ -n "$need99999" ] || has 98432 || has lookup || has syncookies || has fastopen; then
	want=vmlinux
fi
has kvm && want="$want kvm"
has svm && [ "$kvmvendor" = kvm_amd ] && want="$want kvm_amd"
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
	elif [[ $obj == kvm* ]]; then
		echo "object $obj: present (its functions are checked by kvm_hooked)"
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
# The sysfs directories are there whether or not a module is patched, and
# 4.18 has no "patched" file.  ftrace lists what is really redirected, with
# "I" (IPMODIFY) on a livepatched function.
tracing=/sys/kernel/debug/tracing
[ -e $tracing/enabled_functions ] || mount -t debugfs none /sys/kernel/debug 2>/dev/null
kvm_hooked() {
	local f fns=${KVMFNS:-} ef
	has kvm || return 0
	has svm && [ "$kvmvendor" = kvm_amd ] && fns="$fns $SVMFNS"
	ef=$(cat $tracing/enabled_functions)
	for f in $fns; do
		if grep -E "^$f \[kvm(_amd)?\] .* I" <<<"$ef"; then
			echo "$1: $f redirected"
		else
			bad "$1: $f not redirected"
		fi
	done
}
kvm_guest() {
	[ -n "$kvmvendor" ] || return 0
	kr=$("$PY" "$(dirname "$0")/kvmrun.py" 20 2>&1); echo "$kr"
	case $kr in *"runs=20 hlt=20"*) ;; *) bad "$1: kvmrun.py failed under the livepatch" ;; esac
}
kvm_hooked "kvm as found"
kvm_guest "kvm as found"
# The load path: the modules loaded for the first time under the
# livepatch, so it is taken off, they are unloaded, and it goes on again.
kvm_unload() {
	[ -z "$kvmvendor" ] || modprobe -r "$kvmvendor" || bad "modprobe -r $kvmvendor"
	if [ -d /sys/module/kvm ]; then modprobe -r kvm || bad "modprobe -r kvm"; fi
}
kvm_load() {
	modprobe kvm && { [ -z "$kvmvendor" ] || modprobe "$kvmvendor"; }
}
remove_new() { bash "$(dirname "$0")/livepatch.sh" remove; }
remove_new || bad "remove before loading kvm again"
kvm_unload
apply_new || bad "apply with kvm unloaded"
kvm_load || bad "kvm did not load under the livepatch"
msgs=$(dmesg)
for obj in kvm kvm_amd; do
	has kvm || continue
	[ $obj = kvm ] || { has svm && [ "$kvmvendor" = kvm_amd ]; } || continue
	[[ "$msgs" == *"applying patch '$name' to loading module '$obj'"* ]] &&
		echo "object $obj: applied on load" || bad "$obj: no 'applying patch' message"
done
kvm_hooked "kvm loaded under the livepatch"
kvm_guest "kvm loaded under the livepatch"
# Loaded a second time, kvm is refused on kernels without 0c05e7bd2d01
# ("livepatch,x86: Clear relocation targets on a module removal", 6.3):
# the livepatch still has the relocations of the first load.  remove, load,
# apply is the way out.
kvm_unload
if kvm_load 2>/dev/null; then
	echo "kvm second load: accepted"
else
	echo "kvm second load: refused, as without 0c05e7bd2d01"
	remove_new || bad "remove after the refused load"
	kvm_load || bad "kvm did not load after remove"
	apply_new || bad "apply after the refused load"
fi
kvm_hooked "kvm after the second load"
kvm_guest "kvm after the second load"

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

# The refused second load of kvm above logs these.
REFUSED="livepatch: failed to initialize patch '$name' for module 'kvm(_amd)?' \\(-8\\)|livepatch: patch '$name' failed for module 'kvm(_amd)?', refusing"
if dmesg | grep -v "$OLDWARN" | grep -vE "$REFUSED" | grep -E 'BUG:|Oops|WARNING:|livepatch: .*(fail|error)'; then
	bad "kernel messages above"
fi

bash "$(dirname "$0")/livepatch.sh" remove || bad "livepatch.sh remove failed"
mods=$(lsmod)
[[ $'\n'"$mods" == *$'\n'"$name "* ]] && bad "module still loaded after remove"

echo "--- dmesg"
dmesg
if [ $fail = 0 ]; then echo "RESULT: PASS"; else echo "RESULT: FAIL"; fi
exit $fail
