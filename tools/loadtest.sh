#!/bin/bash
# Boot the shipped AlmaLinux or Rocky Linux kernel <nvr> in a throwaway VM
# and load the livepatch.
# usage: loadtest.sh <almalinux|rocky> <minor> <nvr> <module.ko> <outdir>
#
# Runs on an x86_64 Linux host with KVM, qemu-system-x86_64, qemu-img,
# cloud-localds and ssh.  Uses the GenericCloud image of the major,
# installs the kernel from the minor's repository next to the image's
# own, reboots into it, and runs loadtest-guest.sh.  Nothing outside the
# VM is touched.
set -euo pipefail

DISTRO=$1
MINOR=$2
NVR=$3
KO=$(realpath "$4")
OUT=$(realpath -m "$5")
MAJOR=${MINOR%%.*}
ARCH=x86_64
KVER=$NVR.$ARCH
HERE=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$OUT"
W=$(mktemp -d)
QPID=
cleanup() { [ -n "$QPID" ] && kill "$QPID" 2>/dev/null; rm -rf "$W"; }
trap cleanup EXIT
exec > >(tee "$OUT/loadtest.log") 2>&1

case $DISTRO in
almalinux)
	BASE=https://vault.almalinux.org/$MINOR
	curl -sfo /dev/null "$BASE/BaseOS/$ARCH/os/repodata/repomd.xml" ||
		BASE=https://repo.almalinux.org/almalinux/$MINOR
	PKGS=$BASE/BaseOS/$ARCH/os/Packages
	img=AlmaLinux-$MAJOR-GenericCloud-latest.$ARCH.qcow2
	imgurl=https://repo.almalinux.org/almalinux/$MAJOR/cloud/$ARCH/images/$img ;;
rocky)
	BASE=https://dl.rockylinux.org/vault/rocky/$MINOR
	curl -sfo /dev/null "$BASE/BaseOS/$ARCH/os/repodata/repomd.xml" ||
		BASE=https://dl.rockylinux.org/pub/rocky/$MINOR
	PKGS=$BASE/BaseOS/$ARCH/os/Packages/k
	curl -sfo /dev/null "$PKGS/" || PKGS=$BASE/BaseOS/$ARCH/os/Packages
	img=Rocky-$MAJOR-GenericCloud-Base.latest.$ARCH.qcow2
	imgurl=https://dl.rockylinux.org/pub/rocky/$MAJOR/images/$ARCH/$img ;;
*) echo "unknown distribution $DISTRO"; exit 2 ;;
esac
# --http1.1 --retry: the cloud image download died mid-way with curl
# exit 92 (HTTP/2 stream error), and -s had hidden it.
# A copy cached by the workflow (images/, one cache per major and week)
# saves the download; otherwise fetch it, and leave a copy there for the
# workflow to cache.
if [ -f "$HERE/../images/$img" ]; then
	cp "$HERE/../images/$img" "$W/base.qcow2"
else
	curl -sSfL --http1.1 --retry 5 --retry-all-errors -o "$W/base.qcow2" "$imgurl"
	if [ -d "$HERE/../images" ]; then cp "$W/base.qcow2" "$HERE/../images/$img"; fi
fi
qemu-img create -q -f qcow2 -F qcow2 -b "$W/base.qcow2" "$W/disk.qcow2" 20G

# The shipped kernel packages, straight from the minor's repository.
# kernel-modules-extra carries xt_CHECKSUM on EL10.
mkdir -p "$W/rpms"
# kernel-modules-core is split out only in later kernels (AlmaLinux 9.0
# has none), so it is taken when it exists.
for p in kernel kernel-core kernel-modules kernel-modules-core kernel-modules-extra; do
	curl -sfLo "$W/rpms/$p-$KVER.rpm" "$PKGS/$p-$KVER.rpm" ||
		[ $p = kernel-modules-core ] || [ $p = kernel-modules-extra ] ||
		{ echo "missing $p-$KVER.rpm"; exit 1; }
done
ls "$W/rpms"

# The module this kernel had from nsrg-fmlorg/kpatch-cve-2026-98432, if
# it had one: the guest loads it first, and the new module must replace
# it (kpatch-build and klp-build both build replace patches).
OLDREPO=nsrg-fmlorg/kpatch-cve-2026-98432
OLDKO=livepatch_cve_2026_98432_$(echo "$NVR" | tr '.-' '__').ko
if curl -sfL -o "$W/$OLDKO" "https://github.com/$OLDREPO/releases/download/$DISTRO-$NVR/$OLDKO"; then
	echo "earlier module: $OLDKO ($(sha256sum "$W/$OLDKO" | cut -d' ' -f1))"
else
	rm -f "$W/$OLDKO"
	echo "earlier module: none released for $NVR"
fi

ssh-keygen -q -t ed25519 -N '' -f "$W/key"
cat > "$W/user-data" <<EOF
#cloud-config
users:
  - name: t
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys: [$(cat "$W/key.pub")]
EOF
cloud-localds "$W/seed.iso" "$W/user-data"

# cache=unsafe: no flushes to the host; the VM and its disk are thrown
# away, so nothing needs to survive a host crash.
boot() {
	qemu-system-x86_64 -enable-kvm -cpu host -m 4096 -smp "$(nproc)" -display none \
		-drive file="$W/disk.qcow2",if=virtio,cache=unsafe -drive file="$W/seed.iso",if=virtio,media=cdrom \
		-nic user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:2222-:22 \
		-serial file:"$OUT/console-$1.log" -monitor unix:"$W/monitor",server,nowait &
	QPID=$!
	local i
	for i in $(seq 90); do
		vm true 2>/dev/null && return 0
		sleep 5
	done
	echo "VM did not come up"
	# GRUB writes only to the screen, so a boot that stops in GRUB, or in
	# the kernel before the serial console starts, leaves console-N.log
	# empty (Rocky 8.4-8.9, even with console=ttyS0).  Keep the screen.
	python3 -I - "$W/monitor" "$OUT/screen-$1.ppm" <<'PY' || true
import socket, sys, time
s = socket.socket(socket.AF_UNIX)
s.connect(sys.argv[1])
s.sendall(('screendump %s\n' % sys.argv[2]).encode())
time.sleep(2)
PY
	return 1
}
SSH=(ssh -i "$W/key" -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o LogLevel=ERROR t@127.0.0.1)
vm() { "${SSH[@]}" "$@"; }
put() { scp -i "$W/key" -P 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "$@" t@127.0.0.1:; }

boot 1
put "$W"/rpms/*.rpm "$KO" "$HERE/loadtest-guest.sh" "$HERE/csum-probe.sh" "$HERE/csum-inject.py" "$HERE/tcpopt.py" "$HERE/syncookie.py" "$HERE/kvmrun.py" "$HERE/../scripts/livepatch.sh" "$HERE/loadtest-bootinfo.sh" "$HERE/loadtest-bootprep.sh"
[ -f "$W/$OLDKO" ] && put "$W/$OLDKO"
vm "sudo rpm -ivh --oldpackage --nodeps --force ~/kernel*.rpm && sudo grubby --set-default /boot/vmlinuz-$KVER"
# The image's own command line has console=ttyS0; the installed kernel's
# entry may not, and then a failed boot leaves console-2.log empty
# (Rocky 8: "VM did not come up" with nothing to show why).
vm "sudo grubby --update-kernel=/boot/vmlinuz-$KVER --args='console=tty0 console=ttyS0,115200 earlyprintk=ttyS0,115200'"
# Remove every other kernel, so that only the one under test can boot.
# On the Rocky 8 image grubby's default did not hold, and the VM came up
# on the image's own, newer kernel (4.18.0-553.el8_10 instead of
# 4.18.0-372.9.1.el8).
vm "rpm -q kernel-core --qf '%{VERSION}-%{RELEASE}.%{ARCH}\\n' | grep -vx '$KVER' | sed 's/^/kernel-core-/' | xargs -r sudo rpm -e --nodeps; rpm -q kernel-core"
# What GRUB will read on the next boot.  Rocky 8.6 stopped in the GRUB
# menu with no countdown, the removed 553.el8_10 entry still listed and
# highlighted although grubby named 372.9.1 the default.
# Entries whose kernel is gone (tools/loadtest-bootprep.sh).
vm "sudo sh ~/loadtest-bootprep.sh"
vm "sudo sh ~/loadtest-bootinfo.sh" || true
vm 'sudo systemctl poweroff' || true
wait "$QPID" || true
QPID=

boot 2
running=$(vm uname -r)
echo "running kernel: $running"
[ "$running" = "$KVER" ] || { echo "RESULT: FAIL (booted $running, wanted $KVER)"; exit 1; }
rc=0
# Whether the module carries CVE-2026-99999's part, from the port it was
# built from.  The guest cannot tell by probing: on 10 the crafted frame
# is refused before it reaches ip_do_fragment() (csum-probe.sh:
# bad=rejected), and the guest then skipped that part's checks on a
# kernel that needed it (Rocky 6.12.0-211.66.1.el10_2 in the pilot).
need99999=
grep -q ip_check_csum_start "$HERE/../patches/$DISTRO/$NVR.diff" && need99999=1
# Expanded by the guest's shell: the file was put in the guest user's home.
old=
[ -f "$W/$OLDKO" ] && old='$HOME/'$OLDKO
vm "sudo FROM_RELEASE=${FROM_RELEASE:-} SCRIPT_REF=${SCRIPT_REF:-} OLDREPO=$OLDREPO OLDREF=${OLDREF:-} OLDKO=$old NEED99999=$need99999 bash ~/loadtest-guest.sh ~/$(basename "$KO")" || rc=$?
vm 'sudo systemctl poweroff' || true
exit $rc
