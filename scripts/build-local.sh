#!/bin/bash
# Build the livepatch module for one kernel from this checkout, the same
# way CI does, and load-test it in a VM when the machine can run one.
#
# usage: scripts/build-local.sh [--no-loadtest] [<distribution> <kernel-version>]
#
# <distribution> is almalinux or rocky, <kernel-version> a kernel of that
# distribution in tools/kernels.tsv, e.g. rocky 4.18.0-553.144.1.el8_10;
# they default to this host's (ID in /etc/os-release, and the running
# kernel).
#
# Needs an x86_64 Linux host with Docker.  The load test also needs
# /dev/kvm, qemu-system-x86_64, qemu-img, cloud-localds and ssh; without
# them it is skipped and says so.  Output goes to out/ (build) and
# out-loadtest/ (load test).  Nothing outside the container and the VM is
# changed.
set -euo pipefail

loadtest=1
if [ "${1:-}" = --no-loadtest ]; then loadtest=; shift; fi
distro=${1:-$(. /etc/os-release; echo "$ID")}
want=${2:-$(uname -r)}
want=${want%.x86_64}

top=$(cd "$(dirname "$0")/.." && pwd)
cd "$top"
row=$(awk -F'\t' -v d="$distro" -v k="$want" '$1 == d && $3 == k' tools/kernels.tsv)
[ -n "$row" ] || { echo "$distro $want is not in tools/kernels.tsv"; exit 1; }
minor=$(cut -f2 <<<"$row")
nvr=$(cut -f3 <<<"$row")
srpm=$(cut -f4 <<<"$row")
case $distro in
almalinux) image=almalinux:${minor%%.*} ;;
rocky) image=rockylinux/rockylinux:${minor%%.*} ;;
esac

[ "$(uname -m)" = x86_64 ] || { echo "needs an x86_64 host"; exit 1; }
command -v docker >/dev/null || { echo "needs docker"; exit 1; }

rm -rf out
mkdir -p out
docker run --rm -v "$top:/w" "$image" /w/build.sh "$distro" "$minor" "$nvr" ${srpm:+"$srpm"}
ko=$(ls out/*.ko)
echo "built: $ko"
sha256sum "$ko"
echo "(whether a self-built module matches the released SHA-256 has not"
echo " been checked; apply it with SKIP_SHA256=1)"

[ -n "$loadtest" ] || exit 0
missing=
for c in qemu-system-x86_64 qemu-img cloud-localds ssh; do
	command -v "$c" >/dev/null || missing="$missing $c"
done
[ -w /dev/kvm ] || missing="$missing /dev/kvm(writable)"
if [ -n "$missing" ]; then
	echo "load test skipped, missing:$missing"
	exit 0
fi
tools/loadtest.sh "$distro" "$minor" "$nvr" "$ko" out-loadtest
