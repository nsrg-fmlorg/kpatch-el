#!/bin/bash
# Generate the port for every kernel SRPM of one minor release.
# usage: mkdiffs.sh <almalinux|rocky> <minor> <outdir> [<nvr-regex>]
#
# For each kernel: patches/<distro>/<nvr>.diff (the change) and
# patches/<distro>/kpatch/<nvr>.diff (the same in kpatch-build's form),
# named by the binaries' version.  The changed lines are checked in two
# parts, sorted: CVE-2026-98432's must equal tools/ref/98432/upstream.txt,
# and the rest, CVE-2026-99999's, one of tools/ref/99999/*.txt
# (AlmaLinux's patches for 8 and 9, upstream for 10), or be empty where
# the kernel already carries that fix.  Anything else is reported and not
# written.  result-<distro>-<minor>.txt has one line per SRPM: binary
# version, SRPM version, outcome.  <nvr-regex> limits the run to matching
# SRPMs (for a kernel added after the last full run).
set -uo pipefail

DISTRO=$1
MINOR=$2
OUT=$(realpath -m "$3")
ONLY=${4:-.}
HERE=$(cd "$(dirname "$0")" && pwd)
case $DISTRO in
almalinux)
	# Sources and debuginfo of every minor, current or retired, are in vault.
	BASE=https://vault.almalinux.org/$MINOR
	SRC=$BASE/BaseOS/Source/Packages
	DBG=$BASE/BaseOS/debug/x86_64/Packages ;;
rocky)
	BASE=https://dl.rockylinux.org/vault/rocky/$MINOR
	curl -sfo /dev/null "$BASE/BaseOS/x86_64/os/repodata/repomd.xml" ||
		BASE=https://dl.rockylinux.org/pub/rocky/$MINOR
	SRC=$BASE/BaseOS/source/tree/Packages/k
	DBG=$BASE/BaseOS/x86_64/debug/tree/Packages/k
	curl -sfo /dev/null "$SRC/" || { SRC=$BASE/BaseOS/source/tree/Packages; DBG=$BASE/BaseOS/x86_64/debug/tree/Packages; } ;;
*) echo "unknown distribution $DISTRO"; exit 2 ;;
esac
FILES='include/net/ip.h net/ipv4/ip_output.c net/xfrm/xfrm_output.c
net/bridge/netfilter/nf_conntrack_bridge.c net/netfilter/nfnetlink_queue.c
net/netfilter/xt_CHECKSUM.c net/core/dev.c net/core/skbuff.c include/linux/skbuff.h
net/ipv4/af_inet.c net/ipv4/tcp_ipv4.c include/linux/rcupdate.h'
P=$OUT/patches/$DISTRO
mkdir -p "$P/kpatch"
RES=$OUT/result-$DISTRO-$MINOR.txt
: > "$RES"

debug=$(curl -sf "$DBG/" | grep -oE 'kernel-debuginfo-[0-9][^"]*\.x86_64\.rpm' |
	sed 's/^kernel-debuginfo-//; s/\.x86_64\.rpm$//' | sort -u)

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

curl -sf "$SRC/" | grep -oE 'kernel-[0-9][^"]*\.src\.rpm' | sort -u | grep -E -- "$ONLY" |
while read -r srpm; do
	snvr=${srpm#kernel-}; snvr=${snvr%.src.rpm}
	# The binaries' version: the same, or (Rocky 9.0) with the minor
	# appended to the dist tag.
	nvr=$(printf '%s\n' "$debug" | awk -v s="$snvr" '$0 == s || index($0, s "_") == 1' | head -1)
	if [ -z "$nvr" ]; then
		echo "- $snvr NO-DEBUGINFO" >> "$RES"; continue
	fi
	rm -rf "$work"/*
	if ! curl -sfLo "$work/k.src.rpm" "$SRC/$srpm"; then
		echo "$nvr $snvr FETCH-FAILED" >> "$RES"; continue
	fi
	# The tree as %prep leaves it: the tarball plus the SRPM's own patches
	# (tools/prep.py).  Only the files those patches name are unpacked
	# besides ours; unpacking the whole tarball for each of 8.10's hundred
	# kernels would not fit in a job.
	mkdir -p "$work/s" "$work/t" "$work/a"
	bsdtar -xf "$work/k.src.rpm" -C "$work/s"
	rm -f "$work/k.src.rpm"
	tb=$(cd "$work/s" && ls linux-*.tar.xz | head -1)
	# Header paths lose their first component, as -p1 strips it: mostly a/
	# and b/, but some patches name the tree instead (RHEL-36117.patch in
	# 4.18.0-553.el8_10: "--- linux-4.18.0-552.3.1.el8_10/include/...").
	# Both names of a "diff --git" line too: a rename has no ---/+++ lines,
	# and its source must be there to move (AlmaLinux 6.12.0-211.18.1's
	# 1221-redhat-configs-enable-config-aqtion-on-all-archs.patch).
	inc=()
	for f in $FILES $(cat "$work/s"/*.patch 2>/dev/null | sed -n \
		-e 's#^\(---\|+++\) [^/[:space:]]*/\([^[:space:]]*\).*#\2#p' \
		-e 's#^diff --git [^/[:space:]]*/\([^[:space:]]*\) [^/[:space:]]*/\([^[:space:]]*\)$#\1\n\2#p' | sort -u); do
		inc+=(--include="*/$f")
	done
	bsdtar -xf "$work/s/$tb" -C "$work/t" --strip-components=1 "${inc[@]}" 2>/dev/null
	if ! python3 -I "$HERE/prep.py" "$work/s" "$work/t" > "$work/prep.log" 2>&1; then
		echo "$nvr $snvr PREP-FAILED $(tail -1 "$work/prep.log")" >> "$RES"
		continue
	fi
	cp "$work/prep.log" "$OUT/prep-$DISTRO-$nvr.log"
	for f in $FILES; do
		[ -f "$work/t/$f" ] || continue
		mkdir -p "$work/a/$(dirname "$f")"
		cp "$work/t/$f" "$work/a/$f"
	done
	rm -rf "$work/s" "$work/t"

	if grep -q 'kfree_rcu(rcu_dereference_protected(inet->inet_opt' "$work/a/net/ipv4/af_inet.c"; then
		echo "$nvr $snvr ALREADY-FIXED" >> "$RES"; continue
	fi
	fixed99999=
	grep -q 'ip_check_csum_start' "$work/a/include/net/ip.h" && fixed99999=y
	cp -R "$work/a" "$work/b"
	if ! python3 -I "$HERE/port.py" "$work/b" > "$work/port.err" 2>&1; then
		echo "$nvr $snvr PORT-FAILED $(tail -1 "$work/port.err")" >> "$RES"
		continue
	fi
	cp -R "$work/b" "$work/k"
	if ! python3 -I "$HERE/kpatchify.py" "$work/a" "$work/k" > "$work/kp.err" 2>&1; then
		echo "$nvr $snvr KPATCHIFY-FAILED $(tail -1 "$work/kp.err")" >> "$RES"
		continue
	fi
	for t in b k; do
		(cd "$work" && git diff --no-index a $t) |
			sed -e "s|^diff --git a/a/|diff --git a/|; s| b/$t/| b/|" \
			    -e "s|^--- a/a/|--- a/|; s|^+++ b/$t/|+++ b/|" |
			grep -v '^index ' > "$work/out-$t.diff"
	done
	# Compared as sorted sets: the change spans several patches upstream
	# and in AlmaLinux, so the order of lines across files differs.
	grep -E '^[+-][^+-]' "$work/out-b.diff" | LC_ALL=C sort > "$work/chg.txt"
	LC_ALL=C comm -12 "$work/chg.txt" "$HERE/ref/98432/upstream.txt" > "$work/chg98432.txt"
	LC_ALL=C comm -23 "$work/chg.txt" "$HERE/ref/98432/upstream.txt" > "$work/chg99999.txt"
	if ! cmp -s "$work/chg98432.txt" "$HERE/ref/98432/upstream.txt"; then
		echo "$nvr $snvr NO-MATCH-98432" >> "$RES"
		cp "$work/out-b.diff" "$OUT/nomatch-$DISTRO-$nvr.diff"
		continue
	fi
	if [ -n "$fixed99999" ]; then
		match=already
		[ -s "$work/chg99999.txt" ] && match=
	else
		match=
		for r in "$HERE"/ref/99999/*.txt; do
			cmp -s "$work/chg99999.txt" "$r" && { match=$(basename "$r" .txt); break; }
		done
	fi
	if [ -z "$match" ]; then
		echo "$nvr $snvr NO-MATCH-99999" >> "$RES"
		cp "$work/out-b.diff" "$OUT/nomatch-$DISTRO-$nvr.diff"
		continue
	fi
	cp "$work/out-b.diff" "$P/$nvr.diff"
	cp "$work/out-k.diff" "$P/kpatch/$nvr.diff"
	echo "$nvr $snvr OK 99999=$match" >> "$RES"
done
cat "$RES"
