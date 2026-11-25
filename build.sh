#!/bin/bash
# Build the livepatch module for one AlmaLinux or Rocky Linux kernel inside
# that distribution's container (almalinux:<major> or
# rockylinux/rockylinux:<major>).
# usage: build.sh <almalinux|rocky> <minor> <kernel-nvr> [<srpm-nvr>]
#
# <srpm-nvr> is for the rare kernel whose SRPM is named differently from
# its binaries (Rocky 9.0: kernel-5.14.0-70.30.1.el9.src.rpm builds
# kernel-core-5.14.0-70.30.1.el9_0).
#
# 8 and 9 use kpatch-build.  10 uses the kernel's own klp-build: its
# kernels enable CONFIG_X86_KERNEL_IBT, which kpatch-build refuses.
#
# The container is moved to the userland of <minor> and gcc
# is pinned to the one the kernel was built with.
set -euo pipefail

DISTRO=$1
MINOR=$2
NVR=$3
ARCH=x86_64
KVER=$NVR.$ARCH
MAJOR=${MINOR%%.*}
SRPM_NVR=${4:-$NVR}
case $DISTRO in
almalinux)
	VAULTROOT=https://vault.almalinux.org
	BASE=$VAULTROOT/$MINOR
	# The current minor's binary trees are on repo.almalinux.org, not yet
	# in vault; its sources and debuginfo are in vault either way.
	OS=$BASE
	curl -sf --retry 5 -o /dev/null "$BASE/BaseOS/$ARCH/os/repodata/repomd.xml" ||
		OS=https://repo.almalinux.org/almalinux/$MINOR
	url_src()   { echo "$BASE/BaseOS/Source/Packages/kernel-$SRPM_NVR.src.rpm"; }
	url_debug() { echo "$BASE/BaseOS/debug/$ARCH/Packages/$1"; }
	url_devel() { echo "$OS/AppStream/$ARCH/os/Packages/$1"; }
	url_bin()   { echo "$OS/BaseOS/$ARCH/os/Packages/$1"; }
	DEBUGREPO=$BASE/BaseOS/debug/$ARCH/
	# The kpatch release the AlmaLinux modules of CVE-2026-99999 were built
	# and tested with.
	KPATCH_REF=v0.9.11
	# The 10.2 GA kernel, whose klp-build is lent to 10.0 and 10.1.
	KLP_DONOR=6.12.0-211.7.1.el10_2
	KLP_DONOR_URL=$VAULTROOT/10.2/BaseOS/Source/Packages/kernel-$KLP_DONOR.src.rpm ;;
rocky)
	VAULTROOT=https://dl.rockylinux.org/vault/rocky
	# vault holds every retired minor; the current one is only under pub.
	BASE=$VAULTROOT/$MINOR
	curl -sf --retry 5 -o /dev/null "$BASE/BaseOS/$ARCH/os/repodata/repomd.xml" ||
		BASE=https://dl.rockylinux.org/pub/rocky/$MINOR
	OS=$BASE
	# Packages sit in per-letter subdirectories, except on 8.4.
	pkgdir() { # <repo-path> <package-name>
		if curl -sf --retry 5 -o /dev/null "$BASE/$1/Packages/${2:0:1}/"; then
			echo "$BASE/$1/Packages/${2:0:1}"
		else
			echo "$BASE/$1/Packages"
		fi
	}
	url_src()   { echo "$(pkgdir BaseOS/source/tree kernel)/kernel-$SRPM_NVR.src.rpm"; }
	url_debug() { echo "$(pkgdir BaseOS/$ARCH/debug/tree kernel)/$1"; }
	url_devel() { echo "$(pkgdir AppStream/$ARCH/os kernel)/$1"; }
	url_bin()   { echo "$(pkgdir BaseOS/$ARCH/os kernel)/$1"; }
	DEBUGREPO=$BASE/BaseOS/$ARCH/debug/tree/
	# Rocky support (6b1af5079c) came after v0.9.11, whose kpatch-build
	# stops with "Unsupported distribution".  Pinned to master of
	# 2026-09-15.
	KPATCH_REF=74ac9ffe96df2704eb6f141bc7e680a7f449503e
	# The 10.2 GA kernel, whose klp-build is lent to 10.0 and 10.1.
	KLP_DONOR=6.12.0-211.16.1.el10_2.0.1
	KLP_DONOR_URL=https://dl.rockylinux.org/pub/rocky/10.2/BaseOS/source/tree/Packages/k/kernel-$KLP_DONOR.src.rpm ;;
*) echo "unknown distribution $DISTRO"; exit 2 ;;
esac
OUT=/w/out
mkdir -p "$OUT"
exec > >(tee "$OUT/build-script.log") 2>&1

if [ "$MAJOR" = 8 ]; then crb=PowerTools; else crb=CRB; fi
# The official mirror first, then public mirrors that carry the same tree
# (each checked to serve these files, 2026-10-20).  The official ones
# returned transient 504s, and a build is an hour long.
mirrors() { # <official url>
	local r
	case "$1" in
	https://vault.almalinux.org/*)
		r=${1#https://vault.almalinux.org/}
		echo "$1 https://mirror.nju.edu.cn/almalinux-vault/$r" ;;
	https://repo.almalinux.org/almalinux/*)
		r=${1#https://repo.almalinux.org/almalinux/}
		echo "$1 https://mirror.nju.edu.cn/almalinux/$r https://mirror.netzwerge.de/almalinux/$r" ;;
	https://dl.rockylinux.org/vault/rocky/*)
		r=${1#https://dl.rockylinux.org/vault/rocky/}
		echo "$1 https://mirror.nju.edu.cn/rocky-vault/$r https://mirror.netzwerge.de/rocky-vault/$r" ;;
	https://dl.rockylinux.org/pub/rocky/*)
		r=${1#https://dl.rockylinux.org/pub/rocky/}
		echo "$1 https://mirror.nju.edu.cn/rocky/$r https://mirrors.ustc.edu.cn/rocky/$r" ;;
	*) echo "$1" ;;
	esac
}
# The distribution's package signing keys, from the image.  The mirrors
# above are other people's, and until now nothing taken from them was
# authenticated: the repositories had gpgcheck=0, and fetch only checked
# the digest a package carries about itself (rpm -K --nosignature), which
# any well-formed package passes.  The kernel source, its debuginfo and
# gcc all came that way.
for k in /etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux /etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux-$MAJOR \
	/etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-$MAJOR; do
	if [ -f "$k" ]; then rpm --import "$k"; fi
done
rpm -q gpg-pubkey >/dev/null || { echo "no package signing key in the image"; exit 1; }

# fetch <out> <official url>: the first mirror that delivers wins; an RPM
# must carry a good signature by one of the keys above or is refused.
# rpm -K exits 0 for an unsigned package too, and says only "digests OK".
fetch() {
	local out=$1 u r
	for u in $(mirrors "$2"); do
		curl -sSfL --retry 3 -o "$out" "$u" || continue
		case "$out" in
		*.rpm)
			r=$(rpm -K "$out" 2>&1) || true
			[[ $r == *"digests signatures OK" ]] || { echo "bad signature from $u: $r"; continue; } ;;
		esac
		return 0
	done
	echo "could not fetch $2 from any mirror"
	return 1
}

# Keep the minor's repositories in a directory of their own.  On
# AlmaLinux, distro-sync downgraded the release package, which put the
# stock repo files back in /etc/yum.repos.d, and the next install pulled
# current packages (gcc 8.5.0-29.el8_10 into the 8.9 build).
R=/etc/vault.repos.d
mkdir -p $R
dnf() { command dnf --setopt=reposdir=$R "$@"; }
for r in BaseOS AppStream $crb; do
	cat >> $R/vault.repo <<EOF
[vault-$r]
name=vault $MINOR $r
baseurl=$(mirrors "$OS/$r/$ARCH/os/")
gpgcheck=1
EOF
done
# The build-only packages: xxhash-devel, which objtool needs for
# klp-build, and kernel build dependencies such as opencsd-devel, which
# no other repository carries.  Skipped where a minor has none.
cat >> $R/vault.repo <<EOF
[vault-devel]
name=vault $MINOR devel
baseurl=$(mirrors "$OS/devel/$ARCH/os/")
gpgcheck=1
enabled=0
skip_if_unavailable=True
EOF
cat >> $R/vault.repo <<EOF
[vault-debug]
name=vault $MINOR debuginfo
baseurl=$DEBUGREPO
gpgcheck=1
enabled=0
EOF

# Rocky 9.4's openssl-libs carries fips.so itself, and the image's newer,
# separate openssl-fips-provider then collides with it: "file
# /usr/lib64/ossl-modules/fips.so conflicts between attempted installs".
# Only when that happens, drop the provider and sync without it.
if ! dnf -y --setopt=install_weak_deps=False distro-sync --allowerasing; then
	rpm -e --nodeps openssl-fips-provider
	dnf -y --setopt=install_weak_deps=False distro-sync --allowerasing --exclude='openssl-fips-provider*'
fi
dnf -y --setopt=install_weak_deps=False install \
	gcc gcc-c++ make git rpm-build dnf-plugins-core elfutils-libelf-devel \
	bison flex bc openssl-devel perl python3 which findutils diffutils \
	patch xz cpio kmod ncurses-devel dwarves util-linux gawk binutils

# Saved under the binaries' name: kpatch-build takes the kernel version
# from the SRPM's file name.
fetch "/w/kernel-$NVR.src.rpm" "$(url_src)"
# opencsd-devel is only in the devel repository.  Without it, the
# whole builddep transaction failed on Rocky 8.10, installed nothing,
# not even pathfix.py, and rpmbuild -bp stopped in %prep.  strict=False
# installs the rest where a minor lacks a package even there (Rocky 8.4,
# AlmaLinux 8.3 have no opencsd-devel at all).
dnf -y builddep "/w/kernel-$NVR.src.rpm" --allowerasing --enablerepo=vault-devel --setopt=strict=False |
	tee /w/builddep.log || true
grep -E '^No matching package|^No match for' /w/builddep.log > "$OUT/builddep-missing.txt" || true

# r1: the set of fixes in patches/.  A host replaces one module with the
# next, and a loaded module's name cannot be loaded again, so the
# revision goes up whenever a fix is added.
NAME=livepatch_el_r1_${NVR//[.-]/_}
# pin_gcc <version-release as the kernel records it, e.g. 11.5.0-11>
#
# A minor's repositories can carry gcc updates released after its GA
# kernel was built, and dnf would pick the newest; install the exact one.
# The version string the kernel records stops at the dist tag
# (11.5.0-11 for gcc-11.5.0-11.el9 and the like), so the rest is globbed.
#
# If the minor's repositories lack that build, take it from another minor
# of the same major; compiler.txt records which.  kpatch-build's compiler
# check decides whether what was installed will do, and is never skipped:
# AlmaLinux 9.0's GA kernel records 11.3.1-2, a build that was never
# published, and 9.1's 11.3.1-2.1.el9.alma reports the same version and
# passes.
#
# This used to take the newest build of the same upstream version from a
# later minor and pass --skip-compiler-check.  Two released modules were
# built that way: AlmaLinux 5.14.0-70.13.1.el9_0, with the package named
# above, and Rocky 4.18.0-372.16.1.el8_6, with 8.6's 8.5.0-10.1 although
# 8.5 has the kernel's 8.5.0-4.  Rebuilt with the check on, the
# executable sections of both came out byte for byte the same.
pin_gcc() {
	local vr=$1 ver=${1%%-*} p pkgs= m
	for p in gcc gcc-c++ cpp libgcc libgomp libstdc++ libstdc++-devel; do
		rpm -q "$p" >/dev/null 2>&1 && pkgs="$pkgs $p-$vr.*"
	done
	if dnf -y install --allowerasing $pkgs || dnf -y downgrade --allowerasing $pkgs; then
		return 0
	fi
	echo "gcc $vr is in no repository of $MINOR; looking for gcc $ver elsewhere"
	for m in $(curl -sf $VAULTROOT/ | grep -oE "href=\"$MAJOR\.[0-9]+/" | grep -oE '[0-9]+\.[0-9]+' | sort -V); do
		# Not "curl | grep -q": grep exits at the first match, curl dies
		# of SIGPIPE, and with pipefail the minor that has the package
		# is the one skipped.  That is how 9.0 missed 9.1's gcc.
		local listing
		listing=$(curl -sf --retry 5 "$VAULTROOT/$m/AppStream/$ARCH/os/Packages/g/") ||
			listing=$(curl -sf --retry 5 "$VAULTROOT/$m/AppStream/$ARCH/os/Packages/") || continue
		[[ "$listing" == *"\"gcc-$ver-"* ]] || continue
		cat > $R/gcc-$m.repo <<EOF
[gcc-$m-AppStream]
name=vault $m AppStream (gcc)
baseurl=$(mirrors "$VAULTROOT/$m/AppStream/$ARCH/os/")
gpgcheck=1
[gcc-$m-BaseOS]
name=vault $m BaseOS (gcc)
baseurl=$(mirrors "$VAULTROOT/$m/BaseOS/$ARCH/os/")
gpgcheck=1
EOF
		if dnf -y install --allowerasing $pkgs || dnf -y downgrade --allowerasing $pkgs; then
			echo "gcc $vr taken from $m: $(rpm -q gcc)" | tee -a "$OUT/compiler.txt"
			return 0
		fi
		rm -f $R/gcc-$m.repo
	done
	echo "gcc $vr is in no $MAJOR.x minor"
	return 1
}

# ccache, when the workflow provides a cache directory (.ccache in the
# checkout).  Rebuilding the same kernel then reuses its objects; a first
# build of a kernel gains nothing.  ccache sits in front of gcc on PATH,
# which both kpatch-build and klp-build use; compiler_check=content keeps
# objects from another gcc build from being reused.  A static binary from
# ccache's own release, pinned by SHA-256: EL8-10 do not package ccache.
CCACHE_VER=4.14.1
CCACHE_SHA256=fa1443c9fbea879c9bff6619d1284eda3102992e91831b9f6e546879972195cc
setup_ccache() {
	[ -d /w/.ccache ] || return 0
	local t=/tmp/ccache.tar.xz d=/opt/ccache-$CCACHE_VER c
	curl -sSfL --retry 3 -o $t \
		"https://github.com/ccache/ccache/releases/download/v$CCACHE_VER/ccache-$CCACHE_VER-linux-x86_64-musl-static.tar.xz"
	[ "$(sha256sum $t | cut -d' ' -f1)" = "$CCACHE_SHA256" ] || { echo "ccache tarball checksum mismatch"; return 1; }
	mkdir -p $d /opt/ccache-bin
	tar -xJf $t -C $d --strip-components=1
	for c in gcc cc g++ c++; do ln -sf $d/ccache /opt/ccache-bin/$c; done
	export PATH=/opt/ccache-bin:$PATH CCACHE_DIR=/w/.ccache CCACHE_MAXSIZE=4G \
		CCACHE_COMPILERCHECK=content
	ccache=$d/ccache
	$ccache -z >/dev/null
	echo "ccache $CCACHE_VER in front of $(command -v gcc)"
}
ccache_stats() {
	[ -n "${ccache:-}" ] && $ccache -s > "$OUT/ccache.txt" 2>&1 || true
}

build_kpatch() {
	# kpatch-build reads vmlinux from /usr/lib/debug/lib/modules/$KVER/vmlinux.
	local p
	# vmlinux, all kpatch-build reads, is in kernel-debuginfo.  The common
	# package (shared sources) is missing for some kernels (Rocky 9.0 and
	# 9.1), and is installed only when present.
	fetch "/w/kernel-debuginfo-$NVR.$ARCH.rpm" "$(url_debug "kernel-debuginfo-$NVR.$ARCH.rpm")"
	local rpms=("/w/kernel-debuginfo-$NVR.$ARCH.rpm")
	if fetch "/w/kernel-debuginfo-common-$ARCH-$NVR.$ARCH.rpm" \
		"$(url_debug "kernel-debuginfo-common-$ARCH-$NVR.$ARCH.rpm")"; then
		rpms+=("/w/kernel-debuginfo-common-$ARCH-$NVR.$ARCH.rpm")
	else
		echo "note: no kernel-debuginfo-common for $NVR" | tee -a "$OUT/compiler.txt"
	fi
	rpm -ivh --nodeps "${rpms[@]}"
	rm -f /w/kernel-debuginfo*.rpm
	VMLINUX=/usr/lib/debug/lib/modules/$KVER/vmlinux

	local gccvr
	gccvr=$(readelf -p .comment "$VMLINUX" | sed -n 's/.*GCC: .*(Red Hat \([0-9][^)]*\)).*/\1/p' | head -1)
	[ -n "$gccvr" ] || { echo "cannot read gcc version from vmlinux"; return 1; }
	pin_gcc "$gccvr"
	{
		echo "kernel:  $(readelf -p .comment "$VMLINUX" | grep -m1 GCC)"
		echo "gcc:     $(gcc --version | head -1)"
	} | tee -a "$OUT/compiler.txt"

	setup_ccache
	git init -q /w/kpatch
	git -C /w/kpatch fetch -q --depth 1 https://github.com/dynup/kpatch.git "$KPATCH_REF"
	git -C /w/kpatch checkout -q FETCH_HEAD
	make -C /w/kpatch -j"$(nproc)" >/dev/null
	make -C /w/kpatch install >/dev/null

	# patches/<distro>/kpatch/ holds the same change with
	# ip_check_csum_start() moved out of include/net/ip.h; see
	# tools/kpatchify.py.
	cp "/w/patches/$DISTRO/kpatch/$NVR.diff" "$OUT/fixes.diff"
	local rc=0
	# kpatch-build takes the kernel version from the SRPM's file name and
	# refuses -a alongside -r.
	kpatch-build -j"$(nproc)" -r "/w/kernel-$NVR.src.rpm" -v "$VMLINUX" \
		-n "$NAME" -o "$OUT" "$OUT/fixes.diff" || rc=$?
	cp ~/.kpatch/build.log "$OUT/build.log" 2>/dev/null || true
	# Functions kpatch-build picked up, including ones pulled in because
	# an inlined caller changed.
	# kpatch-build prints them on stdout; build.log is only kept on failure.
	grep -E 'changed function|new function' "$OUT/build-script.log" \
		| sort -u > "$OUT/functions.txt" || true
	return $rc
}

build_klp() {
	# The config the kernel was actually built with, from kernel-devel.
	# The .config files in the SRPM lack CONFIG_KLP_BUILD; the built one
	# has it.
	fetch /w/kernel-devel.rpm "$(url_devel "kernel-devel-$KVER.rpm")"
	rpm2cpio /w/kernel-devel.rpm | (cd / && cpio -idm "./usr/src/kernels/$KVER/.config" \
		"./usr/src/kernels/$KVER/Module.symvers")
	local config=/usr/src/kernels/$KVER/.config
	local overlay=
	grep -q '^CONFIG_KLP_BUILD=y' "$config" || overlay=y

	local gccvr
	gccvr=$(sed -n 's/^CONFIG_CC_VERSION_TEXT=".*(Red Hat \([0-9][^)]*\))"$/\1/p' "$config")
	[ -n "$gccvr" ] || { echo "cannot read gcc version from .config"; return 1; }
	pin_gcc "$gccvr"
	{
		echo "kernel:  $(grep '^CONFIG_CC_VERSION_TEXT=' "$config")"
		echo "gcc:     $(gcc --version | head -1)"
	} | tee -a "$OUT/compiler.txt"
	# recountdiff (patchutils): klp-build uses it from 10.3 on.
	dnf -y --enablerepo=vault-devel install xxhash-devel patchutils
	# For the objtool switch's crash backtraces (10.0).
	dnf -y install gdb || true

	setup_ccache
	rpm -i --nodeps "/w/kernel-$NVR.src.rpm"
	rpmbuild -bp --nodeps --target=$ARCH ~/rpmbuild/SPECS/kernel.spec >/dev/null
	local src
	src=$(ls -d ~/rpmbuild/BUILD/kernel-*/linux-*/ | head -1)
	cd "$src"
	cp "$config" .config
	if [ -n "$overlay" ]; then
		# 10.0 and 10.1 have no klp-build; take the tooling from 10.2.
		local donor=$KLP_DONOR
		fetch /w/donor.src.rpm "$KLP_DONOR_URL"
		mkdir -p /w/donor
		# The tarball inside need not carry the SRPM's exact version.
		rpm2cpio /w/donor.src.rpm | (cd /w/donor && cpio -id 'linux-*.tar.xz')
		tar -xJf /w/donor/linux-*.tar.xz -C /w/donor --strip-components=1
		rm -f /w/donor.src.rpm /w/donor/linux-*.tar.xz
		# 10.2's objtool misreads 10.0's objects; see
		# tools/klp-overlay/objtool-split.
		local split=
		[ "$MINOR" = 10.0 ] && split=--split-objtool
		/w/tools/klp-overlay.sh "$src" /w/donor $split | tee -a "$OUT/compiler.txt"
	fi
	# Make the tree report the running kernel's release, so the module's
	# vermagic matches it.
	sed -i "s/^EXTRAVERSION *=.*/EXTRAVERSION = -${NVR#*-}.$ARCH/" Makefile
	make -s olddefconfig
	grep -q '^CONFIG_KLP_BUILD=y' .config || { echo "CONFIG_KLP_BUILD not set"; return 1; }
	local rel
	rel=$(make -s kernelrelease)
	[ "$rel" = "$KVER" ] || { echo "kernelrelease $rel != $KVER"; return 1; }

	cp "/w/patches/$DISTRO/$NVR.diff" "$OUT/fixes.diff"
	local rc=0
	./scripts/livepatch/klp-build -T -j"$(nproc)" -o "$OUT/$NAME.ko" \
		"$OUT/fixes.diff" > "$OUT/build.log" 2>&1 || rc=$?
	cp klp-tmp/diff/diff.log "$OUT/diff.log" 2>/dev/null || true
	cp .objtool-split/crash-*.txt "$OUT/" 2>/dev/null || true
	if [ -d .objtool-split ]; then
		if [ -e .objtool-split/checksum-failures ]; then
			echo "objects without checksums (not diffable): $(sort -u .objtool-split/checksum-failures | wc -l)"
			sort -u .objtool-split/checksum-failures > "$OUT/checksum-failures.txt"
		fi
		# The switch must still be in place and must have been used.
		[[ "$(head -1 .objtool-split/objtool)" == '#!/bin/bash' ]] ||
			{ echo ".objtool-split/objtool was replaced during the build"; rc=1; }
	fi
	cp "$OUT/diff.log" "$OUT/functions.txt" 2>/dev/null || true
	if [ $rc = 0 ]; then
		local vm
		vm=$(modinfo -F vermagic "$OUT/$NAME.ko")
		echo "vermagic: $vm" | tee -a "$OUT/compiler.txt"
		case "$vm" in "$KVER "*) ;; *) echo "vermagic does not match $KVER"; rc=1;; esac
	fi
	if [ $rc = 0 ]; then
		# Every symbol the module refers to must exist in the shipped
		# kernel; klp-build only saw its own rebuild of it.
		local p
		mkdir -p /w/shipped
		for p in kernel-core kernel-modules-core kernel-modules; do
			fetch "/w/$p.rpm" "$(url_bin "$p-$KVER.rpm")"
			rpm2cpio "/w/$p.rpm" | (cd /w/shipped && cpio -idm)
			rm -f "/w/$p.rpm"
		done
		python3 -I /w/tools/klpsymcheck.py "$OUT/$NAME.ko" \
			"/w/shipped/lib/modules/$KVER/System.map" \
			"/usr/src/kernels/$KVER/Module.symvers" \
			"/w/shipped/lib/modules/$KVER/kernel" | tee "$OUT/symcheck.txt" || rc=1
	fi
	return $rc
}

# Not "build_x || rc=$?": that turns off set -e inside the function.
trap ccache_stats EXIT
if [ "$MAJOR" -ge 10 ]; then
	build_klp
else
	build_kpatch
fi
