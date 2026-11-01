# kpatch livepatch for CVE-2026-98432 on AlmaLinux and Rocky Linux

[日本語](README.ja.md)

Livepatch modules that fix CVE-2026-98432 on a running AlmaLinux or Rocky
Linux 8, 9 or 10 host (x86_64) without a reboot. On kernels that lack the
fix for CVE-2026-99999 as well, the same module fixes that too, so a host
needs one module whichever of the two its kernel lacks.

**Status (2026-11-02): every module is built and load-tested; none is
released yet, so there is nothing to apply.** The release, and a test of
the one-line command on each released module, come next; until then
`scripts/livepatch.sh` has no modules in its table and refuses every
kernel.

## Kernels

684 kernels: 380 of AlmaLinux and 304 of Rocky Linux, 8.3 to 10.2,
listed in `tools/kernels.tsv`. That is every kernel whose SRPM and
debuginfo are on the distribution's mirrors (vault included), x86_64
only, except Rocky's 5.14.0-611.41.1.el9_7, whose debuginfo is on no
mirror. It includes Rocky's one 8.3 kernel, 4.18.0-240.22.1.el8, which
the earlier Rocky repository did not cover, and the kernels both
distributions released after the earlier repositories, through
4.18.0-553.180.1.el8_10 (AlmaLinux), 5.14.0-687.61.1.el9_8 and
6.12.0-211.69.1.el10_2. AlmaLinux 10's x86_64_v2 variant is not covered.

666 of the 684 lack the fix for CVE-2026-99999 too, and their module
carries both. The other 18 already have it (from AlmaLinux
4.18.0-553.177.1.el8_10 and Rocky 553.178.1.el8_10, and from
5.14.0-687.59.1.el9_8 and 6.12.0-211.67.1.el10_2 on both), and their
module carries CVE-2026-98432's change alone.

## What was tested

Each module was built in CI and applied with `scripts/livepatch.sh` to
its shipped kernel in a VM (`tools/loadtest.sh`), 2026-10-31, one run
per distribution and minor, 40 runs; all 684 printed `RESULT: PASS`.
In each:

- `inet_sock_destruct` and `tcp_v4_reqsk_destructor` are listed as
  patched functions of vmlinux.
- 2,000 TCP connections over loopback from a socket with IP options set,
  and 2,000 bare SYNs carrying IP options from a raw socket, ran with no
  error and no kernel warning (`tools/tcpopt.py`). This drives both frees
  the fix changes with the options present; without IP options they free
  only NULL.
- Where the module carries CVE-2026-99999's part, it takes effect on
  vmlinux, `nfnetlink_queue` and `xt_CHECKSUM` (and on 9 and 10
  `nf_conntrack_bridge`). On 8 and 9 (511 kernels, and Rocky's 8.3) a
  crafted frame was fragmented by the shipped kernel and dropped with the
  module applied. On 10 (154 kernels) the frame is refused before it
  reaches the flaw, so that probe says nothing either way there.
- 665 kernels had a module from the earlier repositories. It was loaded
  first, and the new module replaced it: the earlier patch was disabled
  and its module unloaded.
- The module was then disabled and removed.

Not tested: the race itself. Showing CVE-2026-98432 on the shipped
kernel and its absence with the module needs KASAN and a contrived
interleaving of a retransmitted SYN with the child's release; it does
not happen on demand in these VMs. Nor was any module tested with Secure
Boot on (it is unsigned and would be refused), or loaded at boot by
`kpatch.service`.

## How the ports are made

`tools/mkdiffs.sh` ports every kernel SRPM of a minor. It first applies
the SRPM's own patches to its tarball, as `%prep` does
(`tools/prep.py`): AlmaLinux carries its own fixes that way, among them
CVE-2026-99999's in 4.18.0-553.177.1.el8_10, and 10.2's 6.12.0-211.69.1
is Red Hat's 211.56.1 tarball plus 466 patches, so a port made
against the bare tarball would miss what the kernel has. The changed
lines are then checked against `tools/ref/`: CVE-2026-98432's must equal
upstream's, CVE-2026-99999's AlmaLinux's patch for 8 or 9 or upstream's
for 10, or be absent where the kernel has that fix. Every one of the 684
matched. `tools/port.py` also stops if the tree's `kfree_rcu()` would not
skip a NULL pointer, as both pointers usually are.

8 and 9 are built with kpatch-build, 10 with the kernel's own
klp-build; both build replace patches, which is how a module takes over
from an earlier one.

## CVE-2026-98432

The upstream fix is torvalds/linux e3f33b0a1d89, "ipv4: free inet_opt and
ireq_opt after an RCU grace period". When a SYN carries IP options, the
listener keeps them on the request socket (`ireq_opt`) and hands them to
the child socket (`inet_opt`) without copying. A retransmitted SYN for the
same request can be answered with a SYN-ACK on another CPU, reading those
options under RCU, while the child is closed and `inet_sock_destruct()`
frees them with a plain `kfree()`: a use after free. Request socket
migration has the same problem in `tcp_v4_reqsk_destructor()`. The fix
frees both with `kfree_rcu()`.

Neither distribution has shipped the fix: on 2026-10-27 the newest
kernels of AlmaLinux and Rocky Linux 8, 9 and 10 did not name the CVE in
their changelogs, and the sources of 4.18.0-305.3.1.el8_4,
4.18.0-553.179.1.el8_10, 5.14.0-687.61.1.el9_8 and 6.12.0-211.68.1.el10_2
still free both pointers with `kfree()`.

## CVE-2026-99999

Fixed earlier, separately for each distribution, by
[nsrg-fmlorg/kpatch-alma-cve-2026-99999](https://github.com/nsrg-fmlorg/kpatch-alma-cve-2026-99999)
and
[nsrg-fmlorg/kpatch-rocky-cve-2026-99999](https://github.com/nsrg-fmlorg/kpatch-rocky-cve-2026-99999).
Both distributions now ship kernels with that fix, from
4.18.0-553.177.1.el8_10 (AlmaLinux) or 553.178.1.el8_10 (Rocky),
5.14.0-687.59.1.el9_8 and 6.12.0-211.67.1.el10_2 on. Where a kernel lacks
it, this repository's module carries the same change as the earlier
ones, and replaces an earlier module already loaded (tested on each of
the 665 kernels that had one, above).

## Layout

| Path | What it is |
|---|---|
| `build.sh` | Builds the module for one kernel inside the distribution's container |
| `tools/kernels.tsv` | The kernels CI builds: distribution, minor, kernel version |
| `tools/select-kernels.py` | Which of them a CI run takes |
| `tools/mkdiffs.sh` | Makes the port for every kernel of a minor and checks it against `tools/ref/` |
| `tools/prep.py` | Applies an SRPM's own patches to its tarball, as `%prep` does, before porting |
| `tools/port.py` | The change itself, applied to a kernel tree |
| `tools/kpatchify.py` | Turns a port into the form fed to kpatch-build |
| `tools/klp-overlay.sh`, `tools/klp-overlay-lds.py`, `tools/klp-overlay/` | Lends 10.2's klp-build to 10.0 and 10.1 |
| `tools/klpsymcheck.py` | Checks a klp-build module's symbols against the shipped kernel |
| `tools/loadtest.sh`, `tools/loadtest-guest.sh`, `tools/loadtest-bootprep.sh`, `tools/loadtest-bootinfo.sh` | Boots the shipped kernel in a VM and applies, checks and removes the module |
| `tools/csum-probe.sh`, `tools/csum-inject.py` | Probes CVE-2026-99999 before and after |
| `tools/tcpopt.py` | Drives the two frees CVE-2026-98432 changes, with IP options present |
| `tools/doccheck.py` | Fails when a file is not named in both READMEs, or a link is broken |
| `scripts/livepatch.sh` | Applies, checks and removes a released module on a host |
| `scripts/build-local.sh` | Builds and load-tests one kernel's module on your own machine |
| `.github/workflows/diffs.yml` | Runs `tools/mkdiffs.sh` for every minor of both distributions |
| `.github/workflows/build.yml` | Builds and load-tests modules |
| `.github/workflows/docs.yml` | Runs `tools/doccheck.py` |
