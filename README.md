# kpatch livepatch for CVE-2026-98432 on AlmaLinux and Rocky Linux

[日本語](README.ja.md)

Livepatch modules that fix CVE-2026-98432 on a running AlmaLinux or Rocky
Linux 8, 9 or 10 host (x86_64) without a reboot. On kernels that lack the
fix for CVE-2026-99999 as well, the same module fixes that too, so a host
needs one module whichever of the two its kernel lacks.

```sh
curl -fsSL https://raw.githubusercontent.com/nsrg-fmlorg/kpatch-cve-2026-98432/main/scripts/livepatch.sh | sudo bash -s -- apply
```

The script picks the module for the running kernel (`uname -r`) and for
the distribution that built it (the vendor its `kernel-core` package
records, so a host converted from one distribution to the other is served
by the kernel it still runs). A kernel with no released module is refused
and nothing changes. `check` instead
of `apply` only checks; `status` and `remove` show and undo it. A
livepatch does not survive a reboot. The fix for CVE-2026-98432 is in the
distributions' changelogs from 4.18.0-553.182.1.el8_10,
5.14.0-687.64.1.el9_8 and 6.12.0-211.72.1.el10_2 on (checked 2026-11-06).

## Kernels

686 kernels: 381 of AlmaLinux and 305 of Rocky Linux, 8.3 to 10.2,
listed in `tools/kernels.tsv`. That is every kernel whose SRPM and
debuginfo are on the distribution's mirrors (vault included), x86_64
only, except Rocky's 5.14.0-611.41.1.el9_7, whose debuginfo is on no
mirror. It includes Rocky's one 8.3 kernel, 4.18.0-240.22.1.el8, which
the earlier Rocky repository did not cover, and the kernels both
distributions released after the earlier repositories, through
4.18.0-553.181.1.el8_10 (AlmaLinux), 553.180.1 (Rocky),
5.14.0-687.61.1.el9_8 and 6.12.0-211.69.1.el10_2. AlmaLinux 10's x86_64_v2 variant is not covered.

666 of the 686 lack the fix for CVE-2026-99999 too, and their module
carries both. The other 20 already have it (from AlmaLinux
4.18.0-553.177.1.el8_10 and Rocky 553.178.1.el8_10, and from
5.14.0-687.59.1.el9_8 and 6.12.0-211.67.1.el10_2 on both), and their
module carries CVE-2026-98432's change alone.

## What was tested

Each module was built in CI and applied with `scripts/livepatch.sh` to
its shipped kernel in a VM (`tools/loadtest.sh`), 2026-10-31, one run
per distribution and minor, 40 runs; all 684 kernels of that date
printed `RESULT: PASS`. Each was then applied from its release with the
one-line command (2026-11-02, 40 runs), and passed again. AlmaLinux
553.181.1 and Rocky 553.180.1 went through both on 2026-11-06 (runs
42066544047 and 42081208786). In each:

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

`scripts/livepatch.sh` changed on 2026-11-11, and the released modules of
14 kernels were applied with it again: seven of each distribution, from
8.3 or 8.4, 8.10, 9.0, 9.8, 10.0 and 10.2, twelve of them with a module
in the earlier repositories (runs 42963197753 and 42963213064), all
`RESULT: PASS`. What is new in
those runs:

- `check` on a host that has nothing yet passes and says `apply` will
  download the module. It used to fail there for want of the file.
- A `WARNING` written to the kernel log before the load does not fail
  `apply`. The whole log used to be searched, so an old warning made
  `apply` exit 1 with the patch enabled.
- On the twelve with an earlier module, the earlier repository's
  script refuses to load its module while this one is applied. It used
  to load it, and that took CVE-2026-98432's fix away.
- The earlier module was then loaded by hand over this one, which leaves
  this module in the kernel with its patch gone. `apply` unloaded it and
  loaded it again.

The choice of module by the kernel's vendor ran in all 14, each on its
own distribution; a converted host was not among them.

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
for 10, or be absent where the kernel has that fix. The form fed to
kpatch-build (`tools/kpatchify.py`) is checked the same way against
`tools/ref/99999-kpatch/`. Every one of the 686 matched. The script stops
when a mirror's listing cannot be read or lists no SRPM; it used to
report success over nothing. `tools/port.py` also stops if the tree's `kfree_rcu()` would not
skip a NULL pointer, as both pointers usually are.

8 and 9 are built with kpatch-build, 10 with the kernel's own
klp-build; both build replace patches, which is how a module takes over
from an earlier one.

`build.sh` takes the kernel's SRPM, its debuginfo and the compiler from
the distribution's mirrors and vault. Since 2026-11-11 it checks their
signatures against the keys in the distribution's container image; the
released modules were built before that, from packages nobody verified.
The compiler is the build the kernel records, taken from another minor
when the kernel's own no longer has it, and kpatch-build's compiler
check always runs. It had been skipped for two released modules,
AlmaLinux 5.14.0-70.13.1.el9_0 and Rocky 4.18.0-372.16.1.el8_6, the
second built with gcc 8.5.0-10.1 where the kernel records 8.5.0-4.

To see what that left in the releases, 15 kernels were rebuilt from
verified packages, those two with the check on, and load-tested (runs 42963914296,
42963928881 and 42999768571): the two above, and for each distribution
kernels of 8.3 or 8.4, 8.10, 9.0, 9.8, 10.0, 10.1 and 10.2. Six gave the
released file bit for bit. The other nine, the two above among them,
differ from their release in the order the functions were linked and in
nothing that runs: on 8 and 9 every executable section is the same, and
on 10, where the functions share one `.text`, every function is. Four of
the nine were also built with the old `build.sh` (runs 42979961871 and
42979965851) and gave the same file as the new one.

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

When this repository started, neither distribution had shipped the
fix: on 2026-10-27 the newest kernels of AlmaLinux and Rocky Linux 8, 9
and 10 did not name the CVE in their changelogs, and the sources of
4.18.0-305.3.1.el8_4, 4.18.0-553.179.1.el8_10, 5.14.0-687.61.1.el9_8 and
6.12.0-211.68.1.el10_2 still freed both pointers with `kfree()`. Both
ship it now, from the kernels named at the top.

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
the 665 kernels that had one, above). The other direction loses a fix:
an earlier module loaded over this one replaces it. The earlier
repositories' scripts refuse to do that, and `apply` here recovers from
it.

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
