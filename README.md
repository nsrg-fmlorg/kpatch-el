# kpatch livepatch for CVE-2026-98432 on AlmaLinux and Rocky Linux

[日本語](README.ja.md)

Livepatch modules that fix CVE-2026-98432 on a running AlmaLinux or Rocky
Linux 8, 9 or 10 host (x86_64) without a reboot. On kernels that lack the
fix for CVE-2026-99999 as well, the same module fixes that too, so a host
needs one module whichever of the two its kernel lacks.

**Status (2026-10-30): work in progress. No module is released yet;
there is nothing to apply.** The ports are being generated for every
kernel of both distributions, and the modules built and tested in VMs.
This README will say what was released and what was tested on it.

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
ones, and is built to replace an earlier module already loaded (both
kpatch-build and klp-build build replace patches by default; not yet
tested in a VM).

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
