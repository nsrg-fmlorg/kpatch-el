# Cumulative kpatch livepatch for AlmaLinux and Rocky Linux

[日本語](README.ja.md)

One livepatch module per kernel for AlmaLinux and Rocky Linux 8, 9 and 10
(x86_64), carrying every fix below that the kernel lacks. The modules are
replace patches: loading a newer one takes the place of the one before,
so the fixes are kept together in one module rather than one module per
CVE.

No module is released yet. The first kernel, Rocky Linux
4.18.0-553.180.1.el8_10, is being built and tested; the others follow
once it passes.

| CVE | What | Upstream fix |
|---|---|---|
| CVE-2026-98432 | use after free of IP options on TCP request and child sockets | e3f33b0a1d89 |
| CVE-2026-99999 | "PwnEscape": a crafted checksum_start lets the checksum code overwrite an IPv4 header already parsed; on kernels without the fix | |
| CVE-2026-99288 | "NoisyTCP": unhashed sockets accepted by the lockless established lookup, remote kernel panic | 4e2b3ef19e0e |
| CVE-2022-3344 | KVM nested SVM: a vCPU reset while L2 is active, host crash | 917401f26a6a, 16ae56d7e052, f9697df25143, ed129ec9057f, 05311ce954ae |
| CVE-2026-99312 | KVM: stale MMU context after INIT while L2 is active | c7c288d178cb |

The two KVM fixes matter on AMD hosts with nested virtualization enabled
(`kvm_amd nested=1`); 9 and 10 already have CVE-2022-3344's, and
CVE-2026-99312 fixes a path that fix opened, so 8 takes both.

```sh
curl -fsSL https://raw.githubusercontent.com/nsrg-fmlorg/kpatch-el/main/scripts/livepatch.sh | sudo bash -s -- apply
```

The script picks the module for the running kernel (`uname -r`); a kernel
with no released module is refused and nothing changes. `check`,
`status` and `remove` check, show and undo it. A module from
nsrg-fmlorg/kpatch-cve-2026-98432, kpatch-alma-cve-2026-99999 or
kpatch-rocky-cve-2026-99999 already loaded is replaced and unloaded. A
livepatch does not survive a reboot.

## How the ports are made

CVE-2026-98432's and CVE-2026-99999's part is the port made for
kpatch-cve-2026-98432 (`tools/mkdiffs.sh`, below). The other three are
upstream's changes, checked against the kernel's source, and appended.

On 4.18.0-553.180.1.el8_10 upstream's KVM changes and NoisyTCP's lookup
changes apply as they are, except for upstream's `WARN_ON_ONCE()` after
the reset, which only checks the fix and is left out. With it, gcc
inlines `kvm_check_request()` into `vcpu_enter_guest()` differently, and
kpatch-build refuses that function for its jump labels on static keys
that live in the `kvm` module; without it the function compiles the same
as in the shipped kernel. NoisyTCP also fixes a refcount in the Fast
Open failure path of `tcp_conn_request()`, which upstream writes against
code where `tcp_disconnect()` has already dropped one reference to the
request. EL8 has that code from 4.18.0-553.87.1.el8_10 on, where Red Hat
took the CVE-2025-39955 fix (RHEL-120664), so upstream's hunk applies
there too. Earlier EL8 kernels still call `reqsk_fastopen_remove()` in
that path and need it written differently; none of them is covered yet.
Upstream's changes to request socket migration have nothing to apply to
on 8.

`tools/mkdiffs.sh` ports CVE-2026-98432 to every kernel SRPM of a minor,
after applying the SRPM's own patches to its tarball as `%prep` does
(`tools/prep.py`), and checks the changed lines against `tools/ref/`.

8 and 9 are built with kpatch-build, 10 with the kernel's own klp-build;
both build replace patches. `build.sh` verifies the signatures of the
SRPM, the debuginfo and the compiler it takes from the distribution's
mirrors, and builds with the gcc the kernel records.

## What is tested

`.github/workflows/build.yml` builds the module and boots the shipped
kernel in a VM (`tools/loadtest.sh`), where `tools/loadtest-guest.sh`
loads the kernel's module from kpatch-cve-2026-98432 first, applies this
one over it with `scripts/livepatch.sh`, and checks that:

- the earlier module is replaced and unloaded;
- the changed functions are in the livepatch, and the changed ones of
  `kvm` and, on AMD, `kvm_amd` are redirected, both in the modules the
  boot loaded before the patch and after loading them again under it;
- 2000 TCP connections with IP options open and close
  (`tools/tcpopt.py`), and 200 connections each over IPv4 and IPv6 that
  are completed through SYN cookies send and receive
  (`tools/syncookie.py`);
- KVM guests are created, run to a HLT and freed (`tools/kvmrun.py`),
  where the VM is given VMX or SVM;
- the earlier module loaded over this one is undone by `apply`, and
  `remove` takes it all off, with no BUG, Oops or WARNING logged.

## Layout

| Path | What it is |
|---|---|
| `build.sh` | Builds the module for one kernel inside the distribution's container |
| `patches/<distro>/<nvr>.diff`, `patches/<distro>/kpatch/<nvr>.diff` | The fixes for one kernel, for klp-build and for kpatch-build |
| `tools/kernels.tsv` | The kernels CI builds: distribution, minor, kernel version |
| `tools/select-kernels.py` | Which of them a CI run takes |
| `tools/mkdiffs.sh` | Makes CVE-2026-98432's port for every kernel of a minor and checks it against `tools/ref/` |
| `tools/prep.py` | Applies an SRPM's own patches to its tarball, as `%prep` does, before porting |
| `tools/port.py` | CVE-2026-98432's change, applied to a kernel tree |
| `tools/kpatchify.py` | Turns a port into the form fed to kpatch-build |
| `tools/klp-overlay.sh`, `tools/klp-overlay-lds.py`, `tools/klp-overlay/` | Lends 10.2's klp-build to 10.0 and 10.1 |
| `tools/klpsymcheck.py` | Checks a klp-build module's symbols against the shipped kernel |
| `tools/loadtest.sh`, `tools/loadtest-guest.sh`, `tools/loadtest-bootprep.sh`, `tools/loadtest-bootinfo.sh` | Boots the shipped kernel in a VM and applies, checks and removes the module |
| `tools/csum-probe.sh`, `tools/csum-inject.py` | Probes CVE-2026-99999 before and after |
| `tools/tcpopt.py` | Drives the two frees CVE-2026-98432 changes, with IP options present |
| `tools/syncookie.py` | Connections completed through SYN cookies (CVE-2026-99288) |
| `tools/kvmrun.py` | Creates, runs and frees KVM guests (CVE-2022-3344, CVE-2026-99312) |
| `tools/doccheck.py` | Fails when a file is not named in both READMEs, or a link is broken |
| `scripts/livepatch.sh` | Applies, checks and removes a released module on a host |
| `scripts/build-local.sh` | Builds and load-tests one kernel's module on your own machine |
| `.github/workflows/diffs.yml` | Runs `tools/mkdiffs.sh` for every minor of both distributions |
| `.github/workflows/build.yml` | Builds and load-tests modules |
| `.github/workflows/docs.yml` | Runs `tools/doccheck.py` |
