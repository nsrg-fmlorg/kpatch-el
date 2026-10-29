"""Apply a kernel SRPM's own patches to its unpacked tarball, as %prep does.

usage: prep.py <dir with kernel.spec and the SRPM's patches> <tree>

The tarball is not the source that was built.  AlmaLinux carries its own
fixes as patches in the spec (8.10's 553.177.1 adds CVE-2026-99999's as
1101-ipv4-validate-checksum_start-before-completing-checksum.patch;
10.2's 211.69.1 is Red Hat's 211.56.1 tarball plus some fifty), and
rpmbuild -bp, which kpatch-build and build.sh's klp-build path both run,
applies them.  A port made against the bare tarball then either misses a
fix the kernel has or fails to apply on top of it.

Only %prep's literal "ApplyPatch <file>" and "ApplyOptionalPatch <file>"
lines are followed, in order, with the spec's own patch command
(patch -p1 -F1 -s).  ApplyOptionalPatch skips a missing or empty file,
as the spec's function does.  Macros in the file name are expanded from
the spec's %define and %global lines.  Prints each patch applied.
"""
import os
import re
import subprocess
import sys

src, tree = sys.argv[1], sys.argv[2]
spec = open(os.path.join(src, 'kernel.spec')).read()

macros = {}
for m in re.finditer(r'^%(?:define|global)\s+(\w+)\s+(.*?)\s*$', spec, re.M):
    macros.setdefault(m.group(1), m.group(2))


def expand(s):
    for _ in range(10):
        t = re.sub(r'%\{\??(\w+)\}', lambda m: macros.get(m.group(1), m.group(0)), s)
        if t == s:
            return s
        s = t
    return s


prep = re.search(r'^%prep\b(.*?)^%build\b', spec, re.M | re.S)
assert prep, 'no %prep section'
n = 0
for m in re.finditer(r'^\s*(ApplyPatch|ApplyOptionalPatch)\s+(\S+)', prep.group(1), re.M):
    kind, name = m.group(1), expand(m.group(2))
    if name.startswith('$'):
        continue  # the function's own body
    assert '%' not in name, f'unexpanded macro in {name}'
    path = os.path.join(src, name)
    if kind == 'ApplyOptionalPatch' and (not os.path.exists(path) or os.path.getsize(path) == 0):
        print(f'skip (optional, empty or absent): {name}')
        continue
    with open(path, 'rb') as f:
        subprocess.run(['patch', '-p1', '-F1', '-s', '-d', tree], stdin=f, check=True)
    print(f'applied: {name}')
    n += 1
print(f'{n} patch(es) applied')
