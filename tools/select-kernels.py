"""Choose which kernels a CI run builds or load-tests.

usage: select-kernels.py <selection> [<changed-file>...]

<selection> is "all", "changed", or a comma-separated list of minors or
kernel versions, each optionally prefixed with a distribution and a colon
(e.g. "rocky:9.0,10.0" or "almalinux:4.18.0-553.144.1.el8_10").  Without
a prefix an item selects from both distributions.  A minor selects every
kernel of that minor in tools/kernels.tsv.  With "changed", the kernels
are derived from the changed files given on the rest of the command line:

  patches/<distro>/<nvr>.diff,
  patches/<distro>/kpatch/<nvr>.diff              that kernel
  tools/klp-overlay*                              10.0, 10.1 (borrowed klp-build)
  tools/klpsymcheck.py                            10.x (checked after klp-build)
  build.sh, .github/workflows/*                   one kernel per build path
                                                  and distribution: 8.10, 9.0,
                                                  9.8, 10.0, 10.1, 10.2
  anything else                                   nothing

tools/kernels.tsv: distribution, minor, kernel version, and, where the
SRPM is named differently from the binaries, the SRPM's version.

Prints a GitHub Actions matrix "include" list as JSON; [] means nothing
to do.
"""
import json
import os
import sys

here = os.path.dirname(os.path.abspath(__file__))
DISTROS = ('almalinux', 'rocky')
rows = []
for line in open(os.path.join(here, 'kernels.tsv')).read().split('\n'):
    if line:
        f = line.split('\t')
        assert f[0] in DISTROS, line
        rows.append({'distro': f[0], 'minor': f[1], 'nvr': f[2],
                     'srpm': f[3] if len(f) > 3 else f[2]})

# 9.0: odd SRPM name on Rocky, gcc fallback on AlmaLinux.  10.0: split
# objtool.  10.1: borrowed klp-build.  10.2: shipped klp-build.  8.10,
# 9.8: plain.
PATHS = {'8.10', '9.0', '9.8', '10.0', '10.1', '10.2'}


def keys(r):
    return {r['minor'], r['nvr'], r['srpm']}


sel, changed = sys.argv[1], sys.argv[2:]
want = set()  # of (distro, minor or nvr)
if sel == 'all':
    want = {(r['distro'], r['minor']) for r in rows}
elif sel == 'changed':
    for f in changed:
        parts = f.split('/')
        base = parts[-1]
        if (parts[0] == 'patches' and len(parts) >= 3 and parts[1] in DISTROS
                and base.endswith('.diff')):
            want.add((parts[1], base[:-5]))
        elif f.startswith('tools/klp-overlay'):
            want |= {(d, m) for d in DISTROS for m in ('10.0', '10.1')}
        elif f == 'tools/klpsymcheck.py':
            want |= {(r['distro'], r['minor']) for r in rows if r['minor'].startswith('10.')}
        elif f == 'build.sh' or f.startswith('.github/workflows/'):
            want |= {(d, m) for d in DISTROS for m in PATHS}
else:
    for x in (x.strip() for x in sel.split(',')):
        if not x:
            continue
        d, _, k = x.rpartition(':')
        for dd in ([d] if d else DISTROS):
            if not any(r['distro'] == dd and k in keys(r) for r in rows):
                if d:
                    sys.exit(f'unknown kernel or minor: {x}')
                continue
            want.add((dd, k))
        if not d and not any(k in keys(r) for r in rows):
            sys.exit(f'unknown kernel or minor: {x}')

out = [r for r in rows if any((r['distro'], k) in want for k in keys(r))]
# A minor picked by a build path builds its first kernel only, not every
# kernel listed for it.
if sel == 'changed':
    seen, first = set(), []
    for r in out:
        dm = (r['distro'], r['minor'])
        if (r['distro'], r['nvr']) in want or (r['distro'], r['srpm']) in want or dm not in seen:
            first.append(r)
        seen.add(dm)
    out = first
# The first kernel of each minor keeps its ccache between runs; the others
# are built once, and their caches (about 2 GB each) would only push the
# first ones out of the repository's 10 GB.
ga = {}
for r in rows:
    ga.setdefault((r['distro'], r['minor']), r['nvr'])
for r in out:
    r['ga'] = ga[(r['distro'], r['minor'])] == r['nvr']
print(json.dumps(out))
