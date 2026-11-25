"""Print scripts/livepatch.sh's table of modules from CI runs.

usage: release-table.py <cachedir> <run-id>...

A kernel of tools/kernels.tsv gets a row when, in one of the build.yml
runs, its build and its load test both succeeded and the module was built
from the diff that is in patches/ now.  A later run on the command line
wins.  Everything else is listed on stderr with the reason.

The modules are hashed and deleted again, 8 MB each; <cachedir> keeps
only the hashes, per artifact.  Needs gh.
"""
import hashlib
import json
import os
import subprocess
import sys
import tempfile

REPO = 'nsrg-fmlorg/kpatch-el'
top = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
cache, runs = sys.argv[1], sys.argv[2:]
os.makedirs(cache, exist_ok=True)


def gh(*a):
    return subprocess.run(['gh', *a], check=True, capture_output=True, text=True,
                          stdin=subprocess.DEVNULL).stdout


def listing(run, what, jq):
    out = gh('api', '--paginate', f'repos/{REPO}/actions/runs/{run}/{what}?per_page=100', '-q', jq)
    return [l.split('\t') for l in out.split('\n') if l]


def artifact(run, aid, name):
    """(module file name, its SHA-256, SHA-256 of the diff it was built from)"""
    c = os.path.join(cache, aid + '.json')
    if os.path.exists(c):
        return json.load(open(c))
    with tempfile.TemporaryDirectory(dir=cache) as d:
        gh('run', 'download', run, '-R', REPO, '-n', name, '-D', d)
        kos = [f for f in os.listdir(d) if f.endswith('.ko')]
        if len(kos) != 1:
            return None
        r = [kos[0]] + [hashlib.sha256(open(os.path.join(d, f), 'rb').read()).hexdigest()
                        for f in (kos[0], 'fixes.diff')]
    with open(c + '.tmp', 'w') as f:
        json.dump(r, f)
    os.rename(c + '.tmp', c)
    return r


kernels = []
for line in open(os.path.join(top, 'tools/kernels.tsv')):
    f = line.rstrip('\n').split('\t')
    if len(f) >= 3:
        kernels.append(tuple(f[:3]))

row, why = {}, {}
for run in runs:
    jobs = {n: c for n, c in listing(run, 'jobs', '.jobs[]|[.name,(.conclusion//.status)]|@tsv')}
    arts = {n: i for n, i in listing(run, 'artifacts', '.artifacts[]|select(.expired|not)|[.name,.id]|@tsv')}
    for k in kernels:
        distro, minor, nvr = k
        b = jobs.get(f'build {distro} {minor} ({nvr})')
        if b is None:
            continue
        t = jobs.get(f'loadtest {distro} {minor} ({nvr})')
        if (b, t) != ('success', 'success'):
            why.setdefault(k, f'run {run}: build {b}, load test {t}')
            continue
        name = f'kpatch-{distro}-{nvr}'
        r = artifact(run, arts[name], name) if name in arts else None
        if not r:
            why.setdefault(k, f'run {run}: no module in the artifacts')
            continue
        sub = 'kpatch/' if int(minor.split('.')[0]) < 10 else ''
        diffs = [p for p in (f'{top}/patches/{distro}/{sub}{nvr}.diff',
                             f'{top}/patches/{distro}/{nvr}.diff') if os.path.exists(p)]
        now = hashlib.sha256(open(diffs[0], 'rb').read()).hexdigest() if diffs else None
        if r[2] != now:
            why.setdefault(k, f'run {run}: built from another diff')
            continue
        want = 'livepatch_el_r1_' + nvr.replace('.', '_').replace('-', '_') + '.ko'
        assert r[0] == want, (r[0], want)
        # Rocky and AlmaLinux name the module alike, so a release each.
        row[k] = f'{distro} {nvr}.x86_64 {r[1]} r1-{distro}-{minor}'

for k in kernels:
    if k in row:
        print(row[k])
    else:
        print(*k, why.get(k, 'not in these runs'), file=sys.stderr)
print(f'{len(row)} of {len(kernels)} kernels', file=sys.stderr)
