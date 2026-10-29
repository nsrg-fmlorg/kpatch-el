"""Check a livepatch module's symbol references against the shipped kernel.

usage: klpsymcheck.py <livepatch.ko> <System.map> <Module.symvers> <modules-dir>

klp-build compiles its own copy of the kernel, so nothing guarantees that
a symbol it resolved there exists in the kernel the module will be loaded
into.  Three things are checked:

  .klp.sym.<obj>.<name>,<pos>  resolved by the livepatch core at load time:
      <name> must occur in <obj> (vmlinux: System.map; a module: its
      symbol table) exactly once when <pos> is 0, at least <pos> times
      otherwise.
  undefined symbols             resolved by the module loader: must be
      exported (Module.symvers).
  __versions CRCs               checked by the module loader under
      modversions: each must equal the CRC in Module.symvers.  10.1
      refused a module whose klp_enable_patch CRC differed ("disagrees
      about version of symbol"), which the name checks above passed.

<modules-dir> is the unpacked /lib/modules/<kver>/kernel of the shipped
kernel.  Exits non-zero, listing each failure, if anything is missing.
"""
import collections, lzma, os, re, subprocess, sys, tempfile

ko, sysmap, symvers, moddir = sys.argv[1:5]


def symtab(path):
    out = subprocess.run(['readelf', '-sW', path], capture_output=True,
                         text=True, check=True).stdout
    for line in out.splitlines():
        f = line.split()
        if len(f) >= 8 and f[0].endswith(':'):
            yield f[7], f[6]          # name, ndx


vmlinux = collections.Counter(l.split()[2] for l in open(sysmap) if len(l.split()) >= 3)
exported = {}
for l in open(symvers):
    f = l.rstrip('\n').split('\t')
    if len(f) >= 2:
        exported[f[1]] = int(f[0], 16)

modpaths = {}
for d, _, files in os.walk(moddir):
    for f in files:
        name = re.sub(r'\.ko(\.xz)?$', '', f)
        if name != f:
            modpaths[name.replace('-', '_')] = os.path.join(d, f)

modcache = {}


def modsyms(obj):
    if obj not in modcache:
        p = modpaths.get(obj)
        if p is None:
            modcache[obj] = None
        else:
            if p.endswith('.xz'):
                tmp = tempfile.NamedTemporaryFile(suffix='.ko', delete=False)
                tmp.write(lzma.open(p).read())
                tmp.close()
                p = tmp.name
            modcache[obj] = collections.Counter(n for n, _ in symtab(p))
    return modcache[obj]


fail = []
checked = 0
for name, ndx in symtab(ko):
    m = re.match(r'^\.klp\.sym\.([^.]+)\.(.+),(\d+)$', name)
    if m:
        obj, sym, pos = m.group(1), m.group(2), int(m.group(3))
        have = vmlinux if obj == 'vmlinux' else modsyms(obj)
        checked += 1
        if have is None:
            fail.append(f'{name}: module {obj} not found')
        elif pos == 0 and have[sym] != 1:
            fail.append(f'{name}: {have[sym]} occurrences in {obj}, need exactly 1')
        elif pos > 0 and have[sym] < pos:
            fail.append(f'{name}: {have[sym]} occurrences in {obj}, need {pos}')
    elif ndx == 'UND' and name:
        checked += 1
        if name not in exported:
            fail.append(f'{name}: undefined and not exported')

out = subprocess.run(['modprobe', '--dump-modversions', ko], capture_output=True,
                     text=True, check=True).stdout
for line in out.splitlines():
    crc, name = line.split()
    checked += 1
    if name not in exported:
        fail.append(f'{name}: versioned but not exported')
    elif int(crc, 16) != exported[name]:
        fail.append(f'{name}: CRC {crc} differs from the shipped kernel\'s {exported[name]:#010x}')

for f in fail:
    print('MISSING', f)
print(f'{checked} references checked, {len(fail)} missing')
sys.exit(1 if fail else 0)
