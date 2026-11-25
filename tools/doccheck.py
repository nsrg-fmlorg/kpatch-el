"""Every file under tools/, scripts/ and .github/workflows/ must be named
in README.md and README.ja.md, and every relative link in the Markdown
files must resolve.  A tool nobody can find from the README is a tool
the next reader re-invents; this went unnoticed several times."""
import os, re, sys
root = sys.argv[1] if len(sys.argv) > 1 else '.'
fail = []
files = []
for top in ('tools', 'scripts', '.github/workflows'):
    for d, _, fs in os.walk(os.path.join(root, top)):
        for f in fs:
            p = os.path.relpath(os.path.join(d, f), root)
            if p.startswith(('tools/ref/', 'tools/extra/')) or '__pycache__' in p:
                continue
            files.append(p)
for readme in ('README.md', 'README.ja.md'):
    text = open(os.path.join(root, readme)).read()
    for p in sorted(files):
        d = os.path.dirname(p) + '/'
        if p not in text and not (d != './' and f'`{d}`' in text and d.count('/') >= 2):
            fail.append(f'{readme}: does not name {p}')
for d, _, fs in os.walk(root):
    if '/.git' in d or d.endswith('.git'):
        continue
    for f in fs:
        if f.endswith('.md'):
            p = os.path.join(d, f)
            for m in re.finditer(r'\]\(([^)#\s]+)', open(p).read()):
                t = m.group(1)
                if not t.startswith('http') and not os.path.exists(os.path.normpath(os.path.join(d, t))):
                    fail.append(f'{os.path.relpath(p, root)}: broken link {t}')
for f in fail:
    print(f)
print(f'{len(files)} files, {len(fail)} problems')
sys.exit(1 if fail else 0)
