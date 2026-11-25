"""Apply the fixes of CVE-2026-99288, CVE-2022-3344 and CVE-2026-99312.

usage: extra.py <tree>...

Each part of a fix has one or more forms in tools/extra/<part>.<form>.diff.
A form is taken only when every hunk applies with no fuzz, and exactly one
form must.  A part is skipped where the tree has the fix, or (migrate) no
such code.  The same form is applied to every tree.  Prints one line,
"<part>=<form>" for each part, and exits 1 when a part has no form, 2 when
it has several; nothing is written then.
"""
import glob
import os
import subprocess
import sys

HERE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'extra')
trees = sys.argv[1:]


def text(f):
    try:
        return open(os.path.join(trees[0], f), errors='surrogateescape').read()
    except FileNotFoundError:
        return ''


X86 = text('arch/x86/kvm/x86.c')
UNHASHED = 'hlist_nulls_unhashed_lockless(&sk->sk_nulls_node)'
INIT = ('\tif (old_cr0 & X86_CR0_PG)\n'
        '\t\tkvm_make_request(KVM_REQ_TLB_FLUSH_GUEST, vcpu);\n')
skip = {
    'lookup4': 'fixed' if UNHASHED in text('net/ipv4/inet_hashtables.c') else None,
    'lookup6': 'fixed' if UNHASHED in text('net/ipv6/inet6_hashtables.c') else None,
    'migrate': None if 'reqsk_migrate_reset' in text('net/ipv4/inet_connection_sock.c') else 'absent',
    'fastopen': 'fixed' if 'already dropped one reqsk ref.' in text('net/ipv4/tcp_input.c') else None,
    'kvm': 'fixed' if INIT in X86 else None,
}
if 'The timer was not armed, drop its reference here.' in text('net/ipv4/inet_connection_sock.c'):
    skip['migrate'] = 'fixed'
s = text('net/ipv4/syncookies.c')
i = s.find('sock_put(child);\n\t\treqsk_put(req);\n\t\treturn NULL;')
skip['syncookies'] = 'fixed' if i >= 0 else None
# Without kvm_leave_nested() a tree lacks CVE-2022-3344's fix and takes
# it whole; with it, only CVE-2026-99312's hunk is missing.
kvm_form = 'inithunk' if 'kvm_leave_nested' in X86 else 'el8'


def patch(tree, diff, *extra):
    return subprocess.run(['patch', '-f', '-p1', '-F0', '-s', '--no-backup-if-mismatch',
                           '-d', tree, '-i', diff, *extra],
                          stdin=subprocess.DEVNULL, capture_output=True, text=True)


res, rc, todo = [], 0, []
for part in ('lookup4', 'lookup6', 'syncookies', 'fastopen', 'migrate', 'kvm'):
    if skip[part]:
        res.append(f'{part}={skip[part]}')
        continue
    ok = [d for d in sorted(glob.glob(f'{HERE}/{part}.*.diff'))
          if patch(trees[0], d, '--dry-run').returncode == 0]
    if part == 'kvm':
        ok = [d for d in ok if os.path.basename(d) == f'kvm.{kvm_form}.diff']
    if len(ok) == 1:
        todo.append(ok[0])
        res.append(f"{part}={os.path.basename(ok[0]).split('.')[1]}")
    else:
        rc = max(rc, 2 if ok else 1)
        res.append(f"{part}={'SEVERAL' if ok else 'NONE'}" + (f'({kvm_form})' if part == 'kvm' else ''))
print(' '.join(res))
if rc:
    sys.exit(rc)
for t in trees:
    for d in todo:
        r = patch(t, d)
        assert r.returncode == 0, (t, d, r.stdout)
