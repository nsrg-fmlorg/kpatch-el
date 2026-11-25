"""Apply the fixes of CVE-2026-99288, CVE-2022-3344 and CVE-2026-99312.

usage: extra.py [--kpatch | --klp] <tree> [<kpatch tree>]

Each part of a fix has one or more forms in tools/extra/<part>.<form>.diff.
A form is taken only when every hunk applies with no fuzz, and exactly one
form must.  A part is skipped where the tree has the fix, or (migrate) no
such code.  The same form is applied to both trees, except KVM's
in the tree that is built (see kvm_callers()): the second with --kpatch,
for 8 and 9, the first with --klp, for 10.  Prints one line,
"<part>=<form>" for each part, and exits 1 when a part has no form, 2 when
it has several; nothing is written then.
"""
import glob
import os
import re
import subprocess
import sys

HERE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'extra')
mode = sys.argv[1] if sys.argv[1] in ('--kpatch', '--klp') else None
trees = sys.argv[2:] if mode else sys.argv[1:]
MACRO, HEADER = (('KLP_STATIC_CALL', '<linux/livepatch_helpers.h>') if mode == '--klp'
                 else ('KPATCH_STATIC_CALL', '"kpatch-macros.h"'))


def text(f):
    try:
        return open(os.path.join(trees[0], f), errors='surrogateescape').read()
    except FileNotFoundError:
        return ''


X86 = text('arch/x86/kvm/x86.c')
UNHASHED = 'hlist_nulls_unhashed_lockless(&sk->sk_nulls_node)'
FROMTIMER = '__inet_csk_reqsk_queue_drop(sk_listener, nreq, true);'
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
skip['syncookies'] = None
if 'sock_put(child);\n\t\treqsk_put(req);\n\t\treturn NULL;' in s:
    skip['syncookies'] = 'fixed'
elif 'child = NULL;\n\t\t\treqsk_put(req);' in s:
    skip['syncookies'] = 'older'  # 8.3 drops the reference there
if 'sock_put(fastopen_sk);\n\t\t\treqsk_put(req);\n\t\t\tgoto drop;' in text('net/ipv4/tcp_input.c'):
    skip['fastopen'] = 'older'  # 8.3 too
# CVE-2022-3344's fix calls the leave_nested member of kvm_x86_nested_ops.
# Where the structure has no such member (8.3 to 8.6, 9.0) a livepatch
# cannot add one, and those kernels get no KVM fix.
if 'leave_nested' not in X86 and not skip['kvm']:
    skip['kvm'] = 'no-leave_nested'
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
        ok = [d for d in ok if os.path.basename(d).startswith(f'kvm.{kvm_form}')]
    if part == 'migrate':
        # Forms differ by context; one that leaves the timer call alone
        # would apply to a kernel that needs it changed as well.
        ft = FROMTIMER in text('net/ipv4/inet_connection_sock.c')
        ok = [d for d in ok if ('fromtimer' in d) == ft]
    if len(ok) == 1:
        todo.append(ok[0])
        res.append(f"{part}={os.path.basename(ok[0]).split('.')[1]}")
    else:
        rc = max(rc, 2 if ok else 1)
        res.append(f"{part}={'SEVERAL' if ok else 'NONE'}" + (f'({kvm_form})' if part == 'kvm' else ''))
print(' '.join(res))
if rc:
    sys.exit(rc)

def edit(t, f, fn):
    f = f'{t}/{f}'
    old = open(f, errors='surrogateescape').read()
    new = fn(old)
    assert new != old, f
    open(f, 'w', errors='surrogateescape').write(new)


def body(src, start):
    i = src.index(start)
    return i, src.index('\n}\n', i) + 3


def kvm_callers(t, forced):
    """KVM where it is built.  Neither kpatch-build nor klp-build can handle
    kvm's own static calls and static keys.  On 9 and 10 kvm_vcpu_reset()
    has some fifteen, most of them in inline functions of headers; on 8 a
    change to it makes gcc inline other functions of x86.c differently on
    some kernels (4.18.0-477.27.2.el8_8, 4.18.0-553.87.1.el8_10), which
    brings in vcpu_enter_guest() with its static keys.  On AMD an L2 can be
    active there on INIT, in kvm_apic_accept_events(), and on SHUTDOWN, in
    shutdown_interception(); the third caller with init_event set, where
    there is one, is for SEV-SNP.  So what the fix does inside
    kvm_vcpu_reset() is done around it in those two, and their own static
    calls and the lapic_in_kernel() key become indirect calls and a test.
    @forced: kvm_vcpu_reset() does not leave the nested mode yet."""
    def lapic(s):
        a, b = body(s, 'int kvm_apic_accept_events(struct kvm_vcpu *vcpu)')
        f = s[a:b]
        n = f.count('kvm_vcpu_reset(vcpu, true);')
        assert n == 1, n
        lead = ('\t\tif (is_guest_mode(vcpu))\n'
                '\t\t\tkvm_x86_ops.nested_ops->leave_nested(vcpu);\n') if forced else ''
        f = f.replace('\t\tkvm_vcpu_reset(vcpu, true);\n',
                      lead + '\t\tkvm_vcpu_reset(vcpu, true);\n'
                      '\t\tkvm_mmu_reset_context(vcpu);\n')
        f = f.replace('!kvm_apic_has_pending_init_or_sipi(vcpu)',
                      '!(vcpu->arch.apic && vcpu->arch.apic->pending_events)')
        f = f.replace('!lapic_in_kernel(vcpu)', '!vcpu->arch.apic')
        # 9.1 calls the negation kvm_vcpu_latch_init().
        blocked = ('(is_smm(vcpu) ||\n\t    '
                   f'{MACRO}(kvm_x86_apic_init_signal_blocked)(vcpu))')
        f, k = re.subn(r'!kvm_apic_init_sipi_allowed\(vcpu\)|kvm_vcpu_latch_init\(vcpu\)',
                       lambda m: blocked, f)
        assert k == 1, k
        f, k = re.subn(r'(static_call\(kvm_x86_|kvm_x86_call\()vcpu_deliver_sipi_vector\)',
                       f'{MACRO}(kvm_x86_vcpu_deliver_sipi_vector)', f)
        assert k == 1, k
        assert not re.search(r'\b(static_call|kvm_x86_call)\(', f), f
        s = s[:a] + f + s[b:]
        inc = [m.end() for m in re.finditer(r'^#include .*\n', s, re.M)]
        return s[:inc[-1]] + f'#include {HEADER}\n' + s[inc[-1]:]

    def svm(s):
        a, b = body(s, 'static int shutdown_interception(struct kvm_vcpu *vcpu)')
        f = s[a:b]
        assert f.count('kvm_vcpu_reset(vcpu, true);') == 1
        f = re.sub(r'(\t+)kvm_vcpu_reset\(vcpu, true\);\n',
                   lambda m: ((f'{m[1]}if (is_guest_mode(vcpu))\n{m[1]}\tsvm_leave_nested(vcpu);\n'
                               if forced else '') + m[0] +
                              f'{m[1]}kvm_mmu_reset_context(vcpu);\n'), f)
        return s[:a] + f + s[b:]

    edit(t, 'arch/x86/kvm/lapic.c', lapic)
    edit(t, 'arch/x86/kvm/svm/svm.c', svm)


kvm_todo = [d for d in todo if os.path.basename(d).startswith('kvm.')]
LOCKLESS = 'hlist_nulls_unhashed_lockless(' in text('include/linux/list_nulls.h')
for n, t in enumerate(trees):
    callers = kvm_todo and n == {'--kpatch': 1, '--klp': 0}.get(mode)
    if callers:
        x86 = open(f'{t}/arch/x86/kvm/x86.c', errors='surrogateescape').read()
    for d in todo:
        if callers and d in kvm_todo and not d.endswith('kvm.el8.diff'):
            continue
        r = patch(t, d)
        assert r.returncode == 0, (t, d, r.stdout)
    if callers:
        # Only the parts outside x86.c stay.
        open(f'{t}/arch/x86/kvm/x86.c', 'w', errors='surrogateescape').write(x86)
        kvm_callers(t, kvm_todo[0].endswith('kvm.el8.diff'))
    if not LOCKLESS and any('lookup' in d for d in todo):
        # 8.3 has no such helper; this is what it does.
        for f in ('net/ipv4/inet_hashtables.c', 'net/ipv6/inet6_hashtables.c'):
            edit(t, f, lambda s: s.replace(UNHASHED, '!READ_ONCE(sk->sk_nulls_node.pprev)'))
