"""Turn a tree patched by port.py into the form fed to kpatch-build.

usage: kpatchify.py <original-tree> <patched-tree>

The fix adds ip_check_csum_start() to include/net/ip.h.  A changed header
recompiles everything that includes it, and kpatch-build then fails on
unrelated objects whose static locals get renumbered (9.8:
"drivers/net/ethernet/chelsio/cxgb4/t4_hw.o: reference to static local
variable t4_reg_ranges.158 in CSWTCH.512 was removed").  So put ip.h back
and give each patched .c file its own copy of the helper instead.  The
code that runs is the same; only where the inline is defined moves.
"""
import sys

orig, root = sys.argv[1], sys.argv[2]
HDR = 'include/net/ip.h'
USERS = ['net/ipv4/ip_output.c', 'net/xfrm/xfrm_output.c',
         'net/bridge/netfilter/nf_conntrack_bridge.c',
         'net/netfilter/nfnetlink_queue.c', 'net/netfilter/xt_CHECKSUM.c']
HELPER = '''
static inline int ip_check_csum_start(const struct sk_buff *skb)
{
	if (unlikely(skb->csum_start < skb->network_header + ip_hdrlen(skb)))
		return -EINVAL;
	return 0;
}
'''

# 26a77d02891a also exports skb_crc32c_csum_help from net/core/dev.c,
# because nfnetlink_queue, a module, now calls it.  kpatch-build cannot add
# an export ("changed section __ksymtab_strings not selected for
# inclusion" on 8.10, ".export_symbol" on 9.8).  Nor does it turn a
# module's reference to an unexported vmlinux function into a livepatch
# symbol ("Undefined symbols: skb_crc32c_csum_help" on 8.10, modpost
# "undefined!" on 9.8); it does that only for references from vmlinux
# objects.  So dev.c is left as it was, and the call goes through a new
# function in another vmlinux object, which only calls the original.
#
# The wrapper lives at the end of net/core/skbuff.c, not in dev.c.  In
# dev.c, inserted after the original, 9.8 also counted
# register_netdevice() as changed (shifted line numbers); appended to
# dev.c it still counted skb_crc32c_csum_help() and
# skb_csum_hwoffload_help(), whose inlining changed once the former had a
# second caller in the same file.  A caller in another file changes
# nothing in dev.o.
DEV = 'net/core/dev.c'
SKB = 'net/core/skbuff.c'
NFQ = 'net/netfilter/nfnetlink_queue.c'
WRAP = 'kpatch_skb_crc32c_csum_help'
try:
    dev = open(f'{orig}/{DEV}').read()
except FileNotFoundError:
    dev = None
if dev is not None:
    open(f'{root}/{DEV}', 'w').write(dev)
    nfq = open(f'{root}/{NFQ}').read()
    if ('skb_crc32c_csum_help(entskb)' in nfq
            and 'EXPORT_SYMBOL(skb_crc32c_csum_help)' not in dev):
        assert 'int skb_crc32c_csum_help(struct sk_buff *skb)\n{' in dev
        skb = open(f'{root}/{SKB}').read()
        skb = skb.rstrip('\n') + f'''

int {WRAP}(struct sk_buff *skb)
{{
	return skb_crc32c_csum_help(skb);
}}
'''
        open(f'{root}/{SKB}', 'w').write(skb)
        assert nfq.count('skb_crc32c_csum_help(entskb)') == 1
        nfq = nfq.replace('skb_crc32c_csum_help(entskb)', f'{WRAP}(entskb)')
        k = nfq.index('static int nf_queue_checksum_help(')
        nfq = nfq[:k] + f'int {WRAP}(struct sk_buff *skb);\n\n' + nfq[k:]
        open(f'{root}/{NFQ}', 'w').write(nfq)

patched_hdr = open(f'{root}/{HDR}').read()
orig_hdr = open(f'{orig}/{HDR}').read()
if 'ip_check_csum_start(' in orig_hdr:
    # The kernel carries CVE-2026-99999's fix; port.py changed only the
    # CVE-2026-98432 lines, which touch no header.
    assert patched_hdr == orig_hdr, 'ip.h changed although already fixed'
    sys.exit(0)
assert 'static inline int ip_check_csum_start(' in patched_hdr, 'not patched'
open(f'{root}/{HDR}', 'w').write(orig_hdr)

for p in USERS:
    try:
        s = open(f'{root}/{p}').read()
    except FileNotFoundError:
        continue
    assert 'ip_check_csum_start(' in s, p
    lines = s.split('\n')
    last = max(i for i, l in enumerate(lines) if l.startswith('#include'))
    lines.insert(last + 1, HELPER.rstrip('\n'))
    open(f'{root}/{p}', 'w').write('\n'.join(lines))
