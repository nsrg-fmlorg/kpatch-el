import sys,re
root=sys.argv[1]
def ed(p,old,new,count=1):
    f=root+'/'+p; s=open(f).read()
    assert s.count(old)==count,(p,old[:40],s.count(old)); open(f,'w').write(s.replace(old,new))

# CVE-2026-98432, torvalds/linux e3f33b0a1d89 "ipv4: free inet_opt and
# ireq_opt after an RCU grace period".  Both pointers are usually NULL (no
# IP options), so kfree_rcu() must skip NULL as kfree() does; it does in
# every EL8-10 tree checked (8.4 GA onward), and this stops where it does
# not rather than turn every socket close into call_rcu(NULL).
# Skipped where the kernel has the fix (from 553.182.1).
if 'kfree_rcu(rcu_dereference_protected(inet->inet_opt' not in open(root+'/net/ipv4/af_inet.c').read():
    rcu=open(root+'/include/linux/rcupdate.h').read()
    assert re.search(r'#define kv?free_rcu(_arg_2)?\(ptr, rhf\)\s*\\\s*\ndo \{\s*\\\s*\n\s*typeof \(ptr\) ___p = \(ptr\);\s*\\\s*\n\s*\\\s*\n\s*if \(___p\)',rcu),'kfree_rcu() does not skip NULL'
    ed('net/ipv4/af_inet.c','''	kfree(rcu_dereference_protected(inet->inet_opt, 1));
''','''	kfree_rcu(rcu_dereference_protected(inet->inet_opt, 1), rcu);
''')
    ed('net/ipv4/tcp_ipv4.c','''	kfree(rcu_dereference_protected(inet_rsk(req)->ireq_opt, 1));
''','''	kfree_rcu(rcu_dereference_protected(inet_rsk(req)->ireq_opt, 1), rcu);
''')

# CVE-2026-99999.  Kernels from 553.178.1, 687.59.1 and 211.67.1 (and
# AlmaLinux's own 553.177.1) carry it already.
if 'ip_check_csum_start' in open(root+'/include/net/ip.h').read():
    sys.exit(0)
ed('include/net/ip.h','''	return ip_hdr(skb)->ihl * 4;
}
''','''	return ip_hdr(skb)->ihl * 4;
}

static inline int ip_check_csum_start(const struct sk_buff *skb)
{
	if (unlikely(skb->csum_start < skb->network_header + ip_hdrlen(skb)))
		return -EINVAL;
	return 0;
}
''')
for p,lbl in [('net/ipv4/ip_output.c','fail'),('net/bridge/netfilter/nf_conntrack_bridge.c','blackhole')]:
    try: open(root+'/'+p)
    except FileNotFoundError: continue
    ed(p,'''	if (skb->ip_summed == CHECKSUM_PARTIAL &&
	    (err = skb_checksum_help(skb)))
		goto %s;
'''%lbl,'''	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		err = ip_check_csum_start(skb);
		if (!err)
			err = skb_checksum_help(skb);
		if (err)
			goto %s;
	}
'''%lbl)
ed('net/xfrm/xfrm_output.c','''	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		err = skb_checksum_help(skb);
		if (err) {
			XFRM_INC_STATS(net, LINUX_MIB_XFRMOUTERROR);
			kfree_skb(skb);
			return err;
		}
	}

out:
	return xfrm_output2(net, sk, skb);
}
''','''	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		if (skb->protocol == htons(ETH_P_IP)) {
			err = ip_check_csum_start(skb);
			if (err)
				goto error;
		}
		err = skb_checksum_help(skb);
		if (err)
			goto error;
	}

out:
	return xfrm_output2(net, sk, skb);
error:
	XFRM_INC_STATS(net, LINUX_MIB_XFRMOUTERROR);
	kfree_skb(skb);
	return err;
}
''')
ed('net/netfilter/xt_CHECKSUM.c','''#include <linux/netfilter_ipv6/ip6_tables.h>
''','''#include <linux/netfilter_ipv6/ip6_tables.h>
#include <net/ip.h>
''')
ed('net/netfilter/xt_CHECKSUM.c','''	if (skb->ip_summed == CHECKSUM_PARTIAL && !skb_is_gso(skb))
		skb_checksum_help(skb);
''','''	if (skb->ip_summed == CHECKSUM_PARTIAL && !skb_is_gso(skb)) {
		if (xt_family(par) == NFPROTO_IPV4 && ip_check_csum_start(skb))
			return NF_DROP;
		skb_checksum_help(skb);
	}
''')
q='net/netfilter/nfnetlink_queue.c'
ed(q,'''#include <net/sock.h>
''','''#include <net/ip.h>
#include <net/sock.h>
''')
def prereq():
    # 26a77d02891a "netfilter: nfnetlink_queue: unbreak SCTP traffic", which
    # AlmaLinux applies before the fix (its Patch1100) and which adds
    # nf_queue_checksum_help().
    d='net/core/dev.c'
    s=open(root+'/'+d).read()
    if 'EXPORT_SYMBOL(skb_crc32c_csum_help);' not in s:
        i=s.index('int skb_crc32c_csum_help(struct sk_buff *skb)\n{')
        j=s.index('\n}\n',i)+3
        open(root+'/'+d,'w').write(s[:j]+'EXPORT_SYMBOL(skb_crc32c_csum_help);\n'+s[j:])
    # skb_csum_is_sctp() is missing before 8.5; in EL8 it is just
    # "return skb->csum_not_inet;", so use the field directly there.
    if 'skb_csum_is_sctp' in open(root+'/include/linux/skbuff.h').read():
        sctp='skb_csum_is_sctp(entskb)'
    else:
        sctp='entskb->csum_not_inet'
    old_call = """		    entskb->ip_summed == CHECKSUM_PARTIAL &&
		    skb_checksum_help(entskb))
"""
    ed(q, old_call, old_call.replace('skb_checksum_help(entskb)', 'nf_queue_checksum_help(entskb)'))
    ed(q, """	if ((queue->flags & NFQA_CFG_F_GSO) || !skb_is_gso(skb))
""", """	if (!skb_is_gso(skb) || ((queue->flags & NFQA_CFG_F_GSO) && !skb_is_gso_sctp(skb)))
""")
    s=open(root+'/'+q).read()
    i=s.index('static struct sk_buff *\nnfqnl_build_packet_message')
    s=s[:i]+"""static int nf_queue_checksum_help(struct sk_buff *entskb)
{
	if (%s)
		return skb_crc32c_csum_help(entskb);

	return skb_checksum_help(entskb);
}

""" % sctp + s[i:]
    open(root+'/'+q,'w').write(s)

if 'static int nf_queue_checksum_help(' not in open(root+'/'+q).read():
    prereq()
ed(q,"""static int nf_queue_checksum_help(struct sk_buff *entskb)
{
""","""static int nf_queue_checksum_help(struct sk_buff *entskb)
{
	if (entskb->protocol == htons(ETH_P_IP)) {
		if (!pskb_network_may_pull(entskb, sizeof(struct iphdr)) ||
		    ip_check_csum_start(entskb))
			return -EINVAL;
	}

""")
