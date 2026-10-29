#!/bin/bash
# Probe CVE-2026-99999 through the TAP -> forward -> ip_do_fragment() path
# and print whether this kernel is vulnerable right now.  Run it before
# and after the livepatch to see the change.  Prints one line:
#
#   CSUM <label>: bad=<vulnerable|fixed|rejected|unknown> control=<frag|nofrag>
#
# A frame is injected into a tap with a virtio_net_hdr whose csum_start
# points into the IP header.  It is addressed to an off-link host, so the
# kernel forwards it; it is larger than the egress MTU, so ip_do_fragment()
# runs.  There the fix's ip_check_csum_start() either drops it or, without
# the fix, skb_checksum_help() runs and corrupts the header.
#
#   bad=vulnerable  IpFragCreates rose: the frame was fragmented, i.e.
#                   skb_checksum_help() ran on it (pre-fix behaviour).
#   bad=fixed       IpFragFails rose: ip_do_fragment() rejected it.
#   bad=rejected    the tap write was refused in virtio_net_hdr_to_skb()
#                   (a newer kernel's own bound on csum_start); the frame
#                   never reached the fix's sink on this kernel.
#   control=frag    a well-formed oversized frame (csum_start past the IP
#                   header) still fragments, so the path itself works.
#
# Needs iproute2 and python3; no iptables and no extra module, so it runs
# the same on EL8, EL9 and EL10.  Everything it makes is named klp* and
# removed on exit.  usage: csum-probe.sh <label>
set -u
label=${1:-probe}
here=$(cd "$(dirname "$0")" && pwd)
TAP=klptap0
SRC=10.77.0.9 DST=203.0.113.9   # DST is off-link: forwarded, not local

# The minimal EL8 cloud image carries no python3 on PATH, only
# /usr/libexec/platform-python (3.6); EL9 and EL10 have python3.
PY=python3
command -v "$PY" >/dev/null 2>&1 || PY=platform-python
command -v "$PY" >/dev/null 2>&1 || PY=/usr/libexec/platform-python
[ -x "$(command -v "$PY" 2>/dev/null)" ] || { echo "CSUM $label: bad=unknown control=unknown (no python)"; exit 0; }

cleanup() { ip link del "$TAP" 2>/dev/null; }
trap cleanup EXIT

# A persistent tap with the vnet_hdr flag, so the injector's writes are
# read with a virtio_net_hdr in front.
ip tuntap add dev "$TAP" mode tap vnet_hdr 2>/dev/null || {
	echo "CSUM $label: bad=unknown control=unknown (tap vnet_hdr unavailable)"; exit 0; }
ip link set "$TAP" mtu 3000 up
ip addr add 10.77.0.1/24 dev "$TAP"
# Forward the injected packet out the default route, and do not let
# reverse-path filtering drop its made-up source.  /proc/sys, not
# sysctl, which the minimal cloud image may not carry.
echo 1 > /proc/sys/net/ipv4/ip_forward
echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter
echo 0 > "/proc/sys/net/ipv4/conf/$TAP/rp_filter"
dmac=$(cat "/sys/class/net/$TAP/address")

# IpFragFails and IpFragCreates from /proc/net/snmp, by column name.
frag() {
	awk '/^Ip:/ { if (h=="") { for (i=1;i<=NF;i++) c[$i]=i; h=$0 }
	      else { print $c["FragFails"], $c["FragCreates"] } }' /proc/net/snmp
}
inject() { # <csum-start> -> echoes the injector's exit status
	"$PY" -I "$here/csum-inject.py" --dev "$TAP" --dmac "$dmac" \
		--src "$SRC" --dst "$DST" --csum-start "$1" --size 2800
	echo $?
}

read -r f0 c0 < <(frag)
rc=$(inject 14); sleep 1     # csum_start inside the IP header: the attack
read -r f1 c1 < <(frag)
inject 34 >/dev/null; sleep 1   # csum_start past the IP header: a control
read -r f2 c2 < <(frag)

bad=unknown
if   [ "$rc" = 2 ];            then bad=rejected
elif [ "$c1" -gt "$c0" ];      then bad=vulnerable
elif [ "$f1" -gt "$f0" ];      then bad=fixed
fi
control=nofrag
[ "$c2" -gt "$c1" ] && control=frag

echo "CSUM $label: bad=$bad control=$control" \
     "(FragFails $f0->$f1->$f2, FragCreates $c0->$c1->$c2)"
