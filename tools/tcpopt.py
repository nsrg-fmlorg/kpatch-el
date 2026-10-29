"""Drive the two frees CVE-2026-98432 changes, with options present.

usage: tcpopt.py <rounds>   (as root, inside the test VM)

inet_opt and ireq_opt are NULL unless a SYN carried IP options, so plain
traffic never reaches the kfree()/kfree_rcu() this livepatch replaces.

- Connections over loopback from a socket with IP_OPTIONS set (NOP NOP
  NOP EOL): the listener saves the SYN's options as ireq_opt
  (tcp_v4_save_options()) and hands them to the child as inet_opt, which
  inet_sock_destruct() frees when the child closes.
- Bare SYNs with the same options from a raw socket: the listener keeps
  ireq_opt on a request socket and answers SYN-ACK, the kernel resets it
  (no socket of ours owns the port), and tcp_v4_reqsk_destructor() frees
  ireq_opt.

This exercises the patched paths; it does not reproduce the race (a
retransmitted SYN against a child being freed on another CPU), which
needs KASAN to be seen.  Prints one summary line; exits 1 on an error.
Python 3.6 (EL8's platform-python): no f-strings.
"""
import random
import socket
import struct
import sys
import threading
import time

ROUNDS = int(sys.argv[1]) if len(sys.argv) > 1 else 2000
OPTS = b'\x01\x01\x01\x00'          # NOP NOP NOP EOL: 4 bytes, optlen 4
errors = []


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def syn(src, dst, sport, dport):
    tcp = struct.pack('!HHLLBBHHH', sport, dport, random.getrandbits(32), 0,
                      5 << 4, 0x02, 65535, 0, 0)
    pseudo = struct.pack('!4s4sBBH', socket.inet_aton(src), socket.inet_aton(dst),
                         0, socket.IPPROTO_TCP, len(tcp))
    tcp = tcp[:16] + struct.pack('!H', csum(pseudo + tcp)) + tcp[18:]
    ihl = (20 + len(OPTS)) // 4
    ip = struct.pack('!BBHHHBBH4s4s', (4 << 4) | ihl, 0, ihl * 4 + len(tcp),
                     random.getrandbits(16), 0, 64, socket.IPPROTO_TCP, 0,
                     socket.inet_aton(src), socket.inet_aton(dst)) + OPTS
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return ip + tcp


def server(ls, n):
    try:
        for _ in range(n):
            c, _ = ls.accept()
            c.recv(16)
            c.close()
    except Exception as e:
        errors.append('server: %r' % e)


def main():
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(('127.0.0.1', 0))
    ls.listen(256)
    port = ls.getsockname()[1]
    t = threading.Thread(target=server, args=(ls, ROUNDS))
    t.start()
    full = 0
    for _ in range(ROUNDS):
        c = socket.socket()
        c.setsockopt(socket.IPPROTO_IP, socket.IP_OPTIONS, OPTS)
        try:
            c.connect(('127.0.0.1', port))
            c.sendall(b'x')
            full += 1
        except Exception as e:
            errors.append('client: %r' % e)
            break
        finally:
            c.close()
    t.join(60)
    if t.is_alive():
        errors.append('server did not finish')

    raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    raw.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    bare = 0
    for _ in range(ROUNDS):
        sport = random.randint(20000, 60000)
        raw.sendto(syn('127.0.0.1', '127.0.0.1', sport, port), ('127.0.0.1', 0))
        bare += 1
    # Let the SYN-ACKs be reset and the request sockets go.
    time.sleep(2)
    raw.close()
    ls.close()
    print('TCPOPT: connections=%d bare_syns=%d errors=%d' % (full, bare, len(errors)))
    for e in errors[:5]:
        print('  ' + e)
    return 1 if errors else 0


sys.exit(main())
