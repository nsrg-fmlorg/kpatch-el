"""Open TCP connections that are all completed through SYN cookies.

usage: syncookie.py [<count>]

Runs inside the test VM as root with the livepatch applied.  With
net.ipv4.tcp_syncookies=2 every SYN is answered with a cookie, so each
connection is created by cookie_v4_check() / cookie_v6_check() through
tcp_get_cookie_sock(), and is then found again by the established-hash
lookups (__inet_lookup_established(), __inet6_lookup_established()):
the functions CVE-2026-99288's fix changes.  Over 127.0.0.1 and ::1,
each connection sends a line and reads it back.  The sysctl is restored
afterwards.

Prints "syncookie: v4=<ok>/<n> v6=<ok>/<n> cookies_recv=<d>" and exits 0
when every connection completed and TcpExt SyncookiesRecv grew by at
least the number made.
"""
import os
import socket
import sys
import threading

SYSCTL = '/proc/sys/net/ipv4/tcp_syncookies'


def cookies_recv():
    lines = open('/proc/net/netstat').read().split('\n')
    for i in range(0, len(lines) - 1, 2):
        if lines[i].startswith('TcpExt:'):
            k = lines[i].split()[1:]
            v = lines[i + 1].split()[1:]
            return int(dict(zip(k, v))['SyncookiesRecv'])
    raise SystemExit('no TcpExt in /proc/net/netstat')


def serve(ls, n):
    for _ in range(n):
        c, _ = ls.accept()
        with c:
            d = c.recv(64)
            c.sendall(d)


def round_trips(family, addr, n):
    ls = socket.socket(family, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind((addr, 0))
    ls.listen(16)
    port = ls.getsockname()[1]
    t = threading.Thread(target=serve, args=(ls, n))
    t.daemon = True
    t.start()
    ok = 0
    for i in range(n):
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(5)
        try:
            s.connect((addr, port))
            msg = ('%d\n' % i).encode()
            s.sendall(msg)
            if s.recv(64) == msg:
                ok += 1
        except OSError as e:
            print('syncookie: %s connection %d: %s' % (addr, i, e))
        finally:
            s.close()
    t.join(10)
    ls.close()
    return ok


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 200
    old = open(SYSCTL).read().strip()
    before = cookies_recv()
    try:
        with open(SYSCTL, 'w') as f:
            f.write('2')
        v4 = round_trips(socket.AF_INET, '127.0.0.1', n)
        v6 = round_trips(socket.AF_INET6, '::1', n)
    finally:
        with open(SYSCTL, 'w') as f:
            f.write(old)
    d = cookies_recv() - before
    print('syncookie: v4=%d/%d v6=%d/%d cookies_recv=%d' % (v4, n, v6, n, d))
    return 0 if v4 == n and v6 == n and d >= 2 * n else 1


if __name__ == '__main__':
    sys.exit(main())
