#!/bin/sh
# Run as root in the test VM before it reboots into the kernel under
# test: what GRUB will read on the next boot.  Rocky 8.6 stopped in the
# GRUB menu with no countdown, the removed 553.el8_10 entry still listed
# and highlighted, although grubby named 372.9.1 the default.
grub2-editenv list
ls -l /boot/vmlinuz-*
for f in /boot/loader/entries/*; do
	echo "== $f"
	cat "$f"
done
echo "== /etc/default/grub"
cat /etc/default/grub
echo "== /boot/grub2/grub.cfg (timeout, menu, blscfg, default)"
grep -n 'timeout\|menu_\|blscfg\|default' /boot/grub2/grub.cfg | head -60
