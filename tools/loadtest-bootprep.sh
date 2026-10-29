#!/bin/sh
# Run as root in the test VM after the other kernels are removed: delete
# every boot entry whose kernel image is gone.
#
# On Rocky 8.4 to 8.9 the VM stopped in the GRUB menu.  The image's
# 4.18.0-553.el8_10 entry outlived its kernel: it is filed under the
# image's machine id (5dedb...), and removing kernel-core left it while
# the kernel's files went.  The screen showed that entry highlighted,
# with no countdown.  The rest is inferred, not read from GRUB or the
# scriptlets: removal only looks under the current machine id; GRUB,
# sorting entries newest first, did not match saved_entry (a file name)
# with the entries' "id" lines, took the first, failed on the missing
# vmlinuz and returned to a menu that then waits.  8.10's 553.144.1
# booted, consistent with that, because it sorts above 553.
for f in /boot/loader/entries/*.conf; do
	k=$(awk '$1 == "linux" { print $2; exit }' "$f")
	if [ -n "$k" ] && [ ! -e "/boot$k" ]; then
		echo "removing $f (no /boot$k)"
		rm -f "$f"
	fi
done
