#!/bin/bash
# Give a 10.0 or 10.1 kernel tree the klp-build tooling of a 10.2 tree.
# usage: klp-overlay.sh <target-tree> <10.2-tree>
#
# 10.2 got klp-build through CentOS Stream 10 MR 1964 (RHEL-114916, 85
# commits).  The MR does not apply to 10.0 or 10.1: it depends on other
# 10.2 changes and fails on the first and third commit respectively.
#
# Only the build tooling is taken: tools/ (objtool and what it builds
# against), scripts/livepatch/, the livepatch headers the generated module
# includes, and the linker-script support for -ffunction-sections that
# klp-build compiles with (scripts/module.lds.S, and the section macros in
# vmlinux.lds.h, see klp-overlay-lds.py).  No C code of the kernel is
# changed, so the objects klp-build compares are those of the target
# kernel.  The MR's other kernel-side changes (__UNIQUE_ID() naming, ELF
# notes) are deliberately not taken: they would change symbol names away
# from the running kernel's.  The runtime ABI the module relies on
# (.klp.sym/.klp.rela naming, klp_enable_patch()) is unchanged by the MR.
#
# CONFIG_KLP_BUILD only changes when objtool runs and what link-vmlinux.sh
# links (scripts/Makefile.lib, scripts/link-vmlinux.sh), and both already
# behave that way under CONFIG_X86_KERNEL_IBT, which 10.0 and 10.1 enable.
# So the option is added to Kconfig without changing the kernel built.
set -euo pipefail

dst=$1
src=$2
split=${3:-}	# --split-objtool: see tools/klp-overlay/objtool-split

[ -e "$dst/scripts/livepatch/klp-build" ] && { echo "already has klp-build"; exit 0; }
grep -q '^CONFIG_X86_KERNEL_IBT=y' "$dst/.config" ||
	{ echo "CONFIG_X86_KERNEL_IBT is not set; the reasoning above does not hold"; exit 1; }

# The target's own objtool, built before its tools/ is replaced.  It
# gets one upstream fix, 69d41d6dafff "objtool: Fix segfault in
# ignore_unreachable_insn()": 10.0's objtool dereferenced a NULL
# prev_insn when an unreachable instruction opened its section, which
# with klp-build's -ffunction-sections happens on vmlinux.o (gdb:
# ignore_unreachable_insn, check.c:4181).  10.1 already has it.  It only
# guards a warning check and changes nothing objtool writes.
if [ "$split" = --split-objtool ]; then
	if ! grep -q 'if (prev_insn && prev_insn->dead_end &&' "$dst/tools/objtool/check.c"; then
		patch -d "$dst" -p1 -f -s --no-backup-if-mismatch \
			< "$(dirname "$0")/klp-overlay/objtool-fix-segfault-ignore_unreachable_insn.diff"
	fi
	make -s -C "$dst/tools/objtool" -j"$(nproc)"
	mkdir -p "$dst/.objtool-split"
	cp "$dst/tools/objtool/objtool" "$dst/.objtool-split/objtool-target"
fi

# tools/ is taken whole, except the BPF parts, which the kernel build uses
# for resolve_btfids and objtool does not: 10.0's scripts/bpf_doc.py could
# not parse 10.2's tools/include/uapi/linux/bpf.h ("The number of unique
# helper in description (8) doesn't match ... (211)").  Those keep the
# target's versions.
keep=$(mktemp -d)
for d in include/uapi lib/bpf bpf; do
	mkdir -p "$keep/$(dirname "$d")"
	cp -a "$dst/tools/$d" "$keep/$d"
done
rm -rf "$dst/tools"
cp -a "$src/tools" "$dst/tools"
for d in include/uapi lib/bpf bpf; do
	rm -rf "$dst/tools/$d"
	cp -a "$keep/$d" "$dst/tools/$d"
done
rm -rf "$keep"
mkdir -p "$dst/scripts/livepatch"
cp -a "$src/scripts/livepatch/." "$dst/scripts/livepatch/"
for h in livepatch.h livepatch_external.h livepatch_helpers.h; do
	cp -a "$src/include/linux/$h" "$dst/include/linux/$h"
done
# 10.2 moved struct klp_callbacks into livepatch_external.h and spelled
# its members with typedefs.  The layout is the same, but modversions
# hashes the spelling, so klp_enable_patch() got a CRC the 10.0/10.1
# kernels do not have, and 10.1 refused the module: "disagrees about
# version of symbol klp_enable_patch".  Spell the members as 10.0/10.1
# do; the typedefs stay for livepatch_helpers.h.  klpsymcheck.py compares
# every CRC with the shipped Module.symvers.
python3 -I - "$dst/include/linux/livepatch_external.h" <<'EOF'
import sys
p = sys.argv[1]
s = open(p).read()
old = """struct klp_callbacks {
	klp_pre_patch_t		pre_patch;
	klp_post_patch_t	post_patch;
	klp_pre_unpatch_t	pre_unpatch;
	klp_post_unpatch_t	post_unpatch;
	bool post_unpatch_enabled;
};"""
new = """struct klp_callbacks {
	int (*pre_patch)(struct klp_object *obj);
	void (*post_patch)(struct klp_object *obj);
	void (*pre_unpatch)(struct klp_object *obj);
	void (*post_unpatch)(struct klp_object *obj);
	bool post_unpatch_enabled;
};"""
assert s.count(old) == 1, "struct klp_callbacks not as expected"
open(p, "w").write(s.replace(old, new))
EOF
# The generated module needs __klp_funcs/__klp_objects placed (its init
# code walks them) and .text.* merged.  10.1 takes 10.2's module linker
# script whole.  10.0's codetag.lds.h lacks MOD_SEPARATE_CODETAG_SECTIONS(),
# which that script uses ("ld:scripts/module.lds:39: syntax error"), so
# 10.0 keeps its own script and gets just those entries, as 10.2 writes
# them.
if grep -q 'MOD_SEPARATE_CODETAG_SECTIONS' "$dst/include/asm-generic/codetag.lds.h"; then
	cp -a "$src/scripts/module.lds.S" "$dst/scripts/module.lds.S"
else
	python3 -I - "$dst/scripts/module.lds.S" <<'EOF'
import sys
p = sys.argv[1]
s = open(p).read()
anchor = "\t__patchable_function_entries : { *(__patchable_function_entries) }\n"
assert s.count(anchor) == 1, "module.lds.S not as expected"
add = """
	__klp_funcs		0: ALIGN(8) { KEEP(*(__klp_funcs)) }

	__klp_objects		0: ALIGN(8) {
		__start_klp_objects = .;
		KEEP(*(__klp_objects))
		__stop_klp_objects = .;
	}

	.text : {
		*(.text .text.[0-9a-zA-Z_]*)
	}
"""
open(p, "w").write(s.replace(anchor, anchor + add))
EOF
fi
python3 -I "$(dirname "$0")/klp-overlay-lds.py" \
	"$dst/include/asm-generic/vmlinux.lds.h" "$src/include/asm-generic/vmlinux.lds.h"

# The generated module refers to __start_klp_objects/__stop_klp_objects,
# which module.lds.S defines at link time; modpost runs before that and
# rejected them as undefined on 10.1.  The MR's "modpost: Ignore
# unresolved section bounds symbols", applied as is.
patch -d "$dst" -p1 -f -s --no-backup-if-mismatch \
	< "$(dirname "$0")/klp-overlay/modpost-ignore-section-bounds.diff"

# The MR renamed objtool's --Werror to --werror; 10.1's kbuild still
# passes the old spelling (10.0 passes neither).  Only the option name
# changes.
sed -i 's/--Werror$/--werror/' "$dst/scripts/Makefile.lib" "$dst/scripts/Makefile.vmlinux_o"

if ! grep -q 'config KLP_BUILD' "$dst/kernel/livepatch/Kconfig"; then
	cat >> "$dst/kernel/livepatch/Kconfig" <<'EOF'

config HAVE_KLP_BUILD
	bool
	help
	  Arch supports klp-build

config KLP_BUILD
	def_bool y
	depends on LIVEPATCH && HAVE_KLP_BUILD
	select OBJTOOL
	help
	  Enable klp-build support
EOF
	sed -i 's/^\(\tselect HAVE_LIVEPATCH\t*if X86_64\)$/\1\n\tselect HAVE_KLP_BUILD\t\t\tif X86_64/' \
		"$dst/arch/x86/Kconfig"
	grep -q 'select HAVE_KLP_BUILD' "$dst/arch/x86/Kconfig" ||
		{ echo "could not add HAVE_KLP_BUILD to arch/x86/Kconfig"; exit 1; }
fi
if [ "$split" = --split-objtool ]; then
	# This objtool only adds checksums and runs klp-build's subcommands.
	# 10.0 records annotations in per-type sections, which 10.2's objtool
	# no longer reads; it then stopped on ftrace_regs_caller ("unannotated
	# intra-function call") and vmlinux.o got no checksums.  Teach it the
	# old sections (objtool-read-old-annotations.diff).
	patch -d "$dst" -p1 -f -s --no-backup-if-mismatch \
		< "$(dirname "$0")/klp-overlay/objtool-read-old-annotations.diff"
	make -s -C "$dst/tools/objtool" -j"$(nproc)"
	cp "$dst/tools/objtool/objtool" "$dst/.objtool-split/objtool-klp"
	install -m 755 "$(dirname "$0")/klp-overlay/objtool-split" "$dst/.objtool-split/objtool"
	# kbuild runs $(objtool) from scripts/Makefile.lib; klp-build calls
	# tools/objtool/objtool (10.2's, rebuilt by kbuild) for its klp
	# subcommands itself.
	sed -i 's|^objtool := $(objtree)/tools/objtool/objtool$|objtool := $(objtree)/.objtool-split/objtool|' \
		"$dst/scripts/Makefile.lib"
	grep -q '^objtool := $(objtree)/.objtool-split/objtool$' "$dst/scripts/Makefile.lib" ||
		{ echo "could not point scripts/Makefile.lib at the objtool switch"; exit 1; }
	# Not "--help | grep -q": with pipefail, grep stopping early fails the pipe.
	help=$("$dst/.objtool-split/objtool-klp" --help 2>&1 || true)
	[[ "$help" == *--checksum* ]] ||
		{ echo "10.2 objtool built without --checksum (xxhash missing?)"; exit 1; }
	echo "objtool split: target objtool for the kernel, 10.2 objtool for klp"
fi
echo "klp-build tooling taken from $src"
