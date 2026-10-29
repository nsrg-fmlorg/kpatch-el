"""Give a 10.0/10.1 include/asm-generic/vmlinux.lds.h the section macros of 10.2.

usage: klp-overlay-lds.py <target-vmlinux.lds.h> <10.2-vmlinux.lds.h>

klp-build compiles with -ffunction-sections -fdata-sections.  10.0 and
10.1 only put .text.* and friends into .text when dead-code elimination
or LTO is on, so their link fails with tens of thousands of "unplaced
orphan section" errors (10.1: `.text.cc_mkdec' and on).  10.2 got
"vmlinux.lds: Unify TEXT_MAIN, DATA_MAIN, and related macros" and
"Exclude .text.startup and .text.exit from TEXT_MAIN" through the same
MR as klp-build.  This replaces the TEXT_MAIN ... SBSS_MAIN definitions
with 10.2's.  Without -ffunction-sections the patterns match exactly
what the old ones did, so only klp-build's own rebuild is affected.
"""
import re
import sys

dst, src = sys.argv[1], sys.argv[2]
s = open(dst).read()
d = open(src).read()

# 10.2: from the comment that introduces TEXT_MAIN to the SBSS_MAIN line.
i = d.index('#define TEXT_MAIN')
i = d.rindex('/*', 0, i)
j = d.index('#define SBSS_MAIN')
j = d.index('\n', j) + 1
new = d[i:j]

# 10.0/10.1: the #if ... #endif blocks that define TEXT_MAIN ... SBSS_MAIN.
k = s.index('#define TEXT_MAIN')
a = s.rindex('#if ', 0, k)
b = s.index('#define SBSS_MAIN .sbss\n#endif\n', k)
b = b + len('#define SBSS_MAIN .sbss\n#endif\n')
old = s[a:b]
assert old.count('#define TEXT_MAIN') == 2 and old.count('#define SBSS_MAIN') == 2, old

s = s[:a] + new + s[b:]

# The new TEXT_MAIN leaves .text.startup.* and .text.exit.* to INIT_TEXT
# and EXIT_TEXT, which in 10.2 match them and in 10.0/10.1 do not.
for old, rep in [('\t*(.text.startup)\n', '\t*(.text.startup .text.startup.*)\n'),
                 ('\t*(.text.exit)\t', '\t*(.text.exit .text.exit.*)\t')]:
    if rep.strip() not in s:
        assert s.count(old) == 1, old
        s = s.replace(old, rep)

open(dst, 'w').write(s)
