#!/usr/bin/env python3
"""Port KernelSU-Next policydb.len fix to BakaSU's main kernel sources.

Run from the kernel-source root:
    python3 path/to/patch_bakasu_policydb_len.py KernelSU

This is a narrowly scoped source patcher, not a kernel runtime repair.
Refuses to modify unfamiliar sources. Review the resulting git diff before use.
"""
import argparse
import os
import re
from pathlib import Path

HELPER = r'''
#define KSU_SEPOL_SYNC_MAX_BUF   SZ_64M
#define KSU_SEPOL_SYNC_SLACK     SZ_256K
#define KSU_SEPOL_SYNC_MAX_TRIES 4

/*
 * The serialized size can grow after KernelSU changes policydb.
 * selinuxfs uses policydb.len to size its policy-read buffer.
 * Recalculate the length before making the updated policy visible.
 */
static int ksu_policydb_sync_len(struct policydb *db, const char *tag)
{
    const size_t tracked = db->len;
    unsigned int attempt = 0;
    size_t cap;
    int ret = -EINVAL;

    if (tracked > KSU_SEPOL_SYNC_MAX_BUF - KSU_SEPOL_SYNC_SLACK) {
        pr_err("sepolicy: [%s] policydb.len %zu is too large to measure\n",
               tag, tracked);
        return -E2BIG;
    }

    cap = tracked + KSU_SEPOL_SYNC_SLACK;

    while (attempt < KSU_SEPOL_SYNC_MAX_TRIES && cap <= KSU_SEPOL_SYNC_MAX_BUF) {
        struct policy_file fp;
        size_t remaining;
        void *buf = vmalloc(cap);

        if (!buf) {
            pr_err("sepolicy: [%s] vmalloc(%zu) failed\n", tag, cap);
            return -ENOMEM;
        }

        attempt++;
        fp.data = buf;
        fp.len = cap;
        ret = policydb_write(db, &fp);
        remaining = fp.len;
        vfree(buf);

        if (!ret) {
            const size_t actual = cap - remaining;

            pr_debug("sepolicy: [%s] len tracked=%zu actual=%zu attempts=%u buf=%zu\n",
                     tag, tracked, actual, attempt, cap);
            db->len = actual;
            return 0;
        }

        if (ret != -EINVAL) {
            pr_err("sepolicy: [%s] policydb_write failed: %d\n", tag, ret);
            return ret;
        }

        if (cap > KSU_SEPOL_SYNC_MAX_BUF / 2)
            break;
        cap *= 2;
    }

    pr_err("sepolicy: [%s] giving up after %u attempts (tracked=%zu): %d\n",
           tag, attempt, tracked, ret);
    return ret;
}

/* Matches KernelSU-Next's best-effort fallback strategy. */
int ksu_policydb_fixup_len(struct policydb *db, const char *tag)
{
    int ret = ksu_policydb_sync_len(db, tag);

    if (ret) {
        db->len += KSU_SEPOL_SYNC_SLACK;
        pr_warn("sepolicy: [%s] could not measure policydb (%d), padded policydb.len to %zu\n",
                tag, ret, (size_t)db->len);
    }
    return ret;
}

'''


def unique_replace(haystack, needle, replacement, label):
    n = haystack.count(needle)
    if n != 1:
        raise ValueError(f"{label}: expected one anchor, found {n}")
    return haystack.replace(needle, replacement, 1)



def upstream_verified(original, sp, sh, rules):
    """Skip only a complete known upstream fix. Unknown changes fail closed."""
    code, header, publish = (original[p] for p in (sp, sh, rules))
    names = ("ksu_policydb_sync_len", "ksu_policydb_fixup_len")
    present = any(name in data for data in original.values() for name in names)
    if not present:
        # A differently named helper immediately before publication is suspicious.
        for m in re.finditer(r"\brcu_assign_pointer\s*\(\s*selinux_state\.policy\s*,\s*pol\s*\)", publish):
            prior = publish[max(0, m.start()-240):m.start()]
            if re.search(r"\b\w*(?:policy|sepol|len|size|sync|fixup)\w*\s*\([^;\n]*\)\s*;\s*$", prior):
                raise ValueError("Possible upstream policy-size helper with another name")
        return False

    def body(name):
        pat = r"\b(?:static\s+)?int\s+" + name + r"\s*\([^;{}]*\)\s*\{"
        defs = list(re.finditer(pat, code))
        if len(defs) != 1:
            raise ValueError(f"Upstream {name}: expected one definition, got {len(defs)}")
        start = defs[0].end()-1
        depth = 0
        for i in range(start, len(code)):
            if code[i] == "{":
                depth += 1
            elif code[i] == "}":
                depth -= 1
                if depth == 0:
                    return code[start+1:i]
        raise ValueError(f"Unterminated {name}")

    sync = body("ksu_policydb_sync_len")
    fixup = body("ksu_policydb_fixup_len")
    checks = [
        (r"\bpolicydb_write\s*\(\s*db\s*,\s*&fp\s*\)", sync),
        (r"\bdb\s*->\s*len\s*=\s*actual\s*;", sync),
        (r"\bksu_policydb_sync_len\s*\(\s*db\s*,\s*tag\s*\)", fixup),
        (r"\bdb\s*->\s*len\s*\+=\s*KSU_SEPOL_SYNC_SLACK\s*;", fixup),
        (r"\bint\s+ksu_policydb_fixup_len\s*\(", header),
    ]
    if not all(re.search(pattern, content) for pattern, content in checks):
        raise ValueError("Upstream fix is incomplete or differs from verified implementation")

    pubs = list(re.finditer(r"\brcu_assign_pointer\s*\(\s*selinux_state\.policy\s*,\s*pol\s*\)", publish))
    calls = list(re.finditer(r"\bksu_policydb_fixup_len\s*\(", publish))
    if len(pubs) != 2 or len(calls) != 2:
        raise ValueError(f"Upstream fix topology differs: {len(pubs)} publications, {len(calls)} calls")
    for p in pubs:
        prefix = publish[max(0,p.start()-240):p.start()]
        if not re.search(
            r"(?:\(\s*void\s*\)\s*)?ksu_policydb_fixup_len\s*\(\s*"
            r"(?:db|&\s*pol\s*->\s*policydb)\s*,\s*" + r'"[^"\n]+"\s*\)\s*;\s*    sp = root / 'kernel/selinux/sepolicy.c'
    sh = root / 'kernel/selinux/sepolicy.h'
    rules = root / 'kernel/selinux/rules.c'
    original = {p: p.read_text() for p in (sp, sh, rules)}

    if upstream_verified(original, sp, sh, rules):
        return "SKIPPED_UPSTREAM"

    a = original[sp]
    a = unique_replace(a, '#include <linux/vmalloc.h>\n',
                       '#include <linux/vmalloc.h>\n#include <linux/sizes.h>\n', 'sepolicy.c include')
    anchor = '#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0) || defined(KSU_COMPAT_HAS_POLICY_MUTEX)\n// 5.10+ using selinux_policy\n'
    a = unique_replace(a, anchor, HELPER + anchor, 'sepolicy.c insertion')

    b = original[sh]
    anchor = 'void ksu_destroy_sepolicy(struct selinux_policy *orig);\n'
    b = unique_replace(b, anchor,
                       anchor + 'int ksu_policydb_fixup_len(struct policydb *db, const char *tag);\n',
                       'sepolicy.h declaration')

    c = original[rules]
    anchor = '    rcu_assign_pointer(selinux_state.policy, pol);\n'
    if c.count(anchor) != 2:
        raise ValueError(f'rules.c: expected two publications, found {c.count(anchor)}')
    c = c.replace(anchor, '    (void)ksu_policydb_fixup_len(&pol->policydb, "apply_kernelsu_rules");\n'+anchor, 1)
    # Replace the second occurrence, never the first already patched block.
    pos = c.find(anchor)
    pos2 = c.find(anchor, pos + len(anchor))
    if pos2 < 0:
        raise ValueError('rules.c: second policy publication missing')
    c = c[:pos2] + '    (void)ksu_policydb_fixup_len(&pol->policydb, "handle_sepolicy");\n' + c[pos2:]

    patched = {sp: a, sh: b, rules: c}
    if not check_only:
        for p, txt in patched.items():
            p.write_text(txt)
    for p in patched:
        print(f'{"Verified" if check_only else "Patched"}: {p}')

    return "CHECKED_PATCHABLE" if check_only else "APPLIED"

if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('root', type=Path, help='Directory containing BakaSU kernel/selinux')
    ap.add_argument('--check', action='store_true', help='Only check patch anchors')
    opts = ap.parse_args()
    try:
        status = patch(opts.root, opts.check)
    except (OSError, ValueError) as exc:
        report("FAILED", str(exc))
        raise SystemExit(1) from exc
    report(status, {
        "APPLIED": "Compatibility patch inserted at both policy publications.",
        "SKIPPED_UPSTREAM": "Existing complete upstream fix verified; no patch needed.",
        "CHECKED_PATCHABLE": "Source is patchable; no changes made (--check).",
    }[status])
,
            prefix,
        ):
            raise ValueError("Missing upstream fixup directly before policy publication")
    return True


def report(status, explanation):
    msg = f"BakaSU policydb.len: {status} - {explanation}"
    print(msg, flush=True)
    if os.getenv("GITHUB_ACTIONS") == "true":
        level = "error" if status == "FAILED" else "notice"
        msg_escaped = msg.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        print(f"::{level} title=BakaSU policydb.len::{msg_escaped}", flush=True)
    if os.getenv("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as f:
            f.write(f"status={status}\n")
    if os.getenv("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write(f"### ReSukiSU SELinux policy serialization\n\n**{status}** — {explanation}\n\n")


def patch(root, check_only=False):
    sp = root / 'kernel/selinux/sepolicy.c'
    sh = root / 'kernel/selinux/sepolicy.h'
    rules = root / 'kernel/selinux/rules.c'
    original = {p: p.read_text() for p in (sp, sh, rules)}

    if upstream_verified(original, sp, sh, rules):
        return "SKIPPED_UPSTREAM"

    a = original[sp]
    a = unique_replace(a, '#include <linux/vmalloc.h>\n',
                       '#include <linux/vmalloc.h>\n#include <linux/sizes.h>\n', 'sepolicy.c include')
    anchor = '#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0) || defined(KSU_COMPAT_HAS_POLICY_MUTEX)\n// 5.10+ using selinux_policy\n'
    a = unique_replace(a, anchor, HELPER + anchor, 'sepolicy.c insertion')

    b = original[sh]
    anchor = 'void ksu_destroy_sepolicy(struct selinux_policy *orig);\n'
    b = unique_replace(b, anchor,
                       anchor + 'int ksu_policydb_fixup_len(struct policydb *db, const char *tag);\n',
                       'sepolicy.h declaration')

    c = original[rules]
    anchor = '    rcu_assign_pointer(selinux_state.policy, pol);\n'
    if c.count(anchor) != 2:
        raise ValueError(f'rules.c: expected two publications, found {c.count(anchor)}')
    c = c.replace(anchor, '    (void)ksu_policydb_fixup_len(&pol->policydb, "apply_kernelsu_rules");\n'+anchor, 1)
    # Replace the second occurrence, never the first already patched block.
    pos = c.find(anchor)
    pos2 = c.find(anchor, pos + len(anchor))
    if pos2 < 0:
        raise ValueError('rules.c: second policy publication missing')
    c = c[:pos2] + '    (void)ksu_policydb_fixup_len(&pol->policydb, "handle_sepolicy");\n' + c[pos2:]

    patched = {sp: a, sh: b, rules: c}
    if not check_only:
        for p, txt in patched.items():
            p.write_text(txt)
    for p in patched:
        print(f'{"Verified" if check_only else "Patched"}: {p}')


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('root', type=Path, help='Directory containing BakaSU kernel/selinux')
    ap.add_argument('--check', action='store_true', help='Only check patch anchors')
    opts = ap.parse_args()
    patch(opts.root, opts.check)
