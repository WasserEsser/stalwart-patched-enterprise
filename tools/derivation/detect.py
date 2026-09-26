"""Generic Stalwart licence-site detector.

Works on any x86-64 Stalwart binary without per-version knowledge:

  1. parse the ELF sections to learn the .text vaddr/file-offset delta,
  2. locate the embedded Ed25519 public key halves (sanity check that this is
     an enterprise build),
  3. find every `call <verify> ; test al, al ; jcc` whose fall-through path
     materialises LicenseError discriminant 4 (Validation),
  4. group the sites by call target and report the ones that belong together,
     together with the bytes needed to build a patch pattern.

Usage: detect.py <binary> [<binary> ...]
"""
import re
import struct
import subprocess
import sys

from capstone import CS_ARCH_X86, CS_MODE_64, Cs

PUBKEY = bytes([0x76, 0x0A, 0xB6, 0x23, 0x59, 0x6F, 0x0B, 0x3C, 0x9A, 0x2F, 0xCD, 0x7F,
                0x6B, 0xE5, 0x37, 0x68, 0x48, 0x36, 0x8D, 0x0E, 0x61, 0xDB, 0x02, 0x04,
                0x77, 0x8F, 0x9C, 0x0A, 0x98, 0xD8, 0x20, 0xC2])

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True


def sections(path):
    """Return {name: (vaddr, offset, size)} from readelf."""
    out = subprocess.run(["readelf", "-SW", path], capture_output=True, text=True).stdout
    secs = {}
    for line in out.splitlines():
        m = re.match(r"\s*\[\s*\d+\]\s+(\S+)\s+(\S+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)", line)
        if m:
            name, _typ, addr, off, size = m.groups()
            secs[name] = (int(addr, 16), int(off, 16), int(size, 16))
    return secs


def s32(b, i):
    """Signed 32-bit read: CALL rel32 is a two's-complement displacement."""
    return int.from_bytes(b[i:i + 4], "little", signed=True)


def disc_after(data, text_vaddr, off, limit=64):
    """Follow the discriminant that the fall-through path builds, and return it.

    The error value is a niche-encoded enum: the high bit marks Err and the low
    bits are the variant index. The compiler materialises it as
    `movabs reg, 0x80000000000000<base>` followed by whatever adds the
    remaining delta (`inc`, `add`, `lea`). So decode from the movabs and track
    the register until it holds the final constant.

    Returns the variant index (4 == LicenseError::Validation) or None.
    """
    try:
        insns = list(md.disasm(data[off:off + limit], text_vaddr + off))
    except Exception:
        return None
    if not insns or insns[0].mnemonic != "movabs":
        return None
    try:
        imm = int(insns[0].op_str.split(",")[1].strip(), 16)
    except Exception:
        return None
    if imm >> 63 != 1:
        return None
    reg = insns[0].op_str.split(",")[0].strip()
    value = imm
    for insn in insns[1:]:
        ops = [o.strip() for o in insn.op_str.split(",")]
        if not ops:
            break
        if insn.mnemonic == "inc" and ops[0] == reg:
            value += 1
        elif insn.mnemonic == "add" and len(ops) == 2 and ops[0] == reg:
            try:
                value += int(ops[1], 16)
            except Exception:
                break
        elif insn.mnemonic == "mov" and len(ops) == 2 and ops[1] == reg:
            reg = ops[0]                       # register copy keeps the value
        elif insn.mnemonic == "lea" and len(ops) == 2 and ops[1].startswith(f"[{reg}"):
            inner = ops[1]
            if "+" in inner:
                try:
                    value += int(inner.split("+")[1].rstrip("]"), 16)
                except Exception:
                    break
            elif "-" in inner:
                try:
                    value -= int(inner.split("-")[1].rstrip("]"), 16)
                except Exception:
                    break
            else:
                break
            reg = ops[0]                       # lea also moves the result
        else:
            break
        if value & 0x7FFFFFFFFFFFFFFF == 4:
            return 4
    return None


def _num(tok):
    """Parse a capstone operand: it prints small values in decimal ("3") and
    larger ones in hex ("0x20"), and signed displacements as "-0x10"."""
    tok = tok.strip()
    try:
        return int(tok, 0)
    except (ValueError, TypeError):
        try:
            return int(tok, 16)
        except (ValueError, TypeError):
            return None


def _imm(ins, n=1):
    try:
        return _num(ins.op_str.split(",")[n])
    except Exception:
        return None


def track_discriminant(insns, branch_idx, indices):
    """Follow the niche-encoded error value across the branch and return the
    variant index if it settles on one of `indices` after the branch.

    The compiler builds it as `movabs reg, 0x80000000000000<base>` plus
    increments, and the movabs may sit EITHER side of the branch (before it, so
    the fall-through only adds the remainder; or after it, as a fresh value).
    Tracking from the test onward through both sides covers both.

    The index of LicenseError::Validation is NOT constant across versions (0.9.x
    has a field-carrying HostnameMismatch variant in position 1, which pushes
    Validation to 3), so the caller supplies the candidate set.
    """
    reg, value = None, None
    for i, ins in enumerate(insns):
        ops = [o.strip() for o in ins.op_str.split(",")]
        m = ins.mnemonic
        if m == "movabs":
            dest = ops[0]
            imm = _imm(ins)
            if imm is not None and imm >> 63 == 1:
                reg, value = dest, imm
            elif dest == reg:
                reg, value = None, None           # overwritten with something else
        elif reg is not None and reg in ins.op_str:
            if m == "inc" and ops[0] == reg:
                value += 1
            elif m == "add" and len(ops) == 2 and ops[0] == reg:
                add = _num(ops[1])
                if add is None:
                    reg, value = None, None
                else:
                    value += add
            elif m == "mov" and len(ops) == 2 and ops[1] == reg:
                reg = ops[0]                      # register copy keeps the value
            elif m == "lea" and len(ops) == 2 and ops[1].startswith(f"[{reg}"):
                inner = ops[1]
                if "+" not in inner:
                    reg, value = None, None
                else:
                    add = _num(inner.split("+")[1].rstrip("]"))
                    if add is None:
                        reg, value = None, None
                    else:
                        value += add
                        reg = ops[0]              # lea moves the result
            elif ops and ops[0] == reg:
                reg, value = None, None           # clobbered
        if i > branch_idx and reg is not None and (value & 0x7FFFFFFFFFFFFFFF) in indices:
            return value & 0x7FFFFFFFFFFFFFFF
    return None


MODRM_RIP = re.compile(rb"[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]")


def pubkey_refs(data, text_vaddr, text_off, text_size, targets):
    """Find instructions whose RIP-relative operand points at the embedded
    license public key (or one of its 16-byte halves).

    A RIP-relative memory operand is ModRM with mod=00, rm=101; there is no SIB
    byte and (for every instruction that uses this form) no immediate, so the
    displacement always ENDS the instruction: target = disp_pos + 4 + disp32.
    That lets us find candidates with a byte scan and validate by decoding.
    """
    text = data[text_off:text_off + text_size]
    out = []
    for m in MODRM_RIP.finditer(text):
        i = m.start()
        if i + 5 > len(text):
            continue
        disp = int.from_bytes(text[i + 1:i + 5], "little", signed=True)
        if text_vaddr + i + 5 + disp not in targets:
            continue
        for back in range(1, 10):                 # find where the insn starts
            start = i - back
            if start < 0:
                break
            insns = list(md.disasm(text[start:start + back + 5], text_vaddr + start))
            if (len(insns) == 1 and insns[0].address + insns[0].size == text_vaddr + i + 5
                    and "rip" in insns[0].op_str):
                out.append(insns[0].address)
                break
    return sorted(set(out))


def find_license_sites(data, path, secs, window=0x800):
    """Locate the Enterprise license signature checks in a Stalwart binary.

    Strategy: the pubkey reference is a version-stable anchor that can only
    occur in license code. From each reference, take the next
    `call ; test al, al ; jcc` site -- that is one inlined copy of the check.
    Those sites all call the same verify function, so take the most common
    target and return every site calling it.
    """
    text_vaddr, text_off, text_size = secs[".text"]

    # vaddrs of the key halves
    targets = set()
    for probe in (PUBKEY, PUBKEY[:16], PUBKEY[16:]):
        start = 0
        while True:
            o = data.find(probe, start)
            if o < 0:
                break
            start = o + 1
            for name, (va, off, sz) in secs.items():
                if off <= o < off + sz:
                    targets.add(va + (o - off))
                    break
    if not targets:
        return [], None, []

    refs = pubkey_refs(data, text_vaddr, text_off, text_size, targets)
    if not refs:
        return [], None, []

    # shape-only scan: every `call ; test al, al ; jcc` in .text
    sites = find_sites(data, text_vaddr, text_off, text_size, indices=None)
    chosen = []
    for r in refs:
        near = [s for s in sites if 0 <= s["call_va"] - r <= window]
        if near:
            s = dict(min(near, key=lambda s: s["call_va"] - r))
            s["anchor"] = r
            chosen.append(s)
    if not chosen:
        return [], None, refs
    from collections import Counter
    main = Counter(s["target"] for s in chosen).most_common(1)[0][0]
    # every site calling the verify, not just the anchored ones
    allsites = [dict(s) for s in sites if s["target"] == main]
    anchored_calls = {c["call_va"] for c in chosen}
    for s in allsites:
        s["anchored"] = s["call_va"] in anchored_calls
    return allsites, main, refs



FLAG_SAFE = {"mov", "movabs", "lea", "movzx", "movsx", "movsxd", "nop", "endbr64", "push", "pop"}

# movabs reg, imm64 encodings, for the look-back below
REG_MOVABS = {}
for _i, _n in enumerate(["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                         "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]):
    REG_MOVABS[_n] = (0x48 if _i < 8 else 0x49, 0xB8 + (_i % 8))


def disc_lookback(text, text_vaddr, call_off, branch, indices):
    """Fallback discriminant check when the base constant is set up well before
    the call.

    Old builds materialise the error value in a register ABOVE the branch, e.g.
    `movabs r14, 0x8000000000000000` ... `call` ... `test al, al` ... `je`;
    `lea rbp, [r14+3]`. The window tracker starts at the test and never sees
    that movabs, so look for it by byte scan in the 64 bytes before the call.
    """
    fall = branch.address + branch.size
    fall_off = fall - text_vaddr
    insns = list(md.disasm(text[fall_off:fall_off + 16], fall))
    if not insns:
        return None
    ins = insns[0]
    ops = [o.strip() for o in ins.op_str.split(",")]
    src, delta = None, None
    if ins.mnemonic == "inc":
        src, delta = ops[0], 1
    elif ins.mnemonic == "add" and len(ops) == 2:
        src, delta = ops[0], _num(ops[1])
    elif ins.mnemonic == "lea" and len(ops) == 2:
        m = re.match(r"\[(\w+)\s*\+\s*(-?(?:0x[0-9a-f]+|\d+))\]", ops[1])
        if not m:
            return None
        src, delta = m.group(1), _num(m.group(2))
    if src not in REG_MOVABS or delta is None:
        return None
    rex, opcode = REG_MOVABS[src]
    # The constant can sit a long way above the branch: 0.9.4 keeps it 563 bytes
    # before the call. 0x400 covers the observed layouts without reaching into
    # unrelated code.
    for i in range(call_off - 2, max(0, call_off - 0x400) - 1, -1):
        if text[i] == rex and text[i + 1] == opcode and i + 10 <= call_off:
            imm = int.from_bytes(text[i + 2:i + 10], "little")
            if imm >> 63 == 1:
                value = (imm & 0x7FFFFFFFFFFFFFFF) + delta
                if value in indices:
                    return value
                return None                       # a different variant
    return None


def find_sites(data, text_vaddr, text_off, text_size, indices=(3, 4)):
    """Sites shaped like `call <verify> ; test al, al ; <flag-safe>... ; jcc`
    where the fall-through path builds a LicenseError discriminant in `indices`.

    Only the shape matters for patching; the index tells us which error variant
    the failure path produces, which is what identifies the site."""
    text = data[text_off:text_off + text_size]
    cands = []
    i = 0
    while True:
        j = text.find(b"\xe8", i)
        if j < 0:
            break
        i = j + 1
        if text[j + 5:j + 7] != b"\x84\xc0":          # call ; test al, al
            continue
        call_va = text_vaddr + j
        target = call_va + 5 + s32(text, j + 1)
        if not (text_vaddr <= target < text_vaddr + text_size):
            continue                                   # not a real call
        test_va = call_va + 5

        # decode from the test: flag-safe instructions, then the branch, then a
        # few instructions past it (the discriminant may be built on either side)
        window, branch, branch_idx = [], None, None
        for insn in md.disasm(text[j + 7:j + 7 + 64], test_va + 2):
            if branch is None:
                if insn.mnemonic.startswith("j") and insn.mnemonic != "jmp":
                    branch, branch_idx = insn, len(window)
                elif insn.mnemonic not in FLAG_SAFE:
                    break
            else:
                if len(window) > branch_idx + 8:
                    break
            window.append(insn)
        if branch is None:
            continue
        # The discriminant index identifies the error variant, which differs
        # between version families (Validation is 3 in 0.9/0.10 and 4 from 0.11
        # on) -- so it is only computed when a caller asks for it (indices is
        # not None). The patchable shape is `call <verify> ; test al, al ; jcc`
        # either way.
        if indices is None:
            disc = None
        else:
            disc = track_discriminant(window, branch_idx, indices)
            if disc is None:
                disc = disc_lookback(text, text_vaddr, j, branch, indices)
            if disc is None:
                continue
        cands.append({
            "call_va": call_va,
            "call_file": text_off + j,
            "target": target,
            "test_va": test_va,
            "test_file": text_off + j + 5,
            "branch_va": branch.address,
            "branch_kind": "short" if branch.size == 2 else "near",
            "disc": disc,
            "window": window,
            "text_vaddr": text_vaddr,
            "context": text[max(0, j - 20):j + 5].hex(" "),
        })
    return cands


def analyse(path):
    data = open(path, "rb").read()
    secs = sections(path)
    tva, toff, tsize = secs[".text"]
    rva, roff, _ = secs.get(".rodata", (0, 0, 0))
    vers = sorted({m.decode() for m in re.findall(rb"\b0\.\d{1,2}\.\d{1,2}\b", data[:2_000_000])})
    h1 = data.find(PUBKEY[:16])
    h2 = data.find(PUBKEY[16:])
    sites = find_sites(data, tva, toff, tsize)
    from collections import Counter
    by_target = Counter(s["target"] for s in sites)
    main = by_target.most_common(1)[0][0] if by_target else None
    mine = [s for s in sites if s["target"] == main]

    print(f"\n=== {path}")
    print(f"    size={len(data):,}  .text vaddr=0x{tva:x} off=0x{toff:x} delta=0x{tva - toff:x}  .rodata vaddr=0x{rva:x} off=0x{roff:x}")
    print(f"    version strings: {', '.join(vers[:6]) or '(none)'}")
    print(f"    pubkey half1 file off: {hex(h1) if h1 >= 0 else 'NOT FOUND'}   half2: {hex(h2) if h2 >= 0 else 'NOT FOUND'}")
    print(f"    discriminant-4 verify calls: {len(sites)} (targets: {dict(by_target)})")
    for s in mine:
        print(f"      test byte 0x{s['test_va']:x} (file 0x{s['test_file']:x})  call 0x{s['call_va']:x} -> 0x{s['target']:x}  {s['branch_kind']}")
        print(f"        ctx: {s['context']}")
    return mine


if __name__ == "__main__":
    for p in sys.argv[1:]:
        analyse(p)
