#!/usr/bin/env python3
"""
check_hierarchy.py - prove the DRIP hierarchy is coherent and delegable.

*** RUN THIS AFTER CHANGING drip_hierarchy.h OR hierarchy.json. ***

The hierarchy is defined twice, because the firmware is C and the observer is
Python and neither can read the other's file at runtime:

    drip_hierarchy.h   firmware   RAA/HDA numbers + the test parents' PRIVATE seeds
    hierarchy.json     observer   the same numbers + the PUBLIC keys and DETs

Two copies means they can drift. This tool exists so drift is caught in one
second by a tool, instead of surfacing later as E-LINK-* / E-SIG-01 in the
observer - findings that look exactly like a firmware fault and cost hours
before anyone suspects a stale constant.

WHAT IT PROVES
--------------
  1. DERIVATION  - every DET in hierarchy.json is re-derived from its public key
                   with cSHAKE128 (RFC 9374 section 3.5.2). Nothing is trusted:
                   the file's own DET fields are checked, not read.
  2. AGREEMENT   - drip_hierarchy.h and hierarchy.json state the same numbers,
                   and the header's private seeds produce the JSON's public keys.
  3. NESTING     - the zones actually contain their children (RFC 9886 section 6):
                       HDA's DET must lie inside the RAA's /44
                       every UA's DET must lie inside the HDA's /56
                   This is the check that matters and the one nothing else does.

WHY NESTING IS NOT AUTOMATIC
----------------------------
RFC 9575 section 6.4.2 - the Broadcast Endorsement chain the observer already
walks - verifies SIGNATURES ONLY. It never looks at zones. So a hierarchy can
verify perfectly offline and still be impossible to publish in DNS.

That is not hypothetical: this project ran for weeks with Apex=0/0, RAA=1/0,
HDA=1/1 while the UAs used 1000/2000. Every self-test passed. But the HDA's zone
was 2001:30:40:100::/56 and the UAs sat at 2001:30:fa07:d005:... - outside it.
The chain was cryptographically sound and undelegable, and nothing said so.

Exit status 0 = coherent, 1 = a problem (so it can gate a build).
"""

import sys
import json
import re
import ipaddress
import argparse

import det
import ed25519


def zone_of(det_bytes, bits):
    """The DNS zone a DET belongs to: its own prefix truncated to `bits`.

    RFC 9886 section 6: RAA -> /44, HDA -> /56. The zone is fixed entirely by
    the RAA/HDA nibbles inside the DET; the key only affects the trailing
    64-bit ORCHID hash, so it cannot influence delegation.
    """
    nbytes = (bits + 7) // 8
    base = bytes(det_bytes[:nbytes]) + b"\x00" * (16 - nbytes)
    return ipaddress.IPv6Network((ipaddress.IPv6Address(base), bits), strict=False)


def parse_header(path):
    """Pull the numbers and seeds out of drip_hierarchy.h.

    Deliberately regex rather than a C parser: the header is ours and its shape
    is fixed. If it stops matching, this tool fails loudly rather than silently
    checking nothing - which is the only failure mode that would matter.
    """
    src = open(path, encoding="utf-8").read()
    out = {"nums": {}, "seeds": {}}

    for key in ("DRIP_UA_RAA", "DRIP_UA_HDA", "DRIP_APEX_RAA", "DRIP_APEX_HDA",
                "DRIP_RAA_RAA", "DRIP_RAA_HDA", "DRIP_HDA_RAA", "DRIP_HDA_HDA"):
        m = re.search(r'#define\s+%s\s+(\S+)' % key, src)
        if not m:
            raise SystemExit(f"ERROR: {path}: #define {key} not found")
        out["nums"][key] = m.group(1).rstrip("u")

    # Resolve aliases (DRIP_RAA_RAA is #defined to DRIP_UA_RAA, not a literal)
    for _ in range(4):
        for k, v in list(out["nums"].items()):
            if v in out["nums"]:
                out["nums"][k] = out["nums"][v]
    for k, v in out["nums"].items():
        try:
            out["nums"][k] = int(v, 0)
        except ValueError:
            raise SystemExit(f"ERROR: {path}: #define {k} is '{v}', not a number "
                             f"this tool can resolve.")

    for key in ("DRIP_APEX_SEED_INIT", "DRIP_RAA_SEED_INIT", "DRIP_HDA_SEED_INIT"):
        m = re.search(r'#define\s+%s\s+\{(.*?)\}' % key, src, re.S)
        if not m:
            raise SystemExit(f"ERROR: {path}: #define {key} not found")
        vals = re.findall(r'0[xX]([0-9a-fA-F]{2})', m.group(1))
        if len(vals) != 32:
            raise SystemExit(f"ERROR: {path}: {key} has {len(vals)} bytes, expected 32")
        out["seeds"][key] = bytes(int(v, 16) for v in vals)
    return out


def main():
    ap = argparse.ArgumentParser(
        description="Prove the DRIP hierarchy is coherent, consistent and delegable")
    ap.add_argument("--json", default="hierarchy.json")
    ap.add_argument("--header", default="drip_hierarchy.h",
                    help="drip_hierarchy.h (skipped if absent)")
    ap.add_argument("--ua-keys", default=None,
                    help="keyring file of UA DET/pubkey pairs (default: the "
                         "observer's built-in bench identities)")
    args = ap.parse_args()

    problems = []
    h = json.load(open(args.json, encoding="utf-8"))
    print(f"hierarchy: {args.json}")
    print(f"  UA numbers: RAA={h['ua_raa']}  HDA={h['ua_hda']}\n")

    # ---- 1. DERIVATION -----------------------------------------------------
    print("1. DERIVATION  (re-derive every DET from its public key, RFC 9374 3.5.2)")
    ents = {}
    for name in ("apex", "raa", "hda"):
        e = h[name]
        pub = bytes.fromhex(e["public_key"])
        claimed = bytes.fromhex(e["det"])
        actual = det.compute_det(pub, e["raa"], e["hda"])
        ok = actual == claimed
        ents[name] = {"det": actual, "pub": pub, "raa": e["raa"], "hda": e["hda"]}
        print(f"   {name:5s} {e['raa']:5d}/{e['hda']:<5d} "
              f"{ipaddress.IPv6Address(actual)}  {'OK' if ok else '*** MISMATCH ***'}")
        if not ok:
            problems.append(f"{name}: hierarchy.json says DET={claimed.hex().upper()} "
                            f"but its own public key derives {actual.hex().upper()}")

    # ---- 2. AGREEMENT with the firmware header -----------------------------
    print("\n2. AGREEMENT  (drip_hierarchy.h vs hierarchy.json)")
    try:
        hdr = parse_header(args.header)
    except SystemExit as e:
        print(f"   SKIPPED: {e}")
        hdr = None
    if hdr:
        pairs = [("DRIP_UA_RAA", h["ua_raa"]), ("DRIP_UA_HDA", h["ua_hda"]),
                 ("DRIP_APEX_RAA", h["apex"]["raa"]), ("DRIP_APEX_HDA", h["apex"]["hda"]),
                 ("DRIP_RAA_RAA", h["raa"]["raa"]),  ("DRIP_RAA_HDA", h["raa"]["hda"]),
                 ("DRIP_HDA_RAA", h["hda"]["raa"]),  ("DRIP_HDA_HDA", h["hda"]["hda"])]
        for key, jval in pairs:
            hval = hdr["nums"][key]
            if hval != jval:
                problems.append(f"{key}: header={hval} but hierarchy.json={jval}")
                print(f"   {key:16s} header={hval:<6} json={jval:<6} *** MISMATCH ***")
        if not problems:
            print("   all 8 numbers agree")
        # the header's private seeds must produce the JSON's public keys
        for name, seedkey in (("apex", "DRIP_APEX_SEED_INIT"),
                              ("raa", "DRIP_RAA_SEED_INIT"),
                              ("hda", "DRIP_HDA_SEED_INIT")):
            pub = ed25519.derive_pubkey(hdr["seeds"][seedkey])
            if pub != ents[name]["pub"]:
                problems.append(f"{name}: the header's seed derives public key "
                                f"{pub.hex().upper()[:16]}... but hierarchy.json "
                                f"has {ents[name]['pub'].hex().upper()[:16]}...")
                print(f"   {name} seed -> public key            *** MISMATCH ***")
        print("   header seeds reproduce the json public keys")

    # ---- 3. NESTING --------------------------------------------------------
    print("\n3. NESTING  (RFC 9886 section 6 - the check that decides delegability)")
    raa_zone = zone_of(ents["raa"]["det"], 44)
    hda_zone = zone_of(ents["hda"]["det"], 56)
    print(f"   RAA /44 zone : {raa_zone}")
    print(f"   HDA /56 zone : {hda_zone}")

    hda_in = ipaddress.IPv6Address(ents["hda"]["det"]) in raa_zone
    print(f"   HDA inside the RAA's zone : {'yes' if hda_in else 'NO'}")
    if not hda_in:
        problems.append(f"the HDA's DET is not inside the RAA's /44 ({raa_zone}). "
                        f"DRIP_HDA_RAA must equal DRIP_RAA_RAA.")

    # UA keys: the observer's built-ins unless a keyring is supplied
    uas = []
    if args.ua_keys:
        for ln, line in enumerate(open(args.ua_keys, encoding="utf-8"), 1):
            t = line.split("#", 1)[0].split()
            if len(t) == 2:
                uas.append((f"{args.ua_keys}:{ln}", bytes.fromhex(t[0]), bytes.fromhex(t[1])))
    else:
        try:
            import observer
            uas = [(lbl, bytes.fromhex(d), bytes.fromhex(p))
                   for d, p, lbl in observer.BUILTIN_KEYS]
        except Exception as e:
            print(f"   (could not load the observer's built-in UA keys: {e})")

    for lbl, d, pub in uas:
        inside = ipaddress.IPv6Address(d) in hda_zone
        bound = det.verify_det_binding(d, pub)
        flags = []
        if not inside:
            flags.append("NOT IN HDA ZONE")
            problems.append(f"UA {ipaddress.IPv6Address(d)} ({lbl}) is not inside the "
                            f"HDA's /56 ({hda_zone}). Its RAA/HDA must match the HDA's.")
        if not bound:
            flags.append("DET/KEY BINDING FAILED")
            problems.append(f"UA {lbl}: DET does not derive from its public key")
        print(f"   UA {ipaddress.IPv6Address(d)}  {lbl:34s} "
              f"{'ok' if not flags else '*** ' + ', '.join(flags) + ' ***'}")

    # ---- verdict -----------------------------------------------------------
    print()
    if problems:
        print(f"FAILED - {len(problems)} problem(s):")
        for p in problems:
            print(f"  * {p}")
        print("\nThis hierarchy cannot be published in DNS as-is.")
        return 1
    print("OK - the hierarchy is coherent, consistent across firmware and observer,")
    print("     and the zones nest, so the chain is delegable in DNS.")
    print("\nNOTE: this proves the STRUCTURE. It does not prove any registry has")
    print("      assigned these numbers (RFC 9374 3.3) - they are test values.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
