#!/usr/bin/env python3
# =============================================================================
#  DRIP Observer - observer.py
#  Reads a DRIP capture (Format W = Wireshark bytes-only export, or
#  Format B = flat hex), decodes it via odid.py, validates it against the
#  errors.py catalog, and prints a report.
#
#  Usage:
#     python3 observer.py <file.txt> [--pubkey HEX] [--verbose] [--now UNIX] [--max-age SEC]
#
#  --pubkey HEX : 32-byte Ed25519 public key (hex). Enables the DET<->key
#                 binding check (E-DET-02) for DRIP Basic ID messages.
#  --now / --max-age : enable freshness check (E-FRESH-01) against a reference time.
# =============================================================================

import sys
import argparse
import ipaddress
from collections import Counter, defaultdict

import odid
from errors import Finding, ERROR_CATALOG

# det.py provides verify_det_binding() (RFC 9374 DET derivation). Optional:
try:
    import det
    HAVE_DET = True
except Exception:
    HAVE_DET = False

# ed25519.py provides RFC 8032 verify() for the Wrapper signature check. Optional:
try:
    import ed25519
    HAVE_ED = True
except Exception:
    HAVE_ED = False

# Plausible ODID timestamp range (seconds since 2019-01-01). Table 8 caps at uint32.
TS_RANGE = (0, 2 ** 32 - 1)

# ---------------------------------------------------------------------------
#  Trust anchor for the DRIP Link chain of trust (RFC 9575 §6.4.2).
#  TEST-ONLY: derived from the fixed test APEX_SEED in drip_registration.cpp.
#  A real deployment MUST configure the true Apex (DET prefix owner) key and
#  DET here (or load them from a trust store) instead of these test values.
# ---------------------------------------------------------------------------
APEX_HI  = bytes.fromhex("4FD099CCD47D7893DFE9EC24414ECB0D9B5420232AAD30D91C465BE33CBE65C4")
APEX_DET = bytes.fromhex("2001003000000005881EC7928833E0FB")

# cSHAKE128 customization string for all DRIP Manifest hashes (RFC 9575 §4.4.3)
MAN_HASH_CS = b"Remote ID Auth Hash"


# ---------------------------------------------------------------------------
#  Validators (each appends Finding objects)
# ---------------------------------------------------------------------------
def validate_message(d, where, findings):
    if d.get("_error") == "bad_length":
        findings.append(Finding("E-FMT-03", where, f"{d['length']} bytes"))
        return
    mtype = d.get("type")
    if mtype not in odid.MSG_TYPES:
        findings.append(Finding("E-FMT-01", where, f"type=0x{mtype:X}"))
    if d.get("version") != odid.PROTO_VERSION:
        findings.append(Finding("E-FMT-02", where, f"version=0x{d.get('version'):X}"))
    if mtype == 0xF:
        findings.append(Finding("E-PACK-04", where, "0xF message nested inside a pack"))

    if mtype == 0x2:                                   # authentication page checks
        at = d.get("auth_type")
        if at is not None and 6 <= at <= 9:
            findings.append(Finding("E-AUTH-01", where, f"AuthType={at}"))
        if d.get("page_num") == 0:
            if d.get("last_page_reserved", 0) != 0:
                findings.append(Finding("E-AUTH-04", where,
                                        f"reserved nibble=0x{d['last_page_reserved']:X}"))
            ts = d.get("timestamp_raw")
            if ts is not None and not (TS_RANGE[0] <= ts <= TS_RANGE[1]):
                findings.append(Finding("E-AUTH-06", where, f"ts={ts}"))

    if mtype == 0x0 and d.get("det") is not None:      # DRIP DET prefix check
        prefix28 = int.from_bytes(d["det"], "big") >> 100
        if prefix28 != (int(odid.DET_PREFIX.network_address) >> 100):
            findings.append(Finding("E-DET-01", where, d.get("det_ipv6", "")))


def validate_pack(pack_info, where, findings):
    if pack_info.get("_error"):
        findings.append(Finding("E-PACK-03", where, pack_info["_error"]))
        return
    if pack_info.get("msg_size") != 0x19:
        findings.append(Finding("E-PACK-01", where, f"size=0x{pack_info['msg_size']:X}"))
    n = pack_info.get("count", 0)
    if n < 1 or n > 9:
        findings.append(Finding("E-PACK-02", where, f"N={n}"))
    need = n * odid.MSG_LEN
    have = pack_info.get("bytes_available", 0)
    if need > have:
        findings.append(Finding("E-PACK-03", where, f"need {need}, have {have}"))


def validate_auth(auth, where, findings, now=None, max_age=None):
    expected = list(range(auth["last_page_index"] + 1))
    if auth["pages_present"] != expected:
        findings.append(Finding("E-AUTH-03", where,
                                f"pages={auth['pages_present']} expected={expected}"))
    if not auth["complete"]:
        findings.append(Finding("E-AUTH-05", where, f"declared length={auth['length']}"))
    if auth["auth_type"] == 5:                          # SAM type only meaningful here
        st = auth["sam_type"]
        if st not in odid.SAM_TYPES:
            findings.append(Finding("E-SAM-01", where,
                                    f"SAM=0x{st:02X}" if st is not None else "empty payload"))
    if now is not None and max_age is not None and auth.get("timestamp_unix") is not None:
        age = now - auth["timestamp_unix"]
        if age > max_age or age < -max_age:
            findings.append(Finding("E-FRESH-01", where, f"age={age}s window=+/-{max_age}s"))


def check_det_binding(det_bytes, pub, where, findings):
    """E-DET-02: re-derive the DET from the public key and compare (RFC 9374)."""
    if not (HAVE_DET and pub):
        return
    try:
        if not det.verify_det_binding(det_bytes, pub):
            findings.append(Finding("E-DET-02", where, str(ipaddress.IPv6Address(det_bytes))))
    except Exception as e:
        findings.append(Finding("E-DET-02", where, f"check error: {e}"))


def check_wrapper_signature(auth, decoded_msgs, pub, where, findings):
    """E-SIG-01: verify a DRIP Wrapper (Extended Transport) Ed25519 signature.

    RFC 9575 §4.3.2 + §4.1 Fig 4. The signed bytes are rebuilt as:
        VNB(4) || VNA(4) || Evidence || UA_DET(16)
    where VNB/VNA are the RAW wire bytes (little-endian, not re-encoded, to
    avoid any endianness ambiguity) and Evidence is reconstructed from the
    pack's non-Auth messages (see odid.reconstruct_wrapper_evidence).

    On-wire SAM data (Evidence cleared) = VNB(4)|VNA(4)|DET(16)|Sig(64) = 88 B.
    """
    if not (HAVE_ED and pub):
        return
    if auth.get("auth_type") != 5 or auth.get("sam_type") != 0x02:
        return  # only DRIP Wrapper
    sam = auth.get("sam_data", b"")
    if len(sam) < 88:
        findings.append(Finding("E-SIG-01", where, f"wrapper payload too short ({len(sam)} B)"))
        return
    vnb_bytes = sam[0:4]
    vna_bytes = sam[4:8]
    det_bytes = sam[8:24]
    sig       = sam[24:88]
    evidence  = odid.reconstruct_wrapper_evidence(decoded_msgs)
    signed    = vnb_bytes + vna_bytes + evidence + det_bytes
    try:
        if not ed25519.verify(pub, signed, sig):
            findings.append(Finding("E-SIG-01", where,
                                    f"{len(evidence)//25} msg(s) in evidence"))
    except Exception as e:
        findings.append(Finding("E-SIG-01", where, f"verify error: {e}"))


# ---------------------------------------------------------------------------
#  Processing
# ---------------------------------------------------------------------------
def process_pack(pack_bytes, where, pub, findings, report, now=None, max_age=None):
    pack = odid.split_pack(pack_bytes)
    report.append((where, {"_pack_raw": bytes(pack_bytes)}))   # for Manifest pack-hash cross-check
    validate_pack(pack, where, findings)
    decoded = [odid.decode_message(m) for m in pack.get("messages_raw", [])]
    for idx, d in enumerate(decoded):
        w = f"{where} msg[{idx}]"
        validate_message(d, w, findings)
        report.append((w, d))
        if d.get("type") == 0x0 and d.get("det") is not None:
            check_det_binding(d["det"], pub, w, findings)

    auths = odid.reassemble_auth(decoded)
    for auth in auths:
        w = f"{where} auth@msg[{auth['start_index']}]"
        validate_auth(auth, w, findings, now=now, max_age=max_age)
        check_wrapper_signature(auth, decoded, pub, w, findings)
        report.append((w, {"_auth": auth}))

    # semantic: DRIP auth present but no DRIP Basic ID in the same pack
    has_drip_auth = any(a["auth_type"] == 5 and a["sam_type"] in odid.SAM_TYPES for a in auths)
    has_drip_bid = any(d.get("type") == 0x0 and d.get("det") is not None for d in decoded)
    if has_drip_auth and not has_drip_bid:
        findings.append(Finding("E-SEM-01", where))


def process_payload(payload, where, pub, findings, report, now=None, max_age=None):
    """payload = a Message Pack (first nibble 0xF) or a single 25-byte message."""
    if not payload:
        return
    if (payload[0] >> 4) == 0xF:
        process_pack(payload, where, pub, findings, report, now=now, max_age=max_age)
    else:
        d = odid.decode_message(payload[:odid.MSG_LEN])
        validate_message(d, where, findings)
        report.append((where, d))
        if d.get("type") == 0x0 and d.get("det") is not None:
            check_det_binding(d["det"], pub, where, findings)


def verify_link_chain(bes, findings, now=None):
    """Verify a set of DRIP Link Broadcast Endorsements (RFC 9575 §4.2 / §6.4.2).

    For each unique BE:
      E-LINK-01  child DET must bind to child HI (cSHAKE128, via det.py)
      E-LINK-04  BE must be within its VNB..VNA window (only if `now` given)
      resolve the parent's HI: either the trust anchor (APEX) or the HI carried
        as the child of a higher BE (det_child == this det_parent)
      E-LINK-03  if no parent HI can be resolved -> chain broken
      E-LINK-02  parent signature over the 72-byte signed region must verify
    """
    if not (HAVE_DET and HAVE_ED) or not bes:
        return
    by_child = {be["det_child"]: be for be in bes}     # child DET -> its endorsement
    for be in bes:
        w = f"Link BE child={ipaddress.IPv6Address(be['det_child'])}"

        # E-LINK-01: child DET <-> child HI binding
        try:
            if not det.verify_det_binding(be["det_child"], be["hi_child"]):
                findings.append(Finding("E-LINK-01", w))
        except Exception as e:
            findings.append(Finding("E-LINK-01", w, f"binding error: {e}"))

        # E-LINK-04: validity window (only when a reference time is supplied)
        if now is not None and not (be["vnb"] <= now <= be["vna"]):
            findings.append(Finding("E-LINK-04", w, f"vnb={be['vnb']} vna={be['vna']} now={now}"))

        # resolve parent HI: trust anchor, or the child-HI of the next BE up
        if be["det_parent"] == APEX_DET:
            parent_hi = APEX_HI
        elif be["det_parent"] in by_child:
            parent_hi = by_child[be["det_parent"]]["hi_child"]
        else:
            findings.append(Finding("E-LINK-03", w,
                f"no parent/anchor for det_parent={ipaddress.IPv6Address(be['det_parent'])}"))
            continue

        # E-LINK-02: parent signature over VNB|VNA|DET_child|HI_child|DET_parent
        if not ed25519.verify(parent_hi, be["signed_region"], be["sig"]):
            findings.append(Finding("E-LINK-02", w))


def _collect_link_bes(report):
    """Extract unique DRIP Link BEs (SAM type 0x01) from the decoded report."""
    seen = set()
    bes = []
    for _w, d in report:
        a = d.get("_auth")
        if not a or a.get("sam_type") != 0x01:
            continue
        be = odid.decode_link_sam(a.get("sam_data", b""))
        if be is None:
            continue
        key = be["det_child"] + be["det_parent"] + be["sig"]
        if key in seen:
            continue
        seen.add(key)
        bes.append(be)
    return bes


def _man_hash8(data):
    """cSHAKE128(data, 64 bits, N='', S='Remote ID Auth Hash') -> 8 bytes (RFC 9575 §4.4.3)."""
    return det.cshake128(bytes(data), 8, N=b'', S=MAN_HASH_CS)


def _collect_manifests(report):
    """Unique DRIP Manifests (SAM 0x03) in report order."""
    seen, out = set(), []
    for w, d in report:
        a = d.get("_auth")
        if not a or a.get("sam_type") != 0x03:
            continue
        m = odid.decode_manifest_sam(a.get("sam_data", b""))
        if m is None:
            continue
        key = bytes(a["sam_data"])
        if key in seen:
            continue
        seen.add(key)
        out.append((w, m))
    return out


def _collect_pack_hashes(report):
    """Hash every observed Message Pack (RFC 9575 §4.4.3.2: full pack, no counter)."""
    return {_man_hash8(d["_pack_raw"]) for _w, d in report if "_pack_raw" in d}


def _collect_link_hashes(report):
    """Hash every observed DRIP Link full SAM (0x01 || sam_data), as the firmware does."""
    hs = set()
    for _w, d in report:
        a = d.get("_auth")
        if a and a.get("sam_type") == 0x01:
            hs.add(_man_hash8(bytes([0x01]) + bytes(a.get("sam_data", b""))))
    return hs


def verify_manifests(report, findings, pub=None, now=None):
    """Verify DRIP Manifests (RFC 9575 §4.4). Cross-checks against packs/links
       observed elsewhere in the same capture; chains manifests by Prev/Curr."""
    if not HAVE_DET:
        return
    mans = _collect_manifests(report)
    if not mans:
        return
    pack_hashes = _collect_pack_hashes(report)
    link_hashes = _collect_link_hashes(report)
    prev_curr = None
    for w, m in mans:
        # E-MAN-01: UA signature over VNB|VNA|Evidence|DET
        if HAVE_ED and pub and not ed25519.verify(pub, m["signed_region"], m["sig"]):
            findings.append(Finding("E-MAN-01", w))
        # E-MAN-05: self-hash = cSHAKE128(Prev | null | Link | ASTM hashes)
        calc = _man_hash8(m["prev"] + b"\x00" * 8 + m["link_hash"] + b"".join(m["astm_hashes"]))
        if calc != m["curr"]:
            findings.append(Finding("E-MAN-05", w, f"curr={m['curr'].hex()} calc={calc.hex()}"))
        # E-MAN-02: each ASTM (pack) hash must match an observed pack
        for h in m["astm_hashes"]:
            if h not in pack_hashes:
                findings.append(Finding("E-MAN-02", w, f"unmatched pack hash {h.hex()}"))
        # E-MAN-03: link hash must match an observed BE:HDA,UA
        if m["link_hash"] not in link_hashes:
            findings.append(Finding("E-MAN-03", w, f"unmatched link hash {m['link_hash'].hex()}"))
        # E-MAN-04: chain (skip for the first manifest, whose Prev is the seed nonce)
        if prev_curr is not None and m["prev"] != prev_curr:
            findings.append(Finding("E-MAN-04", w,
                                    f"prev={m['prev'].hex()} expected={prev_curr.hex()}"))
        prev_curr = m["curr"]


def run(text, pub=None, now=None, max_age=None):
    """Decode + validate `text`. Returns (format_label, report, findings).
       Auto-detects Format L (ESP32 serial log), Format W (Wireshark bytes),
       or Format B (flat hex)."""
    findings = []
    report = []
    if odid.looks_like_format_l(text):
        fmt = "L (ESP32 serial log)"
        for entry in odid.parse_format_l(text):
            where = (f"tx[{entry['tx_cnt']:#04x}] "
                     f"cnt=0x{entry['counter']:02X} "
                     f"cycle={entry['cycle']}")
            process_payload(entry["pack_bytes"], where, pub,
                            findings, report, now=now, max_age=max_age)
    elif odid.looks_like_format_w(text):
        fmt = "W (Wireshark bytes export)"
        for fi, frame in enumerate(odid.parse_format_w(text)):
            ie = odid.extract_drip_ie(frame)
            if ie is None:
                continue
            where = f"frame[{fi}] cnt=0x{ie['counter']:02X}"
            process_payload(ie["payload"], where, pub, findings, report, now=now, max_age=max_age)
    else:
        fmt = "B (flat hex)"
        for ri, (rec, _expect) in enumerate(odid.parse_format_b(text)):
            process_payload(rec, f"record[{ri}]", pub, findings, report, now=now, max_age=max_age)

    # DRIP Link chain of trust: gather all unique Link BEs and verify the chain
    verify_link_chain(_collect_link_bes(report), findings, now=now)
    # DRIP Manifest verification: signature, self-hash, pack/link cross-check, chaining
    verify_manifests(report, findings, pub=pub, now=now)
    return fmt, report, findings


# ---------------------------------------------------------------------------
#  Reporting
# ---------------------------------------------------------------------------
def _fmt_msg_line(where, d):
    if "_auth" in d:
        a = d["_auth"]
        sam = a.get("sam_name") or (f"0x{a['sam_type']:02X}" if a["sam_type"] is not None else "?")
        return (f"  {where}: Auth reassembled  type={a['auth_type']} "
                f"pages={a['pages_present']} len={a['length']} "
                f"SAM={sam} complete={a['complete']}")
    t = d.get("type_name", "?")
    extra = ""
    if d.get("type") == 0x0 and d.get("det_ipv6"):
        extra = f"  DET={d['det_ipv6']}"
    elif d.get("type") == 0x3:
        extra = f"  desc='{d.get('description','')}'"
    elif d.get("type") == 0x5:
        extra = f"  op='{d.get('operator_id','')}'"
    elif d.get("type") == 0x4:
        extra = f"  lat={d.get('operator_lat'):.5f} lon={d.get('operator_lon'):.5f}"
    return f"  {where}: {t}{extra}"


def print_report(fmt, report, findings, verbose=False):
    print(f"Input format: {fmt}")
    msg_items = [(w, d) for w, d in report if "_pack_raw" not in d]
    print(f"DRIP payloads decoded: {len({w.split(' msg')[0].split(' auth')[0] for w, _ in msg_items})}")
    print(f"Decoded items: {len(msg_items)}")
    if not HAVE_DET:
        print("(note: det.py not importable - DET<->key binding check disabled)")

    # message-type histogram
    hist = Counter()
    for _w, d in msg_items:
        if "_auth" in d:
            hist["Authentication (reassembled)"] += 1
        else:
            hist[d.get("type_name", "?")] += 1
    print("\nMessage-type counts:")
    for name, c in hist.most_common():
        print(f"  {c:6d}  {name}")

    if verbose:
        print("\nDecoded items:")
        for w, d in msg_items:
            print(_fmt_msg_line(w, d))

    # findings grouped by error id
    print("\nFindings:")
    if not findings:
        print("  (none)")
    else:
        by_id = defaultdict(list)
        for f in findings:
            by_id[f.error_id].append(f)
        for eid in sorted(by_id):
            desc, constraint = ERROR_CATALOG.get(eid, ("?", ""))
            items = by_id[eid]
            print(f"  {eid}  x{len(items)}  {desc}")
            print(f"          constraint: {constraint}")
            for f in items[:5 if not verbose else len(items)]:
                print(f"          - @ {f.where}" + (f"  ({f.detail})" if f.detail else ""))
            if not verbose and len(items) > 5:
                print(f"          - ... and {len(items) - 5} more")
    print(f"\nTotal findings: {len(findings)}")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Offline DRIP/ASTM observer")
    ap.add_argument("file", help="capture file (Format W or Format B)")
    ap.add_argument("--pubkey", help="32-byte Ed25519 public key (hex) for DET binding check")
    ap.add_argument("--now", type=int, help="reference Unix time for freshness check")
    ap.add_argument("--max-age", type=int, help="max allowed |age| in seconds (with --now)")
    ap.add_argument("--verbose", action="store_true", help="print every decoded item")
    args = ap.parse_args(argv)

    pub = None
    if args.pubkey:
        if not HAVE_DET:
            print("ERROR: --pubkey was supplied but det.py could not be imported.")
            print("       Place det.py in the same folder as observer.py and retry.")
            return 2
        hexkey = args.pubkey.strip()
        if len(hexkey) != 64:
            print(f"ERROR: --pubkey must be 64 hex chars (32 bytes); got {len(hexkey)} chars.")
            return 2
        try:
            pub = bytes.fromhex(hexkey)
        except ValueError as e:
            print(f"ERROR: --pubkey is not valid hex: {e}")
            return 2
            return 2

    with open(args.file, encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    fmt, report, findings = run(text, pub=pub, now=args.now, max_age=args.max_age)
    print_report(fmt, report, findings, verbose=args.verbose)
    return 0 if not findings else 1


if __name__ == "__main__":
    sys.exit(main())
