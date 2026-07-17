#!/usr/bin/env python3
# =============================================================================
#  DRIP Observer - observer.py
#  Reads a DRIP capture (Format W = Wireshark bytes-only export, or
#  Format B = flat hex), decodes it via odid.py, validates it against the
#  errors.py catalog, and prints a report.
#
#  Usage:
#     python3 observer.py <file.txt> [--pubkey HEX] [--keyring FILE]
#                                    [--verbose] [--now UNIX] [--max-age SEC]
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
    # The backend keeps ed25519.py as the normative reference and only uses a
    # faster implementation after proving it agrees (RFC 8032 §7.1 TEST 1,
    # valid AND tampered). It also memoises: the ~10 Hz beacon repeat
    # (ASTM §5.4.4.2 BUR0050) re-sends identical packs, and verifying an
    # identical (key,msg,sig) triple again cannot change the answer.
    import ed25519_backend
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
# ---------------------------------------------------------------------------
#  Trust anchor.
#
#  These are the FALLBACK bench values. The real source of truth is
#  hierarchy.json, loaded at startup if present (or via --anchor FILE), so that
#  swapping in a real DNSSEC-anchored Apex is a DATA change, not a code change.
#
#  Under RFC 9886 7.1 this anchor is exactly what DNSSEC would establish: the
#  observer would learn the Apex key from a DNSSEC-validated lookup instead of
#  from a constant compiled into it. Until then it is hardcoded, and that is the
#  single most important thing this PoC does NOT yet solve (PART 4.3).
# ---------------------------------------------------------------------------
APEX_HI  = bytes.fromhex("4FD099CCD47D7893DFE9EC24414ECB0D9B5420232AAD30D91C465BE33CBE65C4")
APEX_DET = bytes.fromhex("2001003000000005881EC7928833E0FB")
ANCHOR_SOURCE = "built-in bench default"


def load_hierarchy(path="hierarchy.json"):
    """Load the trust anchor from hierarchy.json. Returns True if applied.

    PUBLIC data only. An absent file keeps the built-in default, so nothing
    that worked before this file existed breaks because of it.
    """
    global APEX_HI, APEX_DET, ANCHOR_SOURCE
    import json as _json
    try:
        h = _json.load(open(path, encoding="utf-8"))
        a = h["apex"]
        hi, d = bytes.fromhex(a["public_key"]), bytes.fromhex(a["det"])
    except FileNotFoundError:
        return False
    if len(hi) != 32 or len(d) != 16:
        raise ValueError(f"{path}: apex public_key must be 32 B and det 16 B")
    # Never adopt an anchor that does not hold together. An Apex whose DET does
    # not derive from its own key would silently reject every real drone, and
    # the report would blame the drones.
    if HAVE_DET and not det.verify_det_binding(d, hi):
        raise ValueError(f"{path}: the apex DET does not derive from its public "
                         f"key (RFC 9374 3.5.2). Run check_hierarchy.py.")
    APEX_HI, APEX_DET = hi, d
    ANCHOR_SOURCE = path
    return True

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


# ---------------------------------------------------------------------------
#  Keyring — DET -> Ed25519 public key
#
#  The observer used to hold ONE key (--pubkey) and apply it to every DET it
#  met. That was correct while the transmitter was a single UA. It is not any
#  more: the bench emulator flies up to 3 virtual UAs, each with its OWN key and
#  DET (RFC 9374 3.5.2 binds a DET to the key it was derived from). With one
#  key, two of three drones would fail E-DET-02/E-SIG-01/E-MAN-01 against a key
#  that was never theirs -- a false accusation, not a finding.
# ---------------------------------------------------------------------------

# The three bench identities, as PUBLIC data (det_generator.cpp IDENTITY_TABLE).
# Regenerate with det.py + ed25519.py:
#     seed0 = bytes.fromhex("568BF5E8...C703CCD6")          # slot 0 (legacy)
#     slot_seed = lambda i: det.shake128(b"DRIP PoC UA slot %d" % i, 32)
#     pub = ed25519.derive_pubkey(seed); d = det.compute_det(pub, 1000, 2000)
BUILTIN_KEYS = [
    ("20010030FA07D00531E01AED4E7ECF5C",
     "8B65B265A496E32046CFA378B5A5FB2E877A97723E557CB5F0D21848BFE94477",
     "slot 0 (original single-drone PoC identity)"),
    ("20010030FA07D005F3B66F58E30EAD97",
     "F7D792E5DD000E8C05DCEEB357D03AF1770B0D7D6BFE429AABBD3C3F1CB16FE2",
     "slot 1"),
    ("20010030FA07D00555844FA78F0D14D7",
     "B80BC263962420FBF1454E61BB149FCD1BDC447195B12D63C69E7FB7AEAAC3AC",
     "slot 2"),
]


class Keyring:
    """Maps a DET to the public key that must have signed for it.

    A --pubkey supplied on the command line is kept as a WILDCARD: it applies to
    any DET with no explicit entry. That preserves the historical behaviour for
    a single unknown drone, while named DET->key entries always win.
    """

    def __init__(self):
        self._by_det = {}
        self._wildcard = None

    def add(self, det_bytes, pub):
        self._by_det[bytes(det_bytes)] = bytes(pub)

    def set_wildcard(self, pub):
        self._wildcard = bytes(pub)

    def for_det(self, det_bytes):
        if det_bytes is None:
            return self._wildcard
        return self._by_det.get(bytes(det_bytes), self._wildcard)

    def __len__(self):
        return len(self._by_det)

    def __bool__(self):
        return bool(self._by_det) or self._wildcard is not None


def default_keyring():
    """The three known bench identities."""
    kr = Keyring()
    for d_hex, p_hex, _label in BUILTIN_KEYS:
        kr.add(bytes.fromhex(d_hex), bytes.fromhex(p_hex))
    return kr


def _det_str(det_bytes):
    try:
        return str(ipaddress.IPv6Address(bytes(det_bytes)))
    except Exception:
        return bytes(det_bytes).hex()


def check_det_binding(det_bytes, keys, where, findings):
    """E-DET-02: re-derive the DET from the public key and compare (RFC 9374)."""
    if not HAVE_DET:
        return
    # A caller that passes NO keyring is not asking for key-based checks, and
    # must stay silent exactly as before. A keyring that simply lacks THIS DET
    # is a different thing entirely - that is E-KEY-01.
    if keys is None:
        return
    pub = keys.for_det(det_bytes)
    if pub is None:
        # Previously a silent `return`. Silence read as "checked, fine" when it
        # actually meant "never checked".
        findings.append(Finding("E-KEY-01", where, _det_str(det_bytes)))
        return
    try:
        if not det.verify_det_binding(det_bytes, pub):
            findings.append(Finding("E-DET-02", where, _det_str(det_bytes)))
    except Exception as e:
        findings.append(Finding("E-DET-02", where, f"check error: {e}"))


def check_wrapper_signature(auth, decoded_msgs, keys, where, findings):
    """E-SIG-01: verify a DRIP Wrapper (Extended Transport) Ed25519 signature.

    RFC 9575 §4.3.2 + §4.1 Fig 4. The signed bytes are rebuilt as:
        VNB(4) || VNA(4) || Evidence || UA_DET(16)
    where VNB/VNA are the RAW wire bytes (little-endian, not re-encoded, to
    avoid any endianness ambiguity) and Evidence is reconstructed from the
    pack's non-Auth messages (see odid.reconstruct_wrapper_evidence).

    On-wire SAM data (Evidence cleared) = VNB(4)|VNA(4)|DET(16)|Sig(64) = 88 B.
    """
    if not HAVE_ED:
        return
    # A caller that passes NO keyring is not asking for key-based checks, and
    # must stay silent exactly as before. A keyring that simply lacks THIS DET
    # is a different thing entirely - that is E-KEY-01.
    if keys is None:
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
    # Key selection is driven by the DET carried INSIDE the Wrapper, so each UA
    # in a fleet is checked against its own key.
    pub = keys.for_det(det_bytes)
    if pub is None:
        findings.append(Finding("E-KEY-01", where, _det_str(det_bytes)))
        return
    evidence  = odid.reconstruct_wrapper_evidence(decoded_msgs)
    signed    = vnb_bytes + vna_bytes + evidence + det_bytes
    try:
        if not ed25519_backend.verify(pub, signed, sig):
            findings.append(Finding("E-SIG-01", where,
                                    f"{len(evidence)//25} msg(s) in evidence"))
    except Exception as e:
        findings.append(Finding("E-SIG-01", where, f"verify error: {e}"))


# ---------------------------------------------------------------------------
#  Processing
# ---------------------------------------------------------------------------
def process_pack(pack_bytes, where, keys, findings, report, now=None, max_age=None,
                 mac=None):
    pack = odid.split_pack(pack_bytes)
    report.append((where, {"_pack_raw": bytes(pack_bytes)}))   # for Manifest pack-hash cross-check
    validate_pack(pack, where, findings)
    decoded = [odid.decode_message(m) for m in pack.get("messages_raw", [])]
    for idx, d in enumerate(decoded):
        w = f"{where} msg[{idx}]"
        # Synthetic field, same convention as _pack_raw / _auth. Only Format A
        # (air capture) has a MAC at all; the serial/hex formats do not.
        if mac is not None:
            d["_mac"] = mac
        validate_message(d, w, findings)
        report.append((w, d))
        if d.get("type") == 0x0 and d.get("det") is not None:
            check_det_binding(d["det"], keys, w, findings)

    auths = odid.reassemble_auth(decoded)
    for auth in auths:
        w = f"{where} auth@msg[{auth['start_index']}]"
        validate_auth(auth, w, findings, now=now, max_age=max_age)
        check_wrapper_signature(auth, decoded, keys, w, findings)
        report.append((w, {"_auth": auth}))

    # semantic: DRIP auth present but no DRIP Basic ID in the same pack
    has_drip_auth = any(a["auth_type"] == 5 and a["sam_type"] in odid.SAM_TYPES for a in auths)
    has_drip_bid = any(d.get("type") == 0x0 and d.get("det") is not None for d in decoded)
    if has_drip_auth and not has_drip_bid:
        findings.append(Finding("E-SEM-01", where))


def process_payload(payload, where, keys, findings, report, now=None, max_age=None,
                    mac=None):
    """payload = a Message Pack (first nibble 0xF) or a single 25-byte message."""
    if not payload:
        return
    if (payload[0] >> 4) == 0xF:
        process_pack(payload, where, keys, findings, report, now=now, max_age=max_age,
                     mac=mac)
    else:
        d = odid.decode_message(payload[:odid.MSG_LEN])
        validate_message(d, where, findings)
        report.append((where, d))
        if d.get("type") == 0x0 and d.get("det") is not None:
            check_det_binding(d["det"], keys, where, findings)


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
        if not ed25519_backend.verify(parent_hi, be["signed_region"], be["sig"]):
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


def collect_identities(report, keys=None):
    """Group everything observed by DRIP identity.

    Keyed on the DET, not the MAC: the DET *is* the identity (RFC 9374 §3.5.2
    binds it to a key). The MAC is only the radio that carried it, and ASTM
    F3411-22a §5.4.5.6 NOTE 2 explicitly permits a UA using Specific Session ID
    Type (which DRIP is, ID Type 4) to rotate MACs for privacy. So "how many
    drones are in the air" = how many distinct DETs.
    """
    ids = {}

    def slot(det_b):
        return ids.setdefault(bytes(det_b), {
            "macs": set(), "packs": 0, "wrap": set(), "man": set(), "key": None})

    # Basic ID messages -> DET, MAC, pack count
    for w, d in report:
        if d.get("type") == 0x0 and d.get("det"):
            e = slot(d["det"])
            e["packs"] += 1
            if d.get("_mac"):
                e["macs"].add(d["_mac"])

    # Wrapper signatures (unique), keyed by the DET inside the SAM
    for w, d in report:
        a = d.get("_auth")
        if not a or a.get("auth_type") != 5 or a.get("sam_type") != 0x02:
            continue
        sam = a.get("sam_data", b"")
        if len(sam) < 88:
            continue
        slot(sam[8:24])["wrap"].add(bytes(sam[24:88]))

    # Manifest signatures (unique)
    for w, m in _collect_manifests(report):
        if m.get("det"):
            slot(m["det"])["man"].add(bytes(m["sig"]))

    if keys is not None:
        for det_b, e in ids.items():
            e["key"] = keys.for_det(det_b)
    return ids


def report_identities(ids, findings):
    """Print the identity table and raise W-MAC-02 where warranted."""
    print(f"\nIdentities observed: {len(ids)} drone(s)")
    if not ids:
        return
    label_of = {bytes.fromhex(d): lbl.split("(")[0].strip()
                for d, _p, lbl in BUILTIN_KEYS}
    print(f"\n  {'#':<3}{'DET':<40} {'MAC(s)':<20} {'packs':>6}  {'key':<10} auth")
    for i, (det_b, e) in enumerate(sorted(ids.items(), key=lambda kv: -kv[1]["packs"]), 1):
        macs = sorted(e["macs"]) or ["(n/a)"]
        keylab = label_of.get(det_b, "keyring" if e["key"] else "-")
        if e["key"] is None:
            auth = "NO KEY - not verified"
        else:
            auth = f"OK  ({len(e['wrap'])} wrap, {len(e['man'])} man)"
        print(f"  {i:<3}{_det_str(det_b):<40} {macs[0]:<20} {e['packs']:>6}  {keylab:<10} {auth}")
        for extra in macs[1:]:
            print(f"  {'':<3}{'':<40} {extra:<20}")
        # W-MAC-02: NOT an ASTM violation (see errors.py) — a bench expectation.
        if len(e["macs"]) > 1:
            findings.append(Finding("W-MAC-02", _det_str(det_b),
                                    f"{len(e['macs'])} MACs: {', '.join(macs)}"))
    # One MAC carrying several DETs is visible above as rows sharing a MAC.
    # It is NOT covered by NOTE 2 and is the more serious case, but a validator
    # for it is a separate, un-approved stage.


def verify_manifests(report, findings, keys=None, now=None):
    """Verify DRIP Manifests (RFC 9575 §4.4). Cross-checks against packs/links
       observed elsewhere in the same capture; chains manifests by Prev/Curr."""
    if not HAVE_DET:
        return
    mans = _collect_manifests(report)
    if not mans:
        return
    pack_hashes = _collect_pack_hashes(report)
    link_hashes = _collect_link_hashes(report)
    # ------------------------------------------------------------------
    # FLEET FIX: the Manifest hash chain is PER UA (RFC 9575 4.4.2) — each
    # aircraft maintains its own Prev/Curr ledger. This used to walk ONE global
    # cursor over every manifest in the capture, which is right for one drone
    # and wrong for several: with 3 UAs interleaved it compares drone 0's Curr
    # against drone 1's Prev and reports E-MAN-04 on essentially every manifest.
    # The chain is now tracked per DET. (decode_manifest_sam already returns the
    # UA DET, so no new decoding is needed.)
    # ------------------------------------------------------------------
    prev_by_det = {}
    for w, m in mans:
        det_b = m.get("det")
        pub = keys.for_det(det_b) if keys is not None else None
        # E-MAN-01: UA signature over VNB|VNA|Evidence|DET — with THIS UA's key
        # keys is None => caller did not ask for signature checks (silent).
        if HAVE_ED and keys is not None and pub is None:
            findings.append(Finding("E-KEY-01", w, _det_str(det_b)))
        elif HAVE_ED and pub and not ed25519_backend.verify(pub, m["signed_region"], m["sig"]):
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
        # E-MAN-04: chain, PER UA (skip the first manifest of each UA, whose
        # Prev is that drone's seed nonce)
        prev_curr = prev_by_det.get(det_b)
        if prev_curr is not None and m["prev"] != prev_curr:
            findings.append(Finding("E-MAN-04", w,
                                    f"prev={m['prev'].hex()} expected={prev_curr.hex()}"))
        prev_by_det[det_b] = m["curr"]


class UnknownFormatError(Exception):
    """No parser recognised the input. Raised instead of guessing."""


# Populated by run() for Format A; read by print_report(). Kept module-level so
# run() can keep returning exactly 3 values (make_vectors.py unpacks 3).
capture_health = {}


def run(text, keys=None, now=None, max_age=None, pub=None, progress=False):
    """Decode + validate `text`. Returns (format_label, report, findings).

    `pub` is a BACK-COMPAT shim for callers that predate the keyring
    (make_vectors.py passes pub=UA_PUB). A bare key means "apply this to any
    DET", which is exactly a wildcard entry -- so it is wrapped into one rather
    than being a second code path that could drift.

    Auto-detects Format L (ESP32 serial log), Format A (DRIP_Sniffer air
    capture), Format W (Wireshark bytes export) or Format B (flat hex).

    Raises UnknownFormatError if none of them match.

    Every branch is now a POSITIVE test. Format B used to be the unconditional
    `else`, so an unrecognised file was DECLARED to be flat hex and decoded
    anyway. Handed an air capture, that turned a flawless 555-frame file into
    10157 findings and read as "your firmware is broken" -- a wrong answer
    delivered confidently, which is worse than no answer.
    """
    if pub is not None and keys is None:
        keys = Keyring()
        keys.set_wildcard(pub)

    findings = []
    report = []
    capture_health.clear()
    if odid.looks_like_format_l(text):
        fmt = "L (ESP32 serial log)"
        for entry in odid.parse_format_l(text):
            where = (f"tx[{entry['tx_cnt']:#04x}] "
                     f"cnt=0x{entry['counter']:02X} "
                     f"cycle={entry['cycle']}")
            process_payload(entry["pack_bytes"], where, keys,
                            findings, report, now=now, max_age=max_age)
    elif odid.looks_like_format_a(text):
        fmt = "A (air capture - DRIP_Sniffer)"
        a_frames, a_damaged = odid.parse_format_a(text)
        # A frame whose byte count contradicts the sniffer's own '#F len='
        # never arrived intact. It cannot testify about the drone that sent it,
        # so it is reported as capture damage rather than decoded into
        # DRIP "violations" that are really serial byte loss.
        for meta, got in a_damaged:
            findings.append(Finding("W-CAP-01", "capture",
                                    f"declared len={meta.get('len')}, got {got} B"))
        capture_health["frames"] = len(a_frames) + len(a_damaged)
        capture_health["damaged"] = len(a_damaged)
        for fi, (meta, frame) in enumerate(a_frames):
            ie = odid.extract_drip_ie(frame)
            if ie is None:
                continue          # e.g. a frame truncated when capture stopped
            hdr = odid.parse_mac_header(frame)
            # The transmitter MAC goes in the label so every finding is
            # attributable when several drones are on the air. It is NOT yet
            # validated against the DET -- that is a later stage.
            tag = odid.mac_str(hdr["addr2"]) if hdr else "??:??:??:??:??:??"
            where = f"frame[{fi}] {tag} cnt=0x{ie['counter']:02X}"
            process_payload(ie["payload"], where, keys, findings, report,
                            now=now, max_age=max_age, mac=tag)
            if progress and fi and fi % 2000 == 0:
                print(f"# {fi} frames...", file=sys.stderr, flush=True)
    elif odid.looks_like_format_w(text):
        fmt = "W (Wireshark bytes export)"
        for fi, frame in enumerate(odid.parse_format_w(text)):
            ie = odid.extract_drip_ie(frame)
            if ie is None:
                continue
            where = f"frame[{fi}] cnt=0x{ie['counter']:02X}"
            process_payload(ie["payload"], where, keys, findings, report, now=now, max_age=max_age)
    elif odid.looks_like_format_b(text):
        fmt = "B (flat hex)"
        for ri, (rec, _expect) in enumerate(odid.parse_format_b(text)):
            process_payload(rec, f"record[{ri}]", keys, findings, report, now=now, max_age=max_age)
    else:
        raise UnknownFormatError(odid.diagnose_format(text))

    # DRIP Link chain of trust: gather all unique Link BEs and verify the chain
    verify_link_chain(_collect_link_bes(report), findings, now=now)
    # DRIP Manifest verification: signature, self-hash, pack/link cross-check, chaining
    verify_manifests(report, findings, keys=keys, now=now)
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


def print_report(fmt, report, findings, verbose=False, keys=None):
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

    # Capture health, printed BEFORE the identity table: if the capture itself
    # is damaged, that context has to arrive before any finding is read.
    if capture_health.get("frames"):
        tot = capture_health["frames"]; dmg = capture_health["damaged"]
        pct = 100.0 * (tot - dmg) / tot
        print(f"\nCapture health: {tot - dmg:,}/{tot:,} frames intact ({pct:.2f}%)")
        if dmg:
            print(f"  {dmg} frame(s) DISCARDED - damaged in the capture pipeline "
                  f"(serial byte loss), not on the air.")
            print(f"  These are W-CAP-01, not DRIP defects. Findings from the "
                  f"surrounding frames may be collateral.")

    # Identity report. Raises W-MAC-02, so it must run before findings are
    # grouped for printing.
    idents = collect_identities(report, keys=keys)
    report_identities(idents, findings)

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
    ap.add_argument("file", nargs="?",
                    help="capture file - Format L (ESP32 serial log), "
                         "A (DRIP_Sniffer air capture), W (Wireshark bytes) "
                         "or B (flat hex). Optional with --list-keys.")
    ap.add_argument("--pubkey", metavar="HEX",
                    help="32-byte Ed25519 public key (hex). Used for any DET that has no "
                         "keyring entry -- i.e. a single unknown drone.")
    ap.add_argument("--keyring", metavar="FILE",
                    help="file of 'DET_HEX PUBKEY_HEX' pairs, one per line ('#' comments "
                         "allowed). Adds to / overrides the built-in bench identities.")
    ap.add_argument("--no-builtin-keys", action="store_true",
                    help="do not preload the 3 known bench identities (slots 0-2)")
    ap.add_argument("--list-keys", action="store_true",
                    help="print the keyring and exit")
    ap.add_argument("--anchor", metavar="FILE", default="hierarchy.json",
                    help="hierarchy.json holding the trust anchor (Apex DET + "
                         "public key). Absent = use the built-in bench anchor. "
                         "Swap in a real DNSSEC-anchored Apex here.")
    ap.add_argument("--pure-python", action="store_true",
                    help="force the ed25519.py reference implementation "
                         "(~1300x slower; use to cross-check a result)")
    ap.add_argument("--now", type=int, help="reference Unix time for freshness check")
    ap.add_argument("--max-age", type=int, help="max allowed |age| in seconds (with --now)")
    ap.add_argument("--verbose", action="store_true", help="print every decoded item")
    args = ap.parse_args(argv)

    # ---- build the keyring -------------------------------------------------
    keys = Keyring() if args.no_builtin_keys else default_keyring()

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
            keys.set_wildcard(bytes.fromhex(hexkey))
        except ValueError as e:
            print(f"ERROR: --pubkey is not valid hex: {e}")
            return 2

    if args.keyring:
        try:
            with open(args.keyring, encoding="utf-8") as fh:
                for ln, line in enumerate(fh, 1):
                    t = line.split("#", 1)[0].split()
                    if not t:
                        continue
                    if len(t) != 2:
                        print(f"ERROR: {args.keyring}:{ln}: expected 'DET_HEX PUBKEY_HEX'")
                        return 2
                    d_hex, p_hex = t
                    if len(d_hex) != 32 or len(p_hex) != 64:
                        print(f"ERROR: {args.keyring}:{ln}: DET must be 32 hex chars "
                              f"and pubkey 64; got {len(d_hex)}/{len(p_hex)}")
                        return 2
                    keys.add(bytes.fromhex(d_hex), bytes.fromhex(p_hex))
        except OSError as e:
            print(f"ERROR: cannot read --keyring: {e}")
            return 2

    if args.list_keys:
        print(f"Keyring: {len(keys)} DET-bound key(s)"
              f"{' + 1 wildcard (--pubkey)' if keys.for_det(None) else ''}")
        shown = set()
        for d_hex, p_hex, label in BUILTIN_KEYS:
            if args.no_builtin_keys:
                continue
            shown.add(bytes.fromhex(d_hex))
            print(f"  {_det_str(bytes.fromhex(d_hex)):40s}  {label}")
            print(f"    key {p_hex}")
        for d in keys._by_det:                      # anything from --keyring
            if d not in shown:
                print(f"  {_det_str(d):40s}  (from --keyring)")
                print(f"    key {keys.for_det(d).hex().upper()}")
        if keys.for_det(None):
            print(f"  {'(any other DET)':40s}  wildcard from --pubkey")
        return 0

    if not args.file:
        print("ERROR: no capture file given. (A file is optional only with --list-keys.)")
        return 2

    with open(args.file, encoding="utf-8", errors="replace") as fh:
        text = fh.read()

    # Trust anchor first: everything downstream is verified against it.
    try:
        if load_hierarchy(args.anchor):
            print(f"Trust anchor: {ANCHOR_SOURCE}  "
                  f"apex={_det_str(APEX_DET)}")
        elif args.anchor != "hierarchy.json":
            print(f"ERROR: --anchor {args.anchor}: file not found")
            return 2
    except ValueError as e:
        print(f"ERROR: {e}")
        return 2

    if args.pure_python and HAVE_ED:
        ed25519_backend.force_pure_python()
    if HAVE_ED:
        print(f"Ed25519 backend: {ed25519_backend.backend_name()}")
        print(f"  self-test: {ed25519_backend.selftest_note()}")

    try:
        fmt, report, findings = run(text, keys=keys, now=args.now,
                                    max_age=args.max_age, progress=True)
    except UnknownFormatError as e:
        # Refuse rather than guess. See run()'s docstring.
        print(f"ERROR: {e}")
        return 2
    print_report(fmt, report, findings, verbose=args.verbose, keys=keys)
    return 0 if not findings else 1


if __name__ == "__main__":
    sys.exit(main())
