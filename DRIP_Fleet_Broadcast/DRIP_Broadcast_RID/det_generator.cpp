#include "det_generator.h"
#include "cshake128.h"
#include <string.h>
#include <Arduino.h>

// ---------------------------------------------------------------------------
// Ed25519 backend.
//
// Path A (Arduino Crypto library — Rhys Weatherley) is now REQUIRED.
//   Sketch -> Include Library -> Manage Libraries -> install "Crypto".
//
// WHY PATH B (PSA) WAS DROPPED THIS REVISION:
//   PSA holds ONE imported key handle (psa_import_key -> g_key_id). The fleet
//   must sign with up to 3 different private keys, chosen per message. Path A
//   takes the seed as a call argument and is naturally multi-key; PSA would
//   need an imported handle per identity plus lifecycle management for no
//   benefit on a bench rig. drip_registration.h already required Path A for
//   DRIP_TEST_BE signing, so Path B could not build a working image anyway.
//   The PSA code has been removed rather than left as dead, misleading text.
// ---------------------------------------------------------------------------
#define USE_ARDUINO_CRYPTO_LIB

#ifndef USE_ARDUINO_CRYPTO_LIB
#error "det_generator.cpp: the multi-drone fleet requires the Arduino Crypto library (Path A). PSA supports a single imported key only."
#endif

#include <Ed25519.h>

// ===========================================================================
//  >>>>>>>>>>>>>>>>>  UA IDENTITY SLOT TABLE — EDIT HERE  <<<<<<<<<<<<<<<<<<<
//
//  One row per virtual UA the bench fleet can emulate. Each row is a complete,
//  self-consistent RFC 9374 identity: private seed, the public key it derives,
//  and the DET that public key produces under (RAA=1000, HDA=2000, Suite=5).
//
//  *** TEST VALUES ONLY — every private seed here is published in source. ***
//  No IANA registration stands behind any of them (RFC 9374 §3.3).
//
//  ---------------------------------------------------------------------------
//  REPRODUCING THIS TABLE (for other engineers)
//
//  Everything below is derived, not invented. From the project's own Python
//  reference implementations (det.py + ed25519.py), in that folder:
//
//      import det, ed25519, ipaddress
//
//      # Slot 0 is the LEGACY identity: its seed predates this table and was
//      # generated on-device in sub-step 1a. It is reproduced verbatim so that
//      # a 1-drone fleet is byte-identical to the original single-drone PoC.
//      seed0 = bytes.fromhex("568BF5E8F08ABAADB68BA1964BC25F29"
//                            "76A8AFC938244A39F76E0AB0C703CCD6")
//
//      # Slots 1..N are derived from a documented string, so they can be
//      # regenerated from scratch with no stored secret:
//      def slot_seed(i):
//          return det.shake128(("DRIP PoC UA slot %d" % i).encode(), 32)
//
//      for i in range(3):
//          seed = seed0 if i == 0 else slot_seed(i)
//          pub  = ed25519.derive_pubkey(seed)
//          d    = det.compute_det(pub, det.TEST_RAA, det.TEST_HDA)   # 1000, 2000
//          assert det.verify_det_binding(d, pub)
//          print(i, seed.hex(), pub.hex(), d.hex(), ipaddress.IPv6Address(d))
//
//  The printed values MUST equal the rows below AND the DETs printed at boot.
//
//  ---------------------------------------------------------------------------
//  ADDING A 4th DRONE
//    1. append a row here (use slot_seed(3) from the snippet above),
//    2. raise DET_IDENTITY_SLOTS in det_generator.h,
//    3. raise FLEET_MAX in drone_fleet.h (read the airtime note there first).
// ===========================================================================
struct IdentityRow {
    uint8_t seed[ED25519_SEED_BYTES];
    uint8_t pubkey[ED25519_PUBKEY_BYTES];
    uint8_t det[DET_BYTES];
};

static const IdentityRow IDENTITY_TABLE[DET_IDENTITY_SLOTS] = {
    // -----------------------------------------------------------------------
    // SLOT 0 — the ORIGINAL single-drone PoC identity (unchanged)
    //   seed origin : recorded on-device in sub-step 1a (legacy — predates the slot table)
    //   DET         : 2001:30:fa07:d005:31e0:1aed:4e7e:cf5c
    // -----------------------------------------------------------------------
    {
      {   // seed (Ed25519 private, RFC 8032)
          0x56, 0x8B, 0xF5, 0xE8, 0xF0, 0x8A, 0xBA, 0xAD,
          0xB6, 0x8B, 0xA1, 0x96, 0x4B, 0xC2, 0x5F, 0x29,
          0x76, 0xA8, 0xAF, 0xC9, 0x38, 0x24, 0x4A, 0x39,
          0xF7, 0x6E, 0x0A, 0xB0, 0xC7, 0x03, 0xCC, 0xD6
      },
      {   // pubkey (HI) — derived from the seed; self-checked at boot
          0x8B, 0x65, 0xB2, 0x65, 0xA4, 0x96, 0xE3, 0x20,
          0x46, 0xCF, 0xA3, 0x78, 0xB5, 0xA5, 0xFB, 0x2E,
          0x87, 0x7A, 0x97, 0x72, 0x3E, 0x55, 0x7C, 0xB5,
          0xF0, 0xD2, 0x18, 0x48, 0xBF, 0xE9, 0x44, 0x77
      },
      {   // expected DET — cSHAKE128 ORCHID, RFC 9374 3.5.2; self-checked at boot
          0x20, 0x01, 0x00, 0x30, 0xFA, 0x07, 0xD0, 0x05,
          0x31, 0xE0, 0x1A, 0xED, 0x4E, 0x7E, 0xCF, 0x5C
      }
    },
    // -----------------------------------------------------------------------
    // SLOT 1 — fleet slot 1
    //   seed origin : shake128(b"DRIP PoC UA slot 1", 32)
    //   DET         : 2001:30:fa07:d005:f3b6:6f58:e30e:ad97
    // -----------------------------------------------------------------------
    {
      {   // seed (Ed25519 private, RFC 8032)
          0xF5, 0xD2, 0x2D, 0x33, 0x08, 0x69, 0xD9, 0x06,
          0x0A, 0x97, 0x29, 0x64, 0x19, 0x1B, 0xEB, 0xA9,
          0xF6, 0xCC, 0xA4, 0xBD, 0x36, 0x10, 0xE8, 0x76,
          0x19, 0xE4, 0x78, 0x2D, 0x16, 0x4A, 0x56, 0x66
      },
      {   // pubkey (HI) — derived from the seed; self-checked at boot
          0xF7, 0xD7, 0x92, 0xE5, 0xDD, 0x00, 0x0E, 0x8C,
          0x05, 0xDC, 0xEE, 0xB3, 0x57, 0xD0, 0x3A, 0xF1,
          0x77, 0x0B, 0x0D, 0x7D, 0x6B, 0xFE, 0x42, 0x9A,
          0xAB, 0xBD, 0x3C, 0x3F, 0x1C, 0xB1, 0x6F, 0xE2
      },
      {   // expected DET — cSHAKE128 ORCHID, RFC 9374 3.5.2; self-checked at boot
          0x20, 0x01, 0x00, 0x30, 0xFA, 0x07, 0xD0, 0x05,
          0xF3, 0xB6, 0x6F, 0x58, 0xE3, 0x0E, 0xAD, 0x97
      }
    },
    // -----------------------------------------------------------------------
    // SLOT 2 — fleet slot 2
    //   seed origin : shake128(b"DRIP PoC UA slot 2", 32)
    //   DET         : 2001:30:fa07:d005:5584:4fa7:8f0d:14d7
    // -----------------------------------------------------------------------
    {
      {   // seed (Ed25519 private, RFC 8032)
          0x6C, 0xFF, 0xCF, 0x5B, 0x80, 0xCF, 0x70, 0xE5,
          0x85, 0x34, 0x6E, 0xB4, 0x7E, 0x9A, 0x8B, 0x41,
          0xCA, 0x88, 0x4C, 0xBA, 0x8B, 0x1D, 0xBE, 0x45,
          0x62, 0x6D, 0x1C, 0xBC, 0xD5, 0xCD, 0x7C, 0x77
      },
      {   // pubkey (HI) — derived from the seed; self-checked at boot
          0xB8, 0x0B, 0xC2, 0x63, 0x96, 0x24, 0x20, 0xFB,
          0xF1, 0x45, 0x4E, 0x61, 0xBB, 0x14, 0x9F, 0xCD,
          0x1B, 0xDC, 0x44, 0x71, 0x95, 0xB1, 0x2D, 0x63,
          0xC6, 0x9E, 0x7F, 0xB7, 0xAE, 0xAA, 0xC3, 0xAC
      },
      {   // expected DET — cSHAKE128 ORCHID, RFC 9374 3.5.2; self-checked at boot
          0x20, 0x01, 0x00, 0x30, 0xFA, 0x07, 0xD0, 0x05,
          0x55, 0x84, 0x4F, 0xA7, 0x8F, 0x0D, 0x14, 0xD7
      }
    },
};
// ===========================================================================

// ---------------------------------------------------------------------------
// DRIP DET ORCHID Context ID — RFC 9374 §3 (Figure 1) / IANA CGA Type Tag.
// 0x00B5A69C795DF5D5F0087F56843F2C40
// ---------------------------------------------------------------------------
static const uint8_t DET_CONTEXT_ID[16] = {
    0x00, 0xB5, 0xA6, 0x9C, 0x79, 0x5D, 0xF5, 0xD5,
    0xF0, 0x08, 0x7F, 0x56, 0x84, 0x3F, 0x2C, 0x40
};

// ---------------------------------------------------------------------------
// Build the upper 64 bits of the DET — RFC 9374 Figure 1 (bit-packed):
//   Prefix(28) | RAA(14) | HDA(14) | Suite(8)  ->  8 bytes, big-endian.
// For RAA=1000, HDA=2000, Suite=5 this yields 20 01 00 30 FA 07 D0 05.
// ---------------------------------------------------------------------------
static void build_upper64(uint16_t raa, uint16_t hda, uint8_t suite,
                          uint8_t out[8]) {
    const uint32_t prefix28 = 0x2001003u;          // top 28 bits of 2001:0030::/28
    uint64_t v = 0;
    v |= (uint64_t)(prefix28 & 0x0FFFFFFFu) << 36;  // bits [63:36]
    v |= (uint64_t)(raa      & 0x3FFFu)     << 22;  // bits [35:22]
    v |= (uint64_t)(hda      & 0x3FFFu)     <<  8;  // bits [21:8]
    v |= (uint64_t)(suite    & 0xFFu);              // bits [7:0]
    for (int i = 0; i < 8; i++)
        out[i] = (uint8_t)(v >> (56 - 8 * i));      // serialise big-endian
}

// ---------------------------------------------------------------------------
// DET computation — RFC 9374 §3.5.2, parameterised by (RAA, HDA).
//   ORCHID input := upper64(8) || HOST_ID(36)                    (44 bytes)
//   HOST_ID (EdDSA25519, RFC 9374 §3.4.1.1 Fig 2, per RFC 9373):
//       EdDSA Curve(0x0001) | NULL(0x0000) | PublicKey(32)       (36 bytes)
//   hash    := cSHAKE128(ORCHID input, L=64 bits, N="", S=Context ID)
//   DET     := upper64(8) || hash(8)                             (16 bytes)
//
// This is the SINGLE DET implementation in the codebase. Every UA slot uses it,
// and the test build's parent DETs use it too (drip_registration.cpp), so the
// two can never diverge — that divergence was exactly the bug that produced
// non-conformant parent DETs.
// ---------------------------------------------------------------------------
void det_compute(const uint8_t pubkey[ED25519_PUBKEY_BYTES],
                 uint16_t raa, uint16_t hda, uint8_t det[DET_BYTES]) {
    uint8_t upper[8];
    build_upper64(raa, hda, HHIT_OGA_ID, upper);

    uint8_t orchid_input[8 + 36];
    memcpy(orchid_input, upper, 8);
    orchid_input[8]  = 0x00; orchid_input[9]  = 0x01;   // EdDSA Curve = 1 (EdDSA25519)
    orchid_input[10] = 0x00; orchid_input[11] = 0x00;   // NULL
    memcpy(&orchid_input[12], pubkey, 32);              // Public Key (32)

    uint8_t hash[8];
    cshake128(orchid_input, sizeof(orchid_input),       // input (44 bytes)
              DET_CONTEXT_ID, sizeof(DET_CONTEXT_ID),   // S = Context ID
              hash, 64);                                // L = 64 bits

    memcpy(det,      upper, 8);                          // DET = upper64 || hash
    memcpy(&det[8],  hash,  8);
}

// ---------------------------------------------------------------------------
void det_print(const char *label, const uint8_t det[DET_BYTES]) {
    Serial.print(label);
    for (int i = 0; i < DET_BYTES; i++) {
        Serial.printf("%02X", det[i]);
        if (i % 2 == 1 && i != DET_BYTES - 1) Serial.print(":");
    }
    Serial.println();
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------
bool det_load_identity(uint8_t slot, DETIdentity &out) {
    memset(&out, 0, sizeof(out));
    out.valid = false;

    if (slot >= DET_IDENTITY_SLOTS) {
        Serial.printf("[DET] slot %u out of range (have %u)\n",
                      (unsigned)slot, (unsigned)DET_IDENTITY_SLOTS);
        return false;
    }

    const IdentityRow &row = IDENTITY_TABLE[slot];
    memcpy(out.seed, row.seed, ED25519_SEED_BYTES);

    // Self-check 1: does the seed really produce the recorded public key?
    Ed25519::derivePublicKey(out.pubkey, (uint8_t *)row.seed);
    if (memcmp(out.pubkey, row.pubkey, ED25519_PUBKEY_BYTES) != 0) {
        Serial.printf("[DET] slot %u WARNING: derived pubkey != table pubkey — "
                      "the seed/pubkey pair in IDENTITY_TABLE is inconsistent.\n",
                      (unsigned)slot);
    }

    // Self-check 2: does that public key really produce the recorded DET?
    // (RFC 9374 §3.5.2 — this is the DET<->HI binding an observer re-derives.)
    det_compute(out.pubkey, HHIT_TEST_RAA, HHIT_TEST_HDA, out.det);
    if (memcmp(out.det, row.det, DET_BYTES) != 0) {
        Serial.printf("[DET] slot %u WARNING: computed DET != table DET — "
                      "regenerate the table (see the Python snippet in this file).\n",
                      (unsigned)slot);
        det_print("[DET]   computed = ", out.det);
        det_print("[DET]   table    = ", row.det);
    }

    out.valid = true;
    return true;
}

bool det_load_hardcoded(DETIdentity &out) {
    // Slot 0 is, by construction, the original single-drone PoC identity.
    return det_load_identity(0, out);
}

bool det_sign_with(const DETIdentity &id,
                   const uint8_t *data, size_t len, uint8_t sig[64]) {
    memset(sig, 0, 64);
    if (!id.valid) {
        Serial.println("[DET] identity invalid — cannot sign");
        return false;
    }
    // Ed25519 (RFC 8032) is deterministic, so this signature is byte-identical
    // to the one ed25519.py produces for the same key + message. That is what
    // lets make_vectors.py cross-check the firmware offline.
    Ed25519::sign(sig, (uint8_t *)id.seed, (uint8_t *)id.pubkey, data, len);
    return true;
}

void det_to_session_id(const uint8_t det[DET_BYTES], uint8_t out[SESSION_ID_BYTES]) {
    out[0] = 0x01;                       // SSI Type 1 = IETF DRIP (ASTM Table 5 / Annex A5)
    memcpy(&out[1], det, DET_BYTES);     // 16-byte DET
    memset(&out[17], 0x00, 3);           // null padding to 20 bytes
}
