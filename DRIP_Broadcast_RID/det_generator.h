#pragma once
#include <stdint.h>
#include <stddef.h>

// ---------------------------------------------------------------------------
// DRIP Entity Tag (DET) — RFC 9374
//
// A DET is an HHIT: a 128-bit self-asserting identifier derived from an
// Ed25519 public key via cSHAKE128 (ORCHID construction, RFC 7343 + RFC 9374).
//
// Bit layout of the 16-byte HHIT  — RFC 9374 §3.3, Figure 1:
//   [ Prefix 28b = 2001:0030::/28 | HID 28b = RAA14||HDA14 | HHSI 8b = 0x05 | Hash 64b ]
//   i.e. the Suite ID (HHSI/OGA) sits BETWEEN the HID and the hash (byte 7),
//   NOT right after the prefix. (Corrected per RFC 9374 Fig 1 — previously the
//   Suite and HID were swapped, which produced a non-conformant DET.)
// ---------------------------------------------------------------------------

#define DET_BYTES           16
#define ED25519_SEED_BYTES  32   // private key seed
#define ED25519_PUBKEY_BYTES 32
#define SESSION_ID_BYTES    20   // ASTM F3411-22a UAS ID field width

// Suite ID 5 = EdDSA/cSHAKE128  — RFC 9374 Table 7 (this is the HHSI/OGA value)
#define HHIT_OGA_ID         0x05

// Test hierarchy — these are the locked PoC values (RAA=1000, HDA=2000).
// Per RFC 9374 §3.3 production values MUST be obtained from the IANA DRIP
// Registry; do not use research values in deployment.
#define HHIT_TEST_RAA       1000u   // 0x03E8  (14-bit field)
#define HHIT_TEST_HDA       2000u   // 0x07D0  (14-bit field)

struct DETKeyPair {
    uint8_t det[DET_BYTES];               // the HHIT (16 bytes)
    uint8_t pubkey[ED25519_PUBKEY_BYTES];
    // Ed25519 private key is the hardcoded seed in det_generator.cpp (PoC).
};

// Derive a DET from an Ed25519 public key for an ARBITRARY (RAA, HDA) hierarchy.
// RFC 9374 §3.5.2 + Figure 1 (Suite 5, EdDSA25519 HOST_ID). This is the single
// DET implementation used both for the UA DET and, in DRIP_TEST_BE builds, for
// the fabricated Apex/RAA/HDA parent DETs (drip_registration.cpp).
void det_compute(const uint8_t pubkey[ED25519_PUBKEY_BYTES],
                 uint16_t raa, uint16_t hda, uint8_t det[DET_BYTES]);

// Load the hardcoded test keypair, derive the DET, and initialise the Ed25519
// backend. TEMPORARY: uses a fixed hardcoded seed — add NVS storage before
// deployment. The keypair to use is defined at the top of det_generator.cpp.
bool det_load_hardcoded(DETKeyPair &out);

// Sign arbitrary data with the loaded Ed25519 private key.
// Returns false if Ed25519 is not available or signing fails.
bool det_sign(const uint8_t *data, size_t len, uint8_t sig[64]);

// Encode a DET as the 20-byte ASTM F3411-22a UAS ID Session ID field.
// Byte 0 = 0x01 (SSI Type IETF DRIP), bytes 1–16 = DET, bytes 17–19 = 0x00.
// Per ASTM F3411-22a Table 5 (Specific Session ID) and RFC 9374 §4.
void det_to_session_id(const uint8_t det[DET_BYTES], uint8_t out[SESSION_ID_BYTES]);
