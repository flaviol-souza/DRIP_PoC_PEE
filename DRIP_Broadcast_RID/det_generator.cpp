#include "det_generator.h"
#include "cshake128.h"
#include <string.h>
#include <Arduino.h>

// ===========================================================================
//  >>>>>>>>>>>>>>>>>>>>>>>>  UA KEYPAIR — EDIT HERE  <<<<<<<<<<<<<<<<<<<<<<<<<
//
//  This is the ONLY place to change the identity keypair for the PoC.
//  After changing it:
//    1. Run the matching Python:  det.compute_det(UA_PUB, 1000, 2000, 5)
//       (or the keygen sketch + det.py) to learn the DET for the new key.
//    2. Flash; det_load_hardcoded() prints the on-device DET at boot —
//       it MUST equal the DET you computed in step 1.
//
//  UA_PRIV_SEED : 32-byte Ed25519 private seed (RFC 8032 secret scalar seed).
//  UA_PUB       : 32-byte Ed25519 public key that corresponds to the seed.
//                 (Derived from the seed at boot and self-checked — see below.)
//
//  Current values are the PoC identity generated on-device in sub-step 1a:
//    UA_DET (expected) = 2001:0030:FA07:D005:31E0:1AED:4E7E:CF5C
//                      = 20010030FA07D00531E01AED4E7ECF5C
// ===========================================================================
static const uint8_t UA_PRIV_SEED[32] = {
    0x56, 0x8B, 0xF5, 0xE8, 0xF0, 0x8A, 0xBA, 0xAD,
    0xB6, 0x8B, 0xA1, 0x96, 0x4B, 0xC2, 0x5F, 0x29,
    0x76, 0xA8, 0xAF, 0xC9, 0x38, 0x24, 0x4A, 0x39,
    0xF7, 0x6E, 0x0A, 0xB0, 0xC7, 0x03, 0xCC, 0xD6
};
static const uint8_t UA_PUB[32] = {
    0x8B, 0x65, 0xB2, 0x65, 0xA4, 0x96, 0xE3, 0x20,
    0x46, 0xCF, 0xA3, 0x78, 0xB5, 0xA5, 0xFB, 0x2E,
    0x87, 0x7A, 0x97, 0x72, 0x3E, 0x55, 0x7C, 0xB5,
    0xF0, 0xD2, 0x18, 0x48, 0xBF, 0xE9, 0x44, 0x77
};
// ===========================================================================

// ---------------------------------------------------------------------------
// Ed25519 backend — select ONE path by (un)commenting the define below.
//
// Path A (Arduino Crypto library — RECOMMENDED for arduino-esp32):
//   Sketch → Include Library → Manage Libraries → install "Crypto" (Rhys
//   Weatherley), then leave USE_ARDUINO_CRYPTO_LIB defined.
//
// Path B (PSA Crypto): comment the define; PSA is attempted automatically.
//   If psa_import_key returns NOT_SUPPORTED, switch back to Path A.
//
// If neither path works, signatures are zero-filled but the beacon still
// transmits and the DET remains valid (useful for format-only testing).
// ---------------------------------------------------------------------------
#define USE_ARDUINO_CRYPTO_LIB

#ifdef USE_ARDUINO_CRYPTO_LIB
  #include <Ed25519.h>
#else
  extern "C" {
    #include "psa/crypto.h"
  }
#endif

// ---------------------------------------------------------------------------
// DRIP DET ORCHID Context ID — RFC 9374 §3 (Figure 1) / IANA CGA Type Tag.
// 0x00B5A69C795DF5D5F0087F56843F2C40
// ---------------------------------------------------------------------------
static const uint8_t DET_CONTEXT_ID[16] = {
    0x00, 0xB5, 0xA6, 0x9C, 0x79, 0x5D, 0xF5, 0xD5,
    0xF0, 0x08, 0x7F, 0x56, 0x84, 0x3F, 0x2C, 0x40
};

// ---------------------------------------------------------------------------
// Internal state
#ifndef USE_ARDUINO_CRYPTO_LIB
static psa_key_id_t g_key_id = PSA_KEY_ID_NULL;
#endif
static bool g_signing_ok = false;

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
// This is the SINGLE DET implementation in the codebase. The UA DET uses it
// (via det_load_hardcoded with RAA=1000, HDA=2000); the test build's parent
// DETs use it too (drip_registration.cpp), so the two can never diverge — the
// divergence was exactly the bug that produced non-conformant parent DETs.
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
// Small helper: print a DET as an IPv6-style hex string for boot-time check.
// ---------------------------------------------------------------------------
static void print_det(const uint8_t det[DET_BYTES]) {
    Serial.print("[DET] DET = ");
    for (int i = 0; i < DET_BYTES; i++) {
        Serial.printf("%02X", det[i]);
        if (i % 2 == 1 && i != DET_BYTES - 1) Serial.print(":");
    }
    Serial.println();
    Serial.println("[DET] expected (PoC) = 2001:0030:FA07:D005:31E0:1AED:4E7E:CF5C");
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------
bool det_load_hardcoded(DETKeyPair &out) {
    g_signing_ok = false;

#ifdef USE_ARDUINO_CRYPTO_LIB
    // Path A: derive the public key from the seed and self-check it == UA_PUB.
    Ed25519::derivePublicKey(out.pubkey, (uint8_t *)UA_PRIV_SEED);
    if (memcmp(out.pubkey, UA_PUB, 32) != 0) {
        Serial.println("[DET] WARNING: derived public key != UA_PUB.");
        Serial.println("[DET]          UA_PRIV_SEED and UA_PUB are inconsistent — fix the keypair block.");
    }
    det_compute(out.pubkey, HHIT_TEST_RAA, HHIT_TEST_HDA, out.det);
    g_signing_ok = true;
    Serial.println("[DET] Ed25519 backend: Arduino Crypto library");
    print_det(out.det);
    return true;

#else
    // Path B: PSA Crypto API
    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS && status != PSA_ERROR_ALREADY_EXISTS) {
        Serial.printf("[DET] psa_crypto_init failed: %d\n", (int)status);
        goto fallback;
    }
    {
        psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
        psa_set_key_type(&attr,
            PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS));
        psa_set_key_bits(&attr, 255);
        psa_set_key_algorithm(&attr, PSA_ALG_PURE_EDDSA);
        psa_set_key_usage_flags(&attr,
            PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_EXPORT);

        status = psa_import_key(&attr, UA_PRIV_SEED, sizeof(UA_PRIV_SEED), &g_key_id);
        if (status != PSA_SUCCESS) {
            Serial.printf("[DET] psa_import_key failed: %d\n"
                          "      -> install 'Crypto' (Rhys Weatherley) and define\n"
                          "         USE_ARDUINO_CRYPTO_LIB in det_generator.cpp\n",
                          (int)status);
            goto fallback;
        }
        size_t pk_len;
        psa_export_public_key(g_key_id, out.pubkey, 32, &pk_len);
        if (memcmp(out.pubkey, UA_PUB, 32) != 0)
            Serial.println("[DET] WARNING: exported public key != UA_PUB.");
        g_signing_ok = true;
        Serial.println("[DET] Ed25519 backend: PSA Crypto");
    }
    det_compute(out.pubkey, HHIT_TEST_RAA, HHIT_TEST_HDA, out.det);
    print_det(out.det);
    return true;

fallback:
    memcpy(out.pubkey, UA_PUB, 32);
    det_compute(out.pubkey, HHIT_TEST_RAA, HHIT_TEST_HDA, out.det);
    print_det(out.det);
    Serial.println("[WARN] Ed25519 unavailable — signatures will be zero-filled");
    return false;
#endif
}

bool det_sign(const uint8_t *data, size_t len, uint8_t sig[64]) {
    memset(sig, 0, 64);
    if (!g_signing_ok) {
        Serial.println("[DET] No key loaded — cannot sign");
        return false;
    }

#ifdef USE_ARDUINO_CRYPTO_LIB
    Ed25519::sign(sig, (uint8_t *)UA_PRIV_SEED, (uint8_t *)UA_PUB, data, len);
    return true;
#else
    size_t sig_len;
    psa_status_t st = psa_sign_message(g_key_id, PSA_ALG_PURE_EDDSA,
                                        data, len, sig, 64, &sig_len);
    if (st != PSA_SUCCESS) {
        Serial.printf("[DET] psa_sign_message failed: %d\n", (int)st);
        return false;
    }
    return true;
#endif
}

void det_to_session_id(const uint8_t det[DET_BYTES], uint8_t out[SESSION_ID_BYTES]) {
    out[0] = 0x01;                       // SSI Type 1 = IETF DRIP (ASTM Table 5 / Annex A5)
    memcpy(&out[1], det, DET_BYTES);     // 16-byte DET
    memset(&out[17], 0x00, 3);           // null padding to 20 bytes
}
