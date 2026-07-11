#pragma once
#include <stdint.h>
#include "drip_config.h"   // defines DRIP_TEST_BE — MUST be visible in every
                           // translation unit, not just the .ino (Arduino quirk)
#include "drip_link.h"

// ---------------------------------------------------------------------------
// DRIP test registration / Broadcast Endorsement chain  — VALIDATION ONLY
//
//   *** This entire unit is compiled ONLY when DRIP_TEST_BE is defined. ***
//   *** It MUST NOT be compiled into a production / flight image.       ***
//
// Purpose (agreed scope): fabricate a SELF-CONSISTENT three-link BE chain so the
// encoder, the 7-page Link framing, and the signed-field ordering can be
// validated end-to-end against a DRIP receiver — without real registration data.
//
//   Apex --(BE: Apex,RAA)--> RAA --(BE: RAA,HDA)--> HDA --(BE: HDA,UA)--> UA
//
// Each link is a REAL Ed25519 signature by the parent key over
//   VNB || VNA || DET_child || HI_child || DET_parent
// so a verifier holding the (preconfigured) Apex HI can walk the chain:
//   verify(Apex,RAA) -> trust RAA HI -> verify(RAA,HDA) -> trust HDA HI
//   -> verify(HDA,UA) -> trust the UA's DET<->HI binding.
//
// Garbage/zero fill was rejected on purpose: it would validate paging only, not
// the byte order fed to the signer, because nothing would verify.
//
// SAFETY: the parent identities use the experimental test prefix and arbitrary
// illustrative RAA/HDA values (NOT IANA-registered). No conformant verifier
// will accept this chain as a real registered hierarchy — which is exactly what
// we want for a test artefact. A loud warning is printed at init.
//
// Requires the Arduino "Crypto" library (Ed25519) — i.e. det_generator.cpp
// Path A (#define USE_ARDUINO_CRYPTO_LIB). PSA-only builds are not supported
// for test-BE signing.
// ---------------------------------------------------------------------------

#ifdef DRIP_TEST_BE

// BE validity window. BEs are long-lived registration artefacts, so VNA is set
// far ahead of VNB (unlike the ~120 s UA-signed-evidence window).
#define DRIP_BE_VALIDITY_S   86400UL   // 24 h test window

// Build the fake Apex/RAA/HDA keypairs, derive their DETs, and sign all three
// Broadcast Endorsements. Call once in setup(), after det_load_hardcoded()
// (so the real UA DET + HI are available) and after WiFi is up.
//
//   ua_det : the UA's 16-byte DET   (g_kp.det)
//   ua_hi  : the UA's 32-byte pubkey (g_kp.pubkey)
void drip_reg_init(const uint8_t ua_det[DET_BYTES],
                   const uint8_t ua_hi[DRIP_BE_HI_BYTES]);

// Return the next BE to transmit for Cycle B, rotating per a test schedule that
// approximates RFC 9575 §6.3 (HDA,UA most frequent; RAA,HDA and Apex,RAA
// interspersed). Never returns nullptr after drip_reg_init().
const BroadcastEndorsement *drip_reg_next_link(void);

// Serialise the BE:HDA,UA SAM data (137 octets) into 'out' for Manifest hashing
// (RFC §4.4.2 references BE:HDA,UA specifically). Returns the length (137).
uint8_t drip_reg_hda_ua_sam(uint8_t out[DRIP_LINK_SAM_BYTES]);

#endif // DRIP_TEST_BE
