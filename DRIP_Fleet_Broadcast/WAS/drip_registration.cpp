#include "drip_registration.h"

#ifdef DRIP_TEST_BE

#include "drip_auth_page.h"   // for drip_put_le32()
#include "drip_time.h"
#include "det_generator.h"
#include <Ed25519.h>      // Arduino "Crypto" library (Path A)
#include <string.h>
#include <Arduino.h>

// DET derivation uses the single shared det_compute() from det_generator
// (RFC 9374 §3.5.2 / Fig 1). The previously-duplicated Context ID + compute_det()
// here were the OLD non-conformant layout and have been removed.

// ---------------------------------------------------------------------------
// Fixed TEST seeds for the fake Apex / RAA / HDA Ed25519 keypairs.
// Reproducible across runs so the receiver can cache the Apex HI once.
// *** TEST VECTORS — never use in production. ***
//
// These MUST stay byte-identical to observer.py's APEX_HI/APEX_DET and to
// make_vectors.py's _APEX_SEED/_RAA_SEED/_HDA_SEED, which hardcode the same
// values independently. Nothing enforces that agreement — it is exactly the
// gap the RFC 9886 DNS work is meant to close.
// ---------------------------------------------------------------------------
static const uint8_t APEX_SEED[32] = {
    0xA0,0xA1,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7, 0xA8,0xA9,0xAA,0xAB,0xAC,0xAD,0xAE,0xAF,
    0xB0,0xB1,0xB2,0xB3,0xB4,0xB5,0xB6,0xB7, 0xB8,0xB9,0xBA,0xBB,0xBC,0xBD,0xBE,0xBF };
static const uint8_t RAA_SEED[32] = {
    0xC0,0xC1,0xC2,0xC3,0xC4,0xC5,0xC6,0xC7, 0xC8,0xC9,0xCA,0xCB,0xCC,0xCD,0xCE,0xCF,
    0xD0,0xD1,0xD2,0xD3,0xD4,0xD5,0xD6,0xD7, 0xD8,0xD9,0xDA,0xDB,0xDC,0xDD,0xDE,0xDF };
static const uint8_t HDA_SEED[32] = {
    0xE0,0xE1,0xE2,0xE3,0xE4,0xE5,0xE6,0xE7, 0xE8,0xE9,0xEA,0xEB,0xEC,0xED,0xEE,0xEF,
    0xF0,0xF1,0xF2,0xF3,0xF4,0xF5,0xF6,0xF7, 0xF8,0xF9,0xFA,0xFB,0xFC,0xFD,0xFE,0xFF };

// Illustrative (NON-registered) HID values for the test hierarchy.
// Only required to be internally consistent; not semantically meaningful.
//
// KNOWN DIVERGENCE (tracked, deliberately NOT fixed yet): these do not line up
// with the UA's own HID (RAA=1000/HDA=2000, det_generator.h). A real hierarchy
// would have the endorsing RAA/HDA numbered consistently with the UAs they
// register — and RFC 9886 derives the DNS zones from exactly those nibbles, so
// this must be reconciled before a faithful DNS demo. It does not affect the
// offline signature walk, which is why it is safe to defer.
#define APEX_RAA 0x0000u
#define APEX_HDA 0x0000u
#define RAA_RAA  0x0001u
#define RAA_HDA  0x0000u
#define HDA_RAA  0x0001u
#define HDA_HDA  0x0001u

// ---------------------------------------------------------------------------
// State
//
// The two upper links are SHARED by every UA (one HDA, endorsed once, registers
// all of them). Only the leaf BE is per-UA.
// ---------------------------------------------------------------------------
static BroadcastEndorsement g_be_apex_raa;                        // child = RAA, parent = Apex
static BroadcastEndorsement g_be_raa_hda;                         // child = HDA, parent = RAA
static BroadcastEndorsement g_be_hda_ua[DET_IDENTITY_SLOTS];      // child = UA_i, parent = HDA
static bool                 g_slot_ready[DET_IDENTITY_SLOTS];
static uint8_t              g_rot_idx[DET_IDENTITY_SLOTS];        // per-slot Cycle-B cursor
static uint8_t              g_n_slots   = 0;
static bool                 g_reg_ready = false;

// Build the 72-octet signed region: VNB||VNA||DET_child||HI_child||DET_parent.
static void be_signed_region(const BroadcastEndorsement *be, uint8_t buf[72]) {
    drip_put_le32(&buf[0], be->vnb);
    drip_put_le32(&buf[4], be->vna);
    memcpy(&buf[8],  be->det_child,  DET_BYTES);        // [8..23]
    memcpy(&buf[24], be->hi_child,   DRIP_BE_HI_BYTES); // [24..55]
    memcpy(&buf[56], be->det_parent, DET_BYTES);        // [56..71]
}

// Fill one BE and sign it with the parent's private seed.
static void make_be(BroadcastEndorsement *be,
                    uint32_t vnb, uint32_t vna,
                    const uint8_t det_child[DET_BYTES],
                    const uint8_t hi_child[DRIP_BE_HI_BYTES],
                    const uint8_t det_parent[DET_BYTES],
                    const uint8_t parent_seed[32],
                    const uint8_t parent_pub[32]) {
    memset(be, 0, sizeof(*be));
    be->vnb = vnb;
    be->vna = vna;
    memcpy(be->det_child,  det_child,  DET_BYTES);
    memcpy(be->hi_child,   hi_child,   DRIP_BE_HI_BYTES);
    memcpy(be->det_parent, det_parent, DET_BYTES);

    uint8_t region[72];
    be_signed_region(be, region);
    Ed25519::sign(be->sig, (uint8_t *)parent_seed, (uint8_t *)parent_pub,
                  region, sizeof(region));
}

// ---------------------------------------------------------------------------
void drip_reg_init_fleet(const DETIdentity *ids, uint8_t n) {
    Serial.println(F("[REG] *** DRIP_TEST_BE: fabricating a FAKE Broadcast "
                     "Endorsement chain — TEST/VALIDATION ONLY, not for flight ***"));

    memset(g_slot_ready, 0, sizeof(g_slot_ready));
    memset(g_rot_idx,    0, sizeof(g_rot_idx));
    g_reg_ready = false;
    g_n_slots   = 0;

    if (n == 0 || n > DET_IDENTITY_SLOTS) {
        Serial.printf("[REG] ERROR: n=%u out of range (1..%u)\n",
                      (unsigned)n, (unsigned)DET_IDENTITY_SLOTS);
        return;
    }

    // Derive the three parent public keys + DETs.
    uint8_t apex_pub[32], raa_pub[32], hda_pub[32];
    Ed25519::derivePublicKey(apex_pub, (uint8_t *)APEX_SEED);
    Ed25519::derivePublicKey(raa_pub,  (uint8_t *)RAA_SEED);
    Ed25519::derivePublicKey(hda_pub,  (uint8_t *)HDA_SEED);

    uint8_t det_apex[DET_BYTES], det_raa[DET_BYTES], det_hda[DET_BYTES];
    det_compute(apex_pub, APEX_RAA, APEX_HDA, det_apex);
    det_compute(raa_pub,  RAA_RAA,  RAA_HDA,  det_raa);
    det_compute(hda_pub,  HDA_RAA,  HDA_HDA,  det_hda);

    uint32_t vnb = drip_timestamp();
    uint32_t vna = vnb + DRIP_BE_VALIDITY_S;

    // ---- shared upper links -------------------------------------------------
    // BE: Apex,RAA — child = RAA, signed by Apex
    make_be(&g_be_apex_raa, vnb, vna, det_raa, raa_pub, det_apex, APEX_SEED, apex_pub);
    // BE: RAA,HDA — child = HDA, signed by RAA
    make_be(&g_be_raa_hda,  vnb, vna, det_hda, hda_pub, det_raa,  RAA_SEED,  raa_pub);

    // ---- one leaf BE per UA (RFC 9575 §6.4.2: every UA must chain up) -------
    for (uint8_t s = 0; s < n; s++) {
        make_be(&g_be_hda_ua[s], vnb, vna,
                ids[s].det, ids[s].pubkey,     // child = this UA
                det_hda, HDA_SEED, hda_pub);   // parent = the shared HDA
        g_slot_ready[s] = true;
    }

    g_n_slots   = n;
    g_reg_ready = true;

    det_print("[REG] Apex DET: ", det_apex);
    det_print("[REG] RAA  DET: ", det_raa);
    det_print("[REG] HDA  DET: ", det_hda);
    Serial.printf("[REG] chain signed: 2 shared links + %u leaf BE(s). VNB=%u VNA=%u\n",
                  (unsigned)n, vnb, vna);
    for (uint8_t s = 0; s < n; s++) {
        char lbl[24];
        snprintf(lbl, sizeof(lbl), "[REG]  BE:HDA,UA[%u] -> ", (unsigned)s);
        det_print(lbl, g_be_hda_ua[s].det_child);
    }
}

const BroadcastEndorsement *drip_reg_next_link(uint8_t slot) {
    if (!g_reg_ready || slot >= DET_IDENTITY_SLOTS || !g_slot_ready[slot])
        return nullptr;

    // Test rotation over 6 Cycle-B slots. Approximates §6.3 priority
    // (HDA,UA dominant; the higher links interspersed). Production firmware
    // should instead drive this from §6.3 wall-clock timers
    // (HDA,UA >= 1/min; RAA,HDA & Apex,RAA >= 1/5 min).
    //
    // Multi-drone change: the cursor is PER SLOT (was one shared static), so
    // each virtual UA walks its own rotation independently.
    static const uint8_t pattern[6] = { 0, 0, 0, 0, 1, 2 };  // 0=HDA,UA 1=RAA,HDA 2=Apex,RAA
    uint8_t sel = pattern[g_rot_idx[slot]];
    g_rot_idx[slot] = (uint8_t)((g_rot_idx[slot] + 1) % 6);

    switch (sel) {
        case 1:  return &g_be_raa_hda;
        case 2:  return &g_be_apex_raa;
        default: return &g_be_hda_ua[slot];
    }
}

uint8_t drip_reg_hda_ua_sam(uint8_t slot, uint8_t out[DRIP_LINK_SAM_BYTES]) {
    if (!g_reg_ready || slot >= DET_IDENTITY_SLOTS || !g_slot_ready[slot]) {
        memset(out, 0, DRIP_LINK_SAM_BYTES);
        return 0;
    }
    drip_link_serialize_sam(&g_be_hda_ua[slot], out);
    return DRIP_LINK_SAM_BYTES;
}

#endif // DRIP_TEST_BE
