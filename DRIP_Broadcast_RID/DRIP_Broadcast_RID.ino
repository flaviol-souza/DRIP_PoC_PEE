// DRIP Broadcast RID — ESP32 Firmware
//
// Implements ASTM F3411-22a Broadcast Remote ID over WiFi Beacon
// with DRIP authentication (RFC 9374 DET + RFC 9575 Link + Wrapper + Manifest).
//
// Transmission cycle — 3 Hz, rotating across three phases:
//
//   Cycle A (g_cycle % 3 == 0)  — DRIP Wrapper  — 8 messages
//     [0] Basic ID   [1] Location   [2] System   [3-7] Auth Wrapper (5 pages,
//     Extended Transport, RFC 9575 §4.3.2 — Evidence cleared on the wire)
//
//   Cycle B (g_cycle % 3 == 1)  — DRIP Link / BE chain — 9 messages
//     [0] Basic ID   [1] Location   [2-8] Auth Link (7 pages, BE Figure 5)
//     *** System is intentionally NOT sent in Cycle B — see CYCLE-B NOTE below.
//
//   Cycle C (g_cycle % 3 == 2)  — DRIP Manifest — 9 messages
//     [0] Basic ID   [1] Location   [2] System   [3-8] Auth Manifest (6 pages)
//
// ---------------------------------------------------------------------------
// CYCLE-B NOTE (design decision — please confirm)
//   A compliant DRIP Link is a Broadcast Endorsement of 137 octets = 7 ASTM
//   Auth pages (RFC 9575 §4.2, Appendix B.1). Basic ID + Location + System +
//   7 Link pages = 10 messages, but a Message Pack in one 802.11 VSIE is capped
//   at 9 messages / 255-byte IE body (message_pack.h). To fit, Cycle B carries
//   Basic ID + Location + the 7 Link pages (= 9). System is omitted from Cycle B
//   only; it is still broadcast in Cycles A and C (it is a static message, so
//   its refresh rate is unaffected). Reversible if you prefer the Link in its
//   own dedicated pack/beacon instead.
// ---------------------------------------------------------------------------
//
// DRIP_TEST_BE: compile-time switch that provisions a SELF-CONSISTENT fake
// Apex/RAA/HDA Broadcast Endorsement chain (drip_registration.*) so the Link
// and signatures can be validated against a DRIP receiver. *** Never enable in
// a production/flight image. *** Comment it out to build without a Link.

// Build flags live in drip_config.h so DRIP_TEST_BE reaches ALL .cpp files
// (an .ino #define is local to the sketch translation unit only).
#include "drip_config.h"   // defines DRIP_TEST_BE for the test/validation build

#include <Arduino.h>

extern "C" {
#include "nvs_flash.h"
#include "esp_netif.h"
#include "esp_event.h"
}

#include "det_generator.h"
#include "f3411_messages.h"
#include "message_pack.h"
#include "drip_time.h"       // drip_timestamp() - DRIP-epoch seconds
#include "drip_auth.h"       // DRIP Wrapper  (Cycle A)
#include "drip_link.h"       // DRIP Link / BE (Cycle B)
#include "drip_manifest.h"   // DRIP Manifest (Cycle C)
#include "drip_registration.h" // test BE chain (DRIP_TEST_BE only)
#include "beacon_tx.h"
#include "flight_sim.h"
#include "drone_playback.h" // recorded-track playback (drone_data.h)
#include "drip_debug.h"

// ---------------------------------------------------------------------------
static DETKeyPair         g_kp;
static DRIPManifestState  g_manifest;
static uint8_t            g_msg_counter = 0;
static uint32_t           g_cycle       = 0;

// Recorded-track playback state.
//   g_use_playback : true when drone_data.h loaded; false -> synthetic flight_sim route
//   g_tx_stopped   : true while HALTED at the end of a track (VSIE removed)
static bool               g_use_playback = false;
static bool               g_tx_stopped   = false;

// ---------------------------------------------------------------------------
void setup() {
    Serial.begin(115200);
    delay(500);
    Serial.println("\n=== DRIP Broadcast RID -- ESP32 ===");
    Serial.println("    3-cycle rotation (Wrapper / Link / Manifest) at 3 Hz");

    esp_err_t nvs = nvs_flash_init();
    if (nvs == ESP_ERR_NVS_NO_FREE_PAGES || nvs == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs = nvs_flash_init();
    }
    ESP_ERROR_CHECK(nvs);
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    if (!det_load_hardcoded(g_kp)) {
        Serial.println("[WARN] Ed25519 unavailable -- signatures will be zero-filled");
    }
    // NOTE: det_load_hardcoded() already prints "[DET] DET = ..." and the
    // "[DET] expected (PoC) = ..." check above. A duplicate print here (the
    // older "[DET] HHIT: ..." line) was removed to avoid two labels for the
    // same bytes confusing the serial log.

    beacon_tx_init();
    drip_manifest_init(&g_manifest);

#ifdef DRIP_TEST_BE
    // Fabricate the self-consistent fake 3-link BE chain (needs the real UA
    // DET + HI, which det_load_hardcoded() has now produced).
    drip_reg_init(g_kp.det, g_kp.pubkey);
#endif

    // Recorded-track playback. Falls back to the synthetic route if drone_data.h
    // has no flights, so the DRIP path is exercised either way.
    g_use_playback = drone_playback_init();
    if (!g_use_playback)
        Serial.println("[Playback] falling back to the simulated flight route");

    Serial.println("[OK] Setup complete -- broadcasting at 3 Hz");
}

// ---------------------------------------------------------------------------
void loop() {
    uint32_t now_ms      = millis();
    uint8_t  cycle_phase = (uint8_t)(g_cycle % 3);

    // Poll the serial monitor for flight selection (list | info | next | reset | <n>)
    drone_playback_cmd();

    // ---- HALT AT END OF TRACK ------------------------------------------------
    // The selected flight has been fully transmitted. Remove the DRIP vendor IE
    // once, then idle: no Message Pack is built, nothing is signed, the Manifest
    // hash chain does not advance, and the message counter stops. Transmission
    // resumes the moment the operator selects a flight (or 'reset') on serial.
    if (g_use_playback && drone_playback_finished()) {
        if (!g_tx_stopped) {
            beacon_tx_stop();          // clears the VSIE -> no Remote ID on the air
            g_tx_stopped = true;
        }
        delay(50);                     // do not spin while polling serial
        return;
    }
    g_tx_stopped = false;              // a flight was (re)selected -> resume TX

    // Position source: recorded track, else the synthetic route.
    // NOTE: while DRONE_REPLAY_RECORDED_TIME == 1 (drone_playback.h) the argument
    // is ignored and the point's RECORDED timestamp is used instead. DRIP VNB/VNA
    // still come from drip_timestamp() and remain RFC 9575 3.2.4.3 conformant.
    DronePosition pos;
    if (g_use_playback)
        pos = drone_playback_next(drip_timestamp() + 1546300800u);   // live clock
    else
        pos = flight_sim_get_position(now_ms);

    uint8_t session_id[SESSION_ID_BYTES];
    det_to_session_id(g_kp.det, session_id);

    F3411BasicID  basic_id  = f3411_build_basic_id(session_id);
    F3411Location location  = f3411_build_location(pos);

    double op_lat, op_lon; float op_alt;
    if (g_use_playback) drone_playback_get_launch(&op_lat, &op_lon, &op_alt);
    else                flight_sim_get_launch(&op_lat, &op_lon, &op_alt);
    F3411System system_msg  = f3411_build_system(op_lat, op_lon, op_alt);

    // Common to all cycles: Basic ID + Location. System is added per-cycle
    // (A and C only — see CYCLE-B NOTE at top of file).
    MessagePack pack;
    message_pack_init(&pack);
    message_pack_add(&pack, (const uint8_t *)&basic_id);
    message_pack_add(&pack, (const uint8_t *)&location);

    switch (cycle_phase) {

        // ---- Cycle A: DRIP Wrapper (RFC 9575 §4.3) ----
        case 0: {
            message_pack_add(&pack, (const uint8_t *)&system_msg);

            uint8_t wrapper[DRIP_WRAPPER_MAX_PAGES][F3411_MSG_BYTES];
            uint8_t wrapper_pages = 0;
           //OLD// drip_wrapper_build(g_kp.det, (const uint8_t *)&location, wrapper, &wrapper_pages);
            drip_wrapper_build(g_kp.det, &pack, wrapper, &wrapper_pages); //New
            for (uint8_t i = 0; i < wrapper_pages; i++)
                message_pack_add(&pack, wrapper[i]);

            drip_manifest_update_pack(&g_manifest, pack.buf,
                                      message_pack_bytes(&pack));
            break;
        }

        // ---- Cycle B: DRIP Link / Broadcast Endorsement (RFC 9575 §4.2) ----
        case 1: {
#ifdef DRIP_TEST_BE
            // Pick the next link of the chain on the §6.3-approximating schedule.
            const BroadcastEndorsement *be = drip_reg_next_link();
            uint8_t link[DRIP_LINK_MAX_PAGES][F3411_MSG_BYTES];
            uint8_t link_pages = drip_link_build_be(be, link, DRIP_LINK_MAX_PAGES);
            for (uint8_t i = 0; i < link_pages; i++)
                message_pack_add(&pack, link[i]);   // 7 pages -> 2 + 7 = 9 msgs

            // The Manifest references BE:HDA,UA specifically (RFC §4.4.2), so
            // hash that one regardless of which link was transmitted this cycle.
            uint8_t hu_sam[DRIP_LINK_SAM_BYTES];
            uint8_t hu_len = drip_reg_hda_ua_sam(hu_sam);
            drip_manifest_update_link(&g_manifest, hu_sam, hu_len);
#else
            Serial.println("[Link] No Broadcast Endorsement provisioned. "
                           "Define DRIP_TEST_BE (test) or load BE records (production).");
#endif
            break;
        }

        // ---- Cycle C: DRIP Manifest (RFC 9575 §4.4) ----
        case 2: {
            message_pack_add(&pack, (const uint8_t *)&system_msg);

            uint8_t manifest[DRIP_MANIFEST_MAX_PAGES][F3411_MSG_BYTES];
            uint8_t manifest_pages = 0;
            drip_manifest_build(&g_manifest, g_kp.det, manifest, &manifest_pages);
            for (uint8_t i = 0; i < manifest_pages; i++)
                message_pack_add(&pack, manifest[i]);
            break;
        }
    }

    uint8_t tx_counter = g_msg_counter++;
    beacon_tx_send(&pack, tx_counter);
    drip_debug_print_pack(&pack, tx_counter, cycle_phase);

    g_cycle++;
    delay(333);   // 3 Hz -- full A->B->C rotation completes in ~999 ms
}
