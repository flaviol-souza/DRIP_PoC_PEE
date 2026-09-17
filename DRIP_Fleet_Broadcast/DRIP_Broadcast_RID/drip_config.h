#pragma once

// ---------------------------------------------------------------------------
// Project-wide build configuration.
//
// Put compile-time switches HERE (not in the .ino). In the Arduino build model
// each .cpp is compiled separately, and a #define in the .ino is visible only
// inside the .ino itself — it does NOT reach drip_registration.cpp etc. Defining
// the flag in this shared header (included by every unit that needs it) makes it
// consistent across all translation units.
//
// DRIP_TEST_BE : provision a self-consistent FAKE Apex/RAA/HDA Broadcast
//                Endorsement chain (drip_registration.*) for validation only.
//                *** Comment this line out for a production / flight image. ***
//
// DRIP_TX_SOFTAP : select the SoftAP transmit backend (softap_tx.*) instead of
//                the default raw 802.11 injection (beacon_tx_raw.*). SoftAP is
//                SINGLE-UA (one BSSID), so when you enable it you MUST also set
//                FLEET_MAX=1 in drone_fleet.h — the compile-time guard there
//                (#error) enforces it. See ADR 0001 and .kiro/specs/softap-broadcast.
//                Leave it commented for the multi-drone raw backend (default).
//
// DRIP_TX_BLE  : select the BLE transmit backend (ble_tx.*) — BLE 5 extended
//                advertising, BLE-only (Wi-Fi backends stay off). Single-UA in
//                the MVP, so requires FLEET_MAX=1 (guard in drone_fleet.h).
//                See ADR 0002 and .kiro/specs/ble-broadcast. Enabling it AND
//                DRIP_TX_SOFTAP is an #error below (one transport at a time).
// ---------------------------------------------------------------------------

 #define DRIP_TEST_BE

// #define DRIP_TX_SOFTAP   // single-UA SoftAP backend; requires FLEET_MAX=1
 #define DRIP_TX_BLE      // BLE-only transport (Spec 2); keeps the Wi-Fi backends off

// One transmit transport at a time. BLE is BLE-only: Wi-Fi + BLE coexistence on the
// shared 2.4 GHz radio is out of scope (README). Catch the invalid combo at build time.
#if defined(DRIP_TX_BLE) && defined(DRIP_TX_SOFTAP)
#error "DRIP_TX_BLE e single-transport (BLE-only). Nao habilite DRIP_TX_SOFTAP junto (coexistencia Wi-Fi+BLE fora de escopo)."
#endif
