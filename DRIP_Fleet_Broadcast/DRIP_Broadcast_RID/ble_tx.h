#pragma once
#include <stdint.h>
#include "message_pack.h"

// ---------------------------------------------------------------------------
// BLE transmit backend for ASTM F3411-22a Broadcast RID over Bluetooth — Spec 2
//
// Selected at build time by DRIP_TX_BLE (drip_config.h). This backend advertises
// the DRIP Message Pack over BLE 5 EXTENDED ADVERTISING as a "Service Data -
// 16-bit UUID" AD structure (UUID 0xFFFA, App Code 0x0D — ASTM Bluetooth
// transport). It is the transport ADAPTER selected by the scheduler's drone_emit
// seam (drone_fleet.cpp, ADR 0001 + ADR 0002), exactly like softap_tx.* is for
// Wi-Fi. The pack itself is produced by the transport-agnostic scheduler; only
// the radio layer differs.
//
// FRAMING is done by the pure, unit-testable ble_build_svcdata() (ble_frame.*).
// This unit only wraps those bytes in a BLE AD structure and drives the radio.
//
// SINGLE-UA IN THE MVP: unlike SoftAP (physically one BSSID), BLE *could* run one
// advertising set per drone (multi-drone = S2-T11, a Should). The MVP uses ONE
// set, so drone_fleet.h guards FLEET_MAX==1 for DRIP_TX_BLE — remove that guard
// when per-drone sets land. See ADR 0002.
//
// BLE-only phase: Wi-Fi + BLE coexistence on the shared 2.4 GHz radio is out of
// scope; drip_config.h #errors if DRIP_TX_BLE and DRIP_TX_SOFTAP are both set.
//
// Molde (framing only, NOT the radio API — that is Zephyr):
//   .tmp/transmitter-n52840/odid_bt.cpp
// ---------------------------------------------------------------------------

// Extended-advertising payload budget (bytes). A single ext-adv PDU carries up
// to ~254 bytes of AD data on common controllers; our largest AD is
// 2 (len+type) + 4 (UUID+AppCode+Counter) + 228 (max pack) = 234, so this is a
// safety net in the same spirit as SOFTAP_VSIE_MAX_BODY (ADR 0002, S2-T7).
#define BLE_EXT_ADV_MAX_PAYLOAD   254

// The single advertising-set instance used in the MVP (S2-T11 will add more).
#define BLE_ADV_INSTANCE          0

// Bring up the BLE stack, set a stable random-static address (HU-5) and create
// the extended-advertising set. Call once in setup() INSTEAD OF
// beacon_tx_raw_init()/softap_tx_init(). Prints a boot line (S2-T15). On a stack
// init failure it logs the error code and returns without crashing (S2-T10);
// nothing is transmitted, but the firmware stays responsive on serial.
void ble_tx_init();

// Install/refresh the extended-advertising data with the current Message Pack.
// The BLE controller repeats the advertisement automatically at the configured
// interval, so there is NO separate repeat call (drone_emit_repeat is a no-op
// under DRIP_TX_BLE, like SoftAP).
//   msg_counter : ASTM §5.4.4.2 Message Pack counter.
// Returns false (and keeps the last valid advertisement on the air) if the pack
// does not fit BLE_EXT_ADV_MAX_PAYLOAD or a NimBLE call fails.
bool ble_tx_send(const MessagePack *pack, uint8_t msg_counter);

// Stop advertising. The drone leaves the air (a landed/powered-down UA). The
// next ble_tx_send() re-installs and restarts it.
void ble_tx_stop();
