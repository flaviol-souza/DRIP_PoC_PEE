#pragma once
#include <stdint.h>
#include "message_pack.h"

// ---------------------------------------------------------------------------
// SoftAP transmit backend for ASTM F3411-22a Broadcast RID — SINGLE-UA
//
// Selected at build time by DRIP_TX_SOFTAP (drip_config.h). This backend runs
// the ESP32 as a hidden SoftAP on the DRIP channel and inserts the DRIP Message
// Pack as a Vendor Specific IE (VSIE) into the beacons the AP engine generates
// automatically (esp_wifi_set_vendor_ie). It is the transport ADAPTER selected
// by the scheduler's drone_emit seam (see drone_fleet.cpp, ADR 0001).
//
// WHY SINGLE-UA: a SoftAP has exactly one BSSID, so every pack leaves from the
// same MAC. Real Remote ID receivers correlate tracks by transmitter MAC, so
// this backend can faithfully represent ONE drone only. The compile-time guard
// in drone_fleet.h (#if defined(DRIP_TX_SOFTAP) && FLEET_MAX > 1) enforces that.
//
// Channel / OUI / vendor type are the SAME wire constants the raw backend uses
// (WIFI_CHANNEL_DRIP in beacon_tx_raw.h; OUI FA-0B-BC / type 0x0D, ASTM Table
// 20), so the DRIP_Sniffer and observer.py see an identical payload.
//
// Molde: the superseded single-drone path DRIP_Broadcast_RID/beacon_tx.cpp.
// ---------------------------------------------------------------------------

// VSIE body size guard (ADR 0001, Decisão 2). 255 is the hard limit of the
// 802.11 IE Length field (1 byte). message_pack.h already caps a pack at 9
// messages (VSIE body <= 233 B), so this is a safety net that also protects
// against an eventual smaller IDF limit on the S3 (confirmed by S1-T1).
#define SOFTAP_VSIE_MAX_BODY   255

// Bring up the SoftAP (WIFI_MODE_AP, DRIP channel, SSID hidden, no association).
// Call once in setup() instead of beacon_tx_raw_init(), after nvs_flash_init /
// esp_event_loop_create_default. It performs esp_netif_init() itself.
void softap_tx_init();

// Install/refresh the DRIP VSIE with the current Message Pack. The AP beacon
// engine repeats it automatically at ~100 TU, so there is NO separate repeat
// call for this backend (drone_emit_repeat is a no-op under DRIP_TX_SOFTAP).
//   msg_counter : ASTM §5.4.4.2 Message Pack counter
// Returns false (and keeps the last valid VSIE on the air) if the pack does not
// fit SOFTAP_VSIE_MAX_BODY or the IDF call fails.
bool softap_tx_send(const MessagePack *pack, uint8_t msg_counter);

// Remove the DRIP VSIE. The AP keeps beaconing but carries no Remote ID
// payload — a landed/stopped drone. The next softap_tx_send() re-installs it.
void softap_tx_stop();
