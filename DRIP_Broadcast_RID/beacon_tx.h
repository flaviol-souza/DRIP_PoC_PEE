#pragma once
#include <stdint.h>
#include "message_pack.h"

// ---------------------------------------------------------------------------
// 802.11 Beacon VSIE injection for ASTM F3411-22a Broadcast RID
//
// WiFi channel: 6 (2.4 GHz) — mandatory per ASTM F3411-22a §5.4.8.3
// VSIE OUI: FA-0B-BC, Vendor Type: 0x0D — ASTM F3411-22a Table 20
//
// Transmission method: esp_wifi_set_vendor_ie() — inserts the DRIP VSIE into
// the beacons generated automatically by the ESP32 AP beacon engine.
// (esp_wifi_80211_tx with a manually built beacon frame is NOT used; in
// IDF v5.x AP mode it returns ESP_ERR_INVALID_ARG for management/beacon frames.)
//
// Call beacon_tx_init() once after nvs_flash_init / esp_netif_init /
// esp_event_loop_create_default.
// ---------------------------------------------------------------------------

#define WIFI_CHANNEL_DRIP   6

// Starts WiFi in AP mode on channel 6 (open auth, no associations allowed).
void beacon_tx_init();

// Updates the DRIP VSIE in the AP beacon engine with the current Message Pack.
// The AP broadcasts ~9-10 beacons per second; this is called once per second.
void beacon_tx_send(const MessagePack *pack, uint8_t msg_counter);

// Removes the DRIP VSIE from the AP beacons.
//
// The AP itself keeps beaconing (it remains a normal 802.11 AP), but its
// beacons no longer carry any Open Drone ID / DRIP payload, so a Remote ID
// receiver sees nothing to decode. Used to HALT transmission at the end of a
// recorded flight track (see drone_playback.h); calling beacon_tx_send() again
// re-installs the IE and transmission resumes.
void beacon_tx_stop();
