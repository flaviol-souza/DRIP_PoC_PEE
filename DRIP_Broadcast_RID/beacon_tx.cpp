#include "beacon_tx.h"
#include <string.h>
#include <Arduino.h>

extern "C" {
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
}

// ---------------------------------------------------------------------------
// beacon_tx_init
//
// Starts the ESP32 as a hidden WiFi AP on channel 6 (mandatory per
// ASTM F3411-22a §5.4.8.3). No station associations are accepted.
// The AP beacon engine runs automatically at ~100 TU (≈102 ms) intervals;
// esp_wifi_set_vendor_ie() in beacon_tx_send() updates the DRIP payload
// in those beacons once per second.
// ---------------------------------------------------------------------------
void beacon_tx_init() {
    esp_netif_create_default_wifi_ap();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));

    wifi_config_t ap_cfg = {};
    const char *ssid = "DRIP-RID";
    memcpy(ap_cfg.ap.ssid, ssid, strlen(ssid));
    ap_cfg.ap.ssid_len       = (uint8_t)strlen(ssid);
    ap_cfg.ap.channel        = WIFI_CHANNEL_DRIP;
    ap_cfg.ap.authmode       = WIFI_AUTH_OPEN;
    ap_cfg.ap.max_connection = 0;   // reject all associations
    ap_cfg.ap.ssid_hidden    = 1;

    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap_cfg));
    ESP_ERROR_CHECK(esp_wifi_start());

    Serial.printf("[TX] WiFi AP started, Ch: %d, beacon interval ~102 ms\n",
                  WIFI_CHANNEL_DRIP);
}

// ---------------------------------------------------------------------------
// beacon_tx_send
//
// Inserts the DRIP Message Pack as a Vendor Specific IE (VSIE) into the
// beacons the AP hardware generates automatically. Each call replaces the
// previous VSIE content in slot WIFI_VND_IE_ID_0 — the beacon engine picks
// up the new data on the next beacon it transmits (~9-10 per second).
//
// VSIE wire format (ASTM F3411-22a Table 20):
//   [0xDD][len][0xFA][0x0B][0xBC][0x0D][counter][Message Pack bytes]
//
// Previous approach (esp_wifi_80211_tx with a manually built 802.11 frame)
// returned ESP_ERR_INVALID_ARG (0x102) in IDF v5.x because the AP firmware
// owns beacon generation and blocks raw beacon frame injection.
// esp_wifi_set_vendor_ie() is the correct API for this use case.
// ---------------------------------------------------------------------------
void beacon_tx_send(const MessagePack *pack, uint8_t msg_counter) {
    uint8_t pack_bytes = message_pack_bytes(pack);
    int vsie_body = 5 + (int)pack_bytes;  // OUI(3) + Vendor Type(1) + Counter(1) + pack

    if (vsie_body > 255) {
        Serial.printf("[TX] VSIE body %d > 255 — pack too large\n", vsie_body);
        return;
    }

    // Full IE: element_id(1) + length(1) + body(vsie_body)
    uint8_t ie[2 + 255];
    ie[0] = 0xDD;               // Vendor Specific element ID
    ie[1] = (uint8_t)vsie_body;
    ie[2] = 0xFA; ie[3] = 0x0B; ie[4] = 0xBC;  // ASTM OUI
    ie[5] = 0x0D;               // Vendor Type = Remote ID
    ie[6] = msg_counter;
    memcpy(&ie[7], pack->buf, pack_bytes);

    // Clear the slot before updating — IDF rejects a second set without a prior clear
    esp_wifi_set_vendor_ie(false, WIFI_VND_IE_TYPE_BEACON, WIFI_VND_IE_ID_0, NULL);

    // esp_wifi_set_vendor_ie copies the buffer internally — stack allocation is safe.
    esp_err_t err = esp_wifi_set_vendor_ie(
        true,
        WIFI_VND_IE_TYPE_BEACON,
        WIFI_VND_IE_ID_0,
        (const void *)ie
    );
    if (err != ESP_OK) {
        Serial.printf("[TX] esp_wifi_set_vendor_ie error: 0x%X\n", err);
    }
}

// ---------------------------------------------------------------------------
// beacon_tx_stop
//
// Clears the DRIP vendor IE from the AP beacon engine. This is the same API
// call beacon_tx_send() uses to remove the previous IE before installing a new
// one: passing NULL as the payload with `enable = false` removes it.
//
// After this, the ESP32 still emits 802.11 beacons (it is an AP), but they
// carry no ASTM F3411 Message Pack — nothing is broadcast for a Remote ID
// receiver. The next beacon_tx_send() call re-installs the IE.
// ---------------------------------------------------------------------------
void beacon_tx_stop() {
    esp_wifi_set_vendor_ie(false, WIFI_VND_IE_TYPE_BEACON, WIFI_VND_IE_ID_0, NULL);
    Serial.println("[TX] DRIP VSIE removed - no Remote ID payload is on the air.");
}
