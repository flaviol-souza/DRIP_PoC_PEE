#include "drip_config.h"     // DRIP_TX_SOFTAP — this unit is empty without it

#ifdef DRIP_TX_SOFTAP

#include "softap_tx.h"
#include "beacon_tx_raw.h"   // WIFI_CHANNEL_DRIP — the ONE owner of the channel
#include <string.h>
#include <Arduino.h>

extern "C" {
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
}

// Has a valid VSIE been installed at least once? Used only to log the emitted
// size once (avoids spamming the console at 3 Hz) and to reset on stop.
static bool s_have_valid_ie = false;

// ---------------------------------------------------------------------------
// softap_tx_init — hidden SoftAP on the DRIP channel, no associations.
//
// Ported from DRIP_Broadcast_RID/beacon_tx.cpp, with two differences:
//   * esp_netif_init() is called here (the raw backend used to own it; in a
//     SoftAP build beacon_tx_raw_init() is not called);
//   * the SSID matches the raw backend's per-slot naming ("DRIP-RID-0"). It is
//     not an ASTM field — it exists only so the beacon is a well-formed frame.
// ---------------------------------------------------------------------------
void softap_tx_init() {
    ESP_ERROR_CHECK(esp_netif_init());
    esp_netif_create_default_wifi_ap();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));   // never persist to NVS
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));

    wifi_config_t ap_cfg = {};
    const char *ssid = "DRIP-RID-0";
    memcpy(ap_cfg.ap.ssid, ssid, strlen(ssid));
    ap_cfg.ap.ssid_len       = (uint8_t)strlen(ssid);
    ap_cfg.ap.channel        = WIFI_CHANNEL_DRIP;
    ap_cfg.ap.authmode       = WIFI_AUTH_OPEN;
    ap_cfg.ap.max_connection = 0;   // reject all associations
    ap_cfg.ap.ssid_hidden    = 1;

    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap_cfg));
    ESP_ERROR_CHECK(esp_wifi_start());

    // Boot observability (S1-T11): backend, channel and the size guard in force.
    Serial.printf("[TX] backend=SoftAP (single-UA) — AP up, channel %d, SSID hidden, "
                  "no associations\n", WIFI_CHANNEL_DRIP);
    Serial.printf("[TX] VSIE size guard SOFTAP_VSIE_MAX_BODY=%d bytes\n",
                  SOFTAP_VSIE_MAX_BODY);
}

// ---------------------------------------------------------------------------
// softap_tx_send — install/refresh the DRIP VSIE.
//
// VSIE wire format (ASTM F3411-22a Table 20), byte-identical to the raw
// backend's vendor IE (beacon_tx_raw.cpp) and the legacy AP path:
//   [0xDD][len][FA 0B BC][0x0D][counter][Message Pack bytes]
// ---------------------------------------------------------------------------
bool softap_tx_send(const MessagePack *pack, uint8_t msg_counter) {
    const uint8_t pack_bytes = message_pack_bytes(pack);
    const int     vsie_body  = 5 + (int)pack_bytes;   // OUI(3)+Type(1)+Counter(1)+pack

    // Size guard (S1-T5 / ADR 0001 Decisão 2): never truncate. Refuse and keep
    // the last valid VSIE on the air.
    if (vsie_body > SOFTAP_VSIE_MAX_BODY) {
        Serial.printf("[SoftAP] pack de %d bytes excede a VSIE (max %d); "
                      "mantendo a última válida\n", vsie_body, SOFTAP_VSIE_MAX_BODY);
        return false;
    }

    // Full IE: element_id(1) + length(1) + body(vsie_body)
    uint8_t ie[2 + SOFTAP_VSIE_MAX_BODY];
    ie[0] = 0xDD;                       // Vendor Specific element ID
    ie[1] = (uint8_t)vsie_body;
    ie[2] = 0xFA; ie[3] = 0x0B; ie[4] = 0xBC;   // ASTM OUI (ASD-STAN)
    ie[5] = 0x0D;                       // Vendor Type = Open Drone ID
    ie[6] = msg_counter;                // ASTM §5.4.4.2
    memcpy(&ie[7], pack->buf, pack_bytes);

    // IDF rejects a second set without a prior clear (legacy beacon_tx.cpp note).
    esp_wifi_set_vendor_ie(false, WIFI_VND_IE_TYPE_BEACON, WIFI_VND_IE_ID_0, NULL);

    // esp_wifi_set_vendor_ie copies the buffer internally — stack alloc is safe.
    esp_err_t err = esp_wifi_set_vendor_ie(
        true, WIFI_VND_IE_TYPE_BEACON, WIFI_VND_IE_ID_0, (const void *)ie);
    if (err != ESP_OK) {
        Serial.printf("[SoftAP] esp_wifi_set_vendor_ie error: 0x%X (%s)\n",
                      (unsigned)err, esp_err_to_name(err));
        return false;
    }

    if (!s_have_valid_ie) {
        Serial.printf("[SoftAP] VSIE no ar: corpo %d bytes (pack %u bytes)\n",
                      vsie_body, (unsigned)pack_bytes);
        s_have_valid_ie = true;
    }
    return true;
}

// ---------------------------------------------------------------------------
// softap_tx_stop — strip the DRIP VSIE (the AP keeps beaconing, but with no
// Remote ID payload). Mirrors beacon_tx_raw_stop for the seam.
// ---------------------------------------------------------------------------
void softap_tx_stop() {
    esp_wifi_set_vendor_ie(false, WIFI_VND_IE_TYPE_BEACON, WIFI_VND_IE_ID_0, NULL);
    s_have_valid_ie = false;
    Serial.println("[SoftAP] VSIE removida — nenhum payload Remote ID no ar.");
}

#endif // DRIP_TX_SOFTAP
