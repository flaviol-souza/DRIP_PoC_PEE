#include "drip_config.h"     // DRIP_TX_BLE — this unit is empty without it

#ifdef DRIP_TX_BLE

// ===========================================================================
// !!! NOT COMPILE-VERIFIED HERE (no ESP32 toolchain in the authoring env) !!!
//
// The FRAMING (ble_frame.*) is pure and testable off-target and is trusted.
// The RADIO calls below target NimBLE-Arduino **v2.x** extended advertising.
// Confirm these against your INSTALLED NimBLE-Arduino version before flashing;
// v1.4.x and v2.x differ in the ext-adv API. The calls to check are marked
// "[NIMBLE v2.x]" inline. Also required at library-config time:
//     CONFIG_BT_NIMBLE_EXT_ADV = 1   (extended advertising must be enabled)
// (nimconfig.h / build flag). Without it, getAdvertising() is the legacy type.
// ===========================================================================

#include "ble_tx.h"
#include "ble_frame.h"       // ble_build_svcdata — the pure ODID-BT framing
#include <string.h>
#include <Arduino.h>
#include <NimBLEDevice.h>    // [NIMBLE v2.x] pulls in host/ble_hs.h transitively

// A stable random-static BLE address (HU-5 / ADR 0002), so a receiver correlates
// the same drone across advertisements. NimBLE takes the address LSB-first, so
// this is the human-readable  C2:44:52:49:50:00  reversed. The MSB 0xC2 has its
// top two bits = 0b11, which is what makes it a valid *static random* address
// (BLE Core, Vol 6, Part B, §1.3.2.1). "DRIP" (44 52 49 50) is kept as a nod to
// the raw backend's slot-0 MAC 02:44:52:49:50:00.
static const uint8_t BLE_STATIC_ADDR[6] = { 0x00, 0x50, 0x49, 0x52, 0x44, 0xC2 };

static NimBLEExtAdvertising *s_adv          = nullptr;  // [NIMBLE v2.x] ext-adv object
static bool                  s_have_valid   = false;    // logged the emitted size once?
static bool                  s_up           = false;    // stack + set created OK?

// ---------------------------------------------------------------------------
// ble_tx_init — BLE stack up, static address, one extended-advertising set.
//
// Error handling (S2-T10): any failed step logs and returns; the firmware does
// NOT crash and stays responsive on serial. s_up stays false, so ble_tx_send()
// becomes a no-op that keeps warning instead of dereferencing a null set.
// ---------------------------------------------------------------------------
void ble_tx_init() {
    // [NIMBLE v2.x] init() returns bool in 2.x (void in 1.x). If your version
    // returns void, drop the check.
    if (!NimBLEDevice::init("DRIP-RID")) {
        Serial.println("[BLE] NimBLEDevice::init() falhou — BLE nao iniciado.");
        return;
    }

    // Stable random-static address (HU-5). ble_hs_id_set_rnd is the NimBLE host
    // call; NimBLEDevice.h exposes it via host/ble_hs.h. [NIMBLE v2.x]
    int rc = ble_hs_id_set_rnd(BLE_STATIC_ADDR);
    if (rc != 0) {
        Serial.printf("[BLE] ble_hs_id_set_rnd() rc=%d — usando endereco padrao.\n", rc);
    }
    NimBLEDevice::setOwnAddrType(BLE_OWN_ADDR_RANDOM);   // [NIMBLE v2.x]

    // getAdvertising() returns the EXTENDED advertising object only when the
    // library is built with CONFIG_BT_NIMBLE_EXT_ADV=1. [NIMBLE v2.x]
    s_adv = NimBLEDevice::getAdvertising();
    if (s_adv == nullptr) {
        Serial.println("[BLE] getAdvertising() nulo — extended advertising "
                       "habilitado? (CONFIG_BT_NIMBLE_EXT_ADV=1)");
        return;
    }

    s_up = true;

    // Boot observability (S2-T15): backend, transport, PHY, address and guard.
    Serial.println("[TX] backend=BLE (single-UA, ext adv) — BLE-only, Wi-Fi off");
    Serial.printf("[TX] PHY=1M  addr(static random)=%02X:%02X:%02X:%02X:%02X:%02X\n",
                  BLE_STATIC_ADDR[5], BLE_STATIC_ADDR[4], BLE_STATIC_ADDR[3],
                  BLE_STATIC_ADDR[2], BLE_STATIC_ADDR[1], BLE_STATIC_ADDR[0]);
    Serial.printf("[TX] ext-adv payload guard BLE_EXT_ADV_MAX_PAYLOAD=%d bytes\n",
                  BLE_EXT_ADV_MAX_PAYLOAD);
}

// ---------------------------------------------------------------------------
// ble_tx_send — refresh the extended-advertising data with the current pack.
//
// AD structure built (a single "Service Data - 16-bit UUID" element):
//   [len][0x16][ FA FF 0D counter <Message Pack> ]
//         type  \__ ble_build_svcdata() output (UUID-first) ______________/
//
// The BLE controller repeats the advertisement at the configured interval, so
// this is only called on the 3 Hz pack rebuild (drone_emit_repeat is a no-op).
// ---------------------------------------------------------------------------
bool ble_tx_send(const MessagePack *pack, uint8_t msg_counter) {
    if (!s_up || s_adv == nullptr) {
        Serial.println("[BLE] backend nao inicializado; advert ignorado.");
        return false;
    }

    const uint8_t pack_bytes = message_pack_bytes(pack);

    // Service Data content (UUID-first), built by the pure/tested framing unit.
    uint8_t svc[ODID_BT_HDR_BYTES + MSG_PACK_MAX_BYTES];
    size_t  svc_len = ble_build_svcdata(svc, sizeof(svc),
                                        pack->buf, pack_bytes, msg_counter);
    if (svc_len == 0) {
        Serial.println("[BLE] ble_build_svcdata: pack nao coube; mantendo o ultimo advert.");
        return false;
    }

    // Wrap it in the AD structure: [len][type=0x16][svc...].
    const size_t ad_len = 2 + svc_len;

    // Size guard (S2-T7): never truncate; refuse and keep the last valid advert.
    if (ad_len > BLE_EXT_ADV_MAX_PAYLOAD) {
        Serial.printf("[BLE] AD de %u bytes excede o ext-adv (max %d); "
                      "mantendo o ultimo advert valido.\n",
                      (unsigned)ad_len, BLE_EXT_ADV_MAX_PAYLOAD);
        return false;
    }

    uint8_t ad[2 + sizeof(svc)];
    ad[0] = (uint8_t)(1 + svc_len);      // AD length = type(1) + service-data
    ad[1] = 0x16;                        // AD type: Service Data - 16-bit UUID
    memcpy(&ad[2], svc, svc_len);

    // [NIMBLE v2.x] Build/refresh the extended, non-connectable, non-scannable
    // advertisement on 1M PHY and (re)start it. setData() takes the COMPLETE raw
    // AD payload (the [len][type] structures), which is exactly `ad`.
    NimBLEExtAdvertisement adv(BLE_HCI_LE_PHY_1M, BLE_HCI_LE_PHY_1M);
    adv.setConnectable(false);
    adv.setScannable(false);
    adv.setLegacyAdvertising(false);     // extended advertising
    adv.setData(ad, ad_len);

    // setInstanceData() reconfigures the instance (ble_gap_ext_adv_configure),
    // which the controller REJECTS while that instance is advertising — that was
    // the "[BLE] setInstanceData() falhou" every 3 Hz, freezing the advert on
    // the first pack. So stop first (a harmless no-op on the very first call,
    // before advertising has started), set the new data, then (re)start. The
    // controller repeats the advert between these 3 Hz refreshes.
    s_adv->stop(BLE_ADV_INSTANCE);
    if (!s_adv->setInstanceData(BLE_ADV_INSTANCE, adv)) {   // [NIMBLE v2.x]
        Serial.println("[BLE] setInstanceData() falhou; mantendo o ultimo advert.");
        return false;
    }
    if (!s_adv->start(BLE_ADV_INSTANCE)) {                  // [NIMBLE v2.x]
        Serial.println("[BLE] start() falhou; mantendo o ultimo advert.");
        return false;
    }

    if (!s_have_valid) {
        Serial.printf("[BLE] advert no ar: AD %u bytes (pack %u bytes)\n",
                      (unsigned)ad_len, (unsigned)pack_bytes);
        s_have_valid = true;
    }
    return true;
}

// ---------------------------------------------------------------------------
// ble_tx_stop — stop advertising (the drone leaves the air). Mirrors
// beacon_tx_raw_stop / softap_tx_stop for the transport seam.
// ---------------------------------------------------------------------------
void ble_tx_stop() {
    if (s_adv != nullptr) {
        s_adv->stop(BLE_ADV_INSTANCE);   // [NIMBLE v2.x]
    }
    s_have_valid = false;
    Serial.println("[BLE] advert parado — nenhum payload Remote ID no ar.");
}

#endif // DRIP_TX_BLE
