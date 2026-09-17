// =============================================================================
//  DRIP_BLE_Sniffer — ESP32 #2 : over-the-air capture of ASTM F3411-22a
//  Broadcast RID over BLUETOOTH (Spec 3). The BLE counterpart of DRIP_Sniffer.
//
//  This board does NOT transmit. It scans BLE, keeps only advertisements that
//  carry an Open Drone ID "Service Data - 16-bit UUID" element (UUID 0xFFFA,
//  App Code 0x0D — ASTM Bluetooth transport), and prints each one over serial
//  in the "Format BT" hex format that Observer+Sniffer/odid.py understands.
//
// -----------------------------------------------------------------------------
//  !!! NOT COMPILE-VERIFIED HERE (no ESP32 toolchain in the authoring env) !!!
//  The NimBLE SCAN calls below target NimBLE-Arduino **v2.x** — the SAME library
//  the transmitter (ble_tx.cpp) already builds against, so the version matches.
//  Version-sensitive calls are marked "[NIMBLE v2.x]". As on the transmitter,
//  extended-advertising RECEPTION needs the library built with
//      CONFIG_BT_NIMBLE_EXT_ADV = 1
//  and a BLE 5 radio (ESP32-S3 / C3) to hear the BT5 ext-adv the transmitter
//  sends. Without it you only receive legacy (BT4) adverts. (S3-T1 confirms this
//  on hardware; if the S3 cannot receive the transmitted mode, fall back to a
//  host + BLE dongle per ADR 0003.)
//
// -----------------------------------------------------------------------------
//  WHY A SNIFFER (same rationale as the Wi-Fi DRIP_Sniffer)
//    The transmitter's serial log prints the pack it INTENDED to send, out of
//    RAM, before the radio is driven. It cannot see whether the advert reached
//    the air or from which BLE address. This tool reads the AIR: what it prints
//    actually propagated, and it recovers the source BLE address (which the
//    report uses to label/attribute each drone).
//
// -----------------------------------------------------------------------------
//  CALLBACK DISCIPLINE (identical to the Wi-Fi sniffer, and it matters)
//    The NimBLE scan callback runs in the BLE host task. Serial.print there can
//    block when the TX FIFO fills and stall the BLE stack, dropping adverts at
//    the radio. So the callback ONLY copies into a ring buffer and returns;
//    loop() does all the printing. dropped>0 in the stats line => the serial
//    link could not keep up and adverts were LOST (capture is INCOMPLETE).
//
// -----------------------------------------------------------------------------
//  OUTPUT — "Format BT" (parsed by odid.looks_like_format_bt / parse_format_bt)
//
//      # DRIP-BLE-SNIFFER v1 ...                         <- banner (ignored)
//      #B addr=C2:44:52:49:50:00 rssi=-42 t_ms=12345 len=208
//      FA FF 0D 86 F2 19 08 ...   <- Service Data field, UUID-first:
//                                    [UUID FA FF][AppCode 0D][counter][Msg Pack]
//
//    The hex line is EXACTLY the bytes the transmitter's ble_build_svcdata()
//    assembles, so the observer's BLE path and the transmitter's framing agree
//    byte-for-byte. 'len' is the Service Data byte count; odid.py checks the
//    received hex against it and reports a mismatch as W-CAP-01 (capture damage),
//    never as a DRIP conformance error.
//
// -----------------------------------------------------------------------------
//  HOW TO RUN
//    1. Folder must be named exactly  DRIP_BLE_Sniffer/
//    2. Flash to the SECOND ESP32-S3 (the transmitter keeps running its BLE build).
//    3. Capture with the SAME tool as the Wi-Fi sniffer (Serial Monitor cannot
//       save to a file):
//         python arduino_logger.py --port COMx --baud 921600 -o capture_ble.txt
//    4. Validate:
//         python observer.py capture_ble.txt
// =============================================================================

#include <Arduino.h>
#include <string.h>
#include <vector>
#include <NimBLEDevice.h>     // [NIMBLE v2.x] — same library as the transmitter

// -----------------------------------------------------------------------------
//  Configuration
// -----------------------------------------------------------------------------
// Serial rate. BLE advert volume is far below the Wi-Fi sniffer's 30 fps, so
// 921600 has ample headroom (matches the Wi-Fi sniffer / arduino_logger note).
// Drop to 460800 only if your USB-serial chip is unreliable at 921600; do NOT
// use 115200 (silent frame loss).
#define SNIFFER_BAUD        921600

// ODID Bluetooth markers (ASTM F3411-22a Bluetooth transport; see ble_frame.h
// on the transmitter). Service Data field is UUID-first on the wire.
#define ODID_BT_UUID_LO     0xFA     // UUID 0xFFFA, little-endian low byte
#define ODID_BT_UUID_HI     0xFF
#define ODID_BT_APP_CODE    0x0D
#define AD_TYPE_SVC_DATA16  0x16     // "Service Data - 16-bit UUID" (Core Suppl.)

// Ring buffer — the callback copies here; loop() drains and prints. Largest
// Service Data field = UUID(2)+AppCode(1)+Counter(1)+Message Pack(228) = 232.
#define RING_SLOTS          24
#define SVC_MAX             240

struct Slot {
    char     addr[18];        // "c2:44:52:49:50:00"
    int8_t   rssi;
    uint32_t t_ms;            // millis() at capture (rate/freshness analysis)
    uint8_t  svc[SVC_MAX];    // Service Data field content, UUID-first
    uint16_t svc_len;
};

static Slot              g_ring[RING_SLOTS];
static volatile uint16_t g_head     = 0;   // written by the BLE task
static volatile uint16_t g_tail     = 0;   // written by loop()
static volatile uint32_t g_captured = 0;
static volatile uint32_t g_dropped  = 0;   // ring overflow — serial too slow
static volatile uint32_t g_oversize = 0;   // Service Data > SVC_MAX, skipped

// -----------------------------------------------------------------------------
//  Find the ODID Service Data element in a raw advertising payload and copy its
//  field content (UUID-first) into `out`. Returns the length, or 0 if absent.
//
//  An AD structure is [length][type][data...] where `length` counts type+data.
//  For Service Data 16-bit: type=0x16, data = [uuid_lo][uuid_hi][service data].
//  We filter on UUID 0xFFFA + App Code 0x0D, NOT on the source address, so a
//  real ODID drone nearby is also captured and an advert from an unexpected
//  transmitter is not hidden (same rationale as the Wi-Fi sniffer's OUI filter).
// -----------------------------------------------------------------------------
static uint16_t extract_odid_svcdata(const uint8_t *p, size_t n,
                                     uint8_t *out, size_t out_cap) {
    size_t pos = 0;
    while (pos + 1 < n) {
        uint8_t len = p[pos];
        if (len == 0) break;                       // end of AD structures
        if (pos + 1 + len > n) break;              // truncated/malformed
        uint8_t type   = p[pos + 1];
        const uint8_t *data = &p[pos + 2];
        uint8_t dlen   = (uint8_t)(len - 1);       // bytes after the type octet
        if (type == AD_TYPE_SVC_DATA16 && dlen >= 3 &&
            data[0] == ODID_BT_UUID_LO &&
            data[1] == ODID_BT_UUID_HI &&
            data[2] == ODID_BT_APP_CODE) {
            if (dlen > out_cap) { g_oversize++; return 0; }   // skip, never truncate
            memcpy(out, data, dlen);
            return dlen;
        }
        pos += 1 + len;
    }
    return 0;
}

// -----------------------------------------------------------------------------
//  Scan callback — runs in the BLE host task. KEEP IT SHORT: copy and return.
// -----------------------------------------------------------------------------
class ScanCB : public NimBLEScanCallbacks {                 // [NIMBLE v2.x]
    void onResult(const NimBLEAdvertisedDevice *dev) override {   // [NIMBLE v2.x]
        // getPayload() returns the raw AD payload as a std::vector<uint8_t>.
        std::vector<uint8_t> payload = dev->getPayload();         // [NIMBLE v2.x]
        if (payload.empty()) return;

        uint8_t svc[SVC_MAX];
        uint16_t svc_len = extract_odid_svcdata(payload.data(), payload.size(),
                                                svc, sizeof(svc));
        if (svc_len == 0) return;                    // not an ODID advert (or oversize)

        uint16_t next = (uint16_t)((g_head + 1) % RING_SLOTS);
        if (next == g_tail) { g_dropped++; return; } // serial cannot keep up

        Slot *s = &g_ring[g_head];
        // toString() is bounded and quick; acceptable in a NimBLE callback.
        strncpy(s->addr, dev->getAddress().toString().c_str(), sizeof(s->addr) - 1);
        s->addr[sizeof(s->addr) - 1] = '\0';
        s->rssi    = (int8_t)dev->getRSSI();          // [NIMBLE v2.x]
        s->t_ms    = millis();
        s->svc_len = svc_len;
        memcpy(s->svc, svc, svc_len);

        g_head = next;
        g_captured++;
    }
};

static ScanCB g_scan_cb;

// -----------------------------------------------------------------------------
//  Emit one advert in Format BT: a '#B' metadata line + one hex line.
// -----------------------------------------------------------------------------
static void emit(const Slot *s) {
    Serial.printf("#B addr=%s rssi=%d t_ms=%lu len=%u\n",
                  s->addr, (int)s->rssi, (unsigned long)s->t_ms,
                  (unsigned)s->svc_len);
    for (uint16_t k = 0; k < s->svc_len; k++) {
        Serial.printf("%02X", s->svc[k]);
        if (k + 1 < s->svc_len) Serial.print(' ');
    }
    Serial.println();
}

// -----------------------------------------------------------------------------
void setup() {
    Serial.begin(SNIFFER_BAUD);
    delay(600);

    // [NIMBLE v2.x] init() returns bool in 2.x (void in 1.x). If your version
    // returns void, drop the check.
    if (!NimBLEDevice::init("DRIP-BLE-Sniffer")) {
        Serial.println("# [ERR] NimBLEDevice::init() falhou — scan nao iniciado.");
        return;
    }

    NimBLEScan *scan = NimBLEDevice::getScan();               // [NIMBLE v2.x]
    scan->setScanCallbacks(&g_scan_cb, false);                // [NIMBLE v2.x]
    scan->setActiveScan(true);                                // [NIMBLE v2.x]
    scan->setMaxResults(0);                                   // callback-only, do not store
    scan->setInterval(80);                                    // 0.625 ms units (~50 ms)
    scan->setWindow(80);                                      // 100% duty (single channel dwell)

    // Self-documenting header — a capture handed to another engineer explains
    // itself and its import command (mirrors the Wi-Fi sniffer banner).
    Serial.println();
    Serial.println("# DRIP-BLE-SNIFFER v1 — over-the-air ASTM F3411-22a Broadcast RID (Bluetooth)");
    Serial.printf ("# baud=%d  filter=Service Data UUID 0xFFFA + AppCode 0x0D\n", SNIFFER_BAUD);
    Serial.println("# needs BLE5 + CONFIG_BT_NIMBLE_EXT_ADV=1 to hear BT5 ext adv (see ADR 0003).");
    Serial.println("# each advert: a '#B addr=.. rssi=.. t_ms=.. len=..' line, then one hex line");
    Serial.println("#   of the Service Data field, UUID-first: FA FF 0D <counter> <Message Pack>.");
    Serial.println("# capture:  python arduino_logger.py --port COMx --baud 921600 -o capture_ble.txt");
    Serial.println("# validate: python observer.py capture_ble.txt");
    Serial.println("#");

    // start(0) = scan forever; callbacks fire as adverts arrive. [NIMBLE v2.x]
    scan->start(0, false);
}

// -----------------------------------------------------------------------------
void loop() {
    // Drain the ring. Printing happens only here, never in the callback.
    while (g_tail != g_head) {
        emit(&g_ring[g_tail]);
        g_tail = (uint16_t)((g_tail + 1) % RING_SLOTS);
    }

    // Periodic health line (emitted only between adverts, so it can never split
    // a record). dropped>0 => the ring overflowed and adverts were LOST; any
    // rate analysis from such a capture is unsound — raise the baud.
    static uint32_t last = 0;
    if (millis() - last >= 10000) {
        last = millis();
        Serial.printf("# stats captured=%u dropped=%u oversize=%u  (dropped>0 => "
                      "capture is INCOMPLETE)\n",
                      (unsigned)g_captured, (unsigned)g_dropped,
                      (unsigned)g_oversize);
    }
}
