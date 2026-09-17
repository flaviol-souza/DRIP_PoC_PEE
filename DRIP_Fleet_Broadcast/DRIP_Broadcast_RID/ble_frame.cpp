#include "ble_frame.h"
#include <string.h>

// Pure ODID-BT Service Data assembly. See ble_frame.h for the wire layout.
// No BLE stack, no I/O — safe to unit-test on the host.
size_t ble_build_svcdata(uint8_t *out, size_t out_cap,
                         const uint8_t *payload, size_t payload_len,
                         uint8_t counter) {
    if (out == nullptr || payload == nullptr) return 0;

    const size_t need = (size_t)ODID_BT_HDR_BYTES + payload_len;
    if (need > out_cap) return 0;                 // never truncate

    out[0] = ODID_BT_UUID_LO;   // 0xFA  (UUID 0xFFFA, little-endian low byte)
    out[1] = ODID_BT_UUID_HI;   // 0xFF
    out[2] = ODID_BT_APP_CODE;  // 0x0D
    out[3] = counter;
    memcpy(&out[4], payload, payload_len);
    return need;
}
