#pragma once
#include <stdint.h>
#include <stddef.h>

// ---------------------------------------------------------------------------
// ODID-over-Bluetooth framing (ASTM F3411-22a Bluetooth transport) — PURE.
//
// This unit builds ONLY the Service Data payload for a Remote ID advertisement.
// It has NO dependency on any BLE stack (NimBLE/Bluedroid) and no I/O, so it can
// be unit-tested off-target and is independent of the S2-T1 stack decision. The
// radio layer (ble_tx.*, S2-T4) will call this and hand the bytes to the chosen
// BLE API wrapped in a "Service Data - 16-bit UUID" AD structure.
//
// Wire layout of the Service Data content (what the BLE AD carries after its own
// [length][AD type=0x16] header, which the radio layer adds):
//
//     [UUID lo][UUID hi][App Code][Msg Counter][ payload ... ]
//         0xFA    0xFF      0x0D      counter     ODID message or Message Pack
//
//   * UUID = 0xFFFA (ASTM/OpenDroneID service UUID), little-endian on the wire.
//   * App Code = 0x0D (ODID AD Application Code).
//   * Msg Counter: increments when the payload content changes (ASTM §5.4.4.2).
//   * payload:
//       - BT4 legacy: exactly ONE 25-byte ODID message.
//       - BT5 extended: a full ASTM Message Pack (starts with 0xF2 ...), the same
//         bytes produced by message_pack.* — so the caller passes pack->buf.
//
// Reference (framing only, NOT the radio API): .tmp/transmitter-n52840/odid_bt.cpp
// (Zephyr) — pack_buffer[0..2] = {uuid_l, uuid_h, 0x0D}, [3] = counter, [4..] pack.
// ---------------------------------------------------------------------------

#define ODID_BT_UUID          0xFFFA   // ASTM / OpenDroneID Bluetooth service UUID
#define ODID_BT_UUID_LO       0xFA
#define ODID_BT_UUID_HI       0xFF
#define ODID_BT_APP_CODE      0x0D     // AD Application Code (ASTM Table 20 family)
#define ODID_BT_HDR_BYTES     4        // UUID(2) + AppCode(1) + Counter(1)

// Build the Service Data content into `out` (capacity `out_cap`).
//   payload / payload_len : the ODID message (BT4) or Message Pack (BT5) bytes.
//   counter               : ODID message counter for this advertisement.
// Returns the number of bytes written (ODID_BT_HDR_BYTES + payload_len), or 0 if
// it would not fit `out_cap` (never truncates).
size_t ble_build_svcdata(uint8_t *out, size_t out_cap,
                         const uint8_t *payload, size_t payload_len,
                         uint8_t counter);
