#pragma once
#include <stdint.h>
#include "message_pack.h"

// ---------------------------------------------------------------------------
// DRIP Debug — Serial hex dump for manual validation
//
// Prints, for every transmitted Message Pack:
//   1. The reconstructed on-air VSIE bytes (0xDD + len + OUI + Type + counter
//      + pack bytes) — ASTM F3411-22a Table 20
//   2. The raw Message Pack header (3 bytes)
//   3. Each 25-byte message with type annotation and hex dump.
//
// Auth messages are decoded against the CORRECTED page framing:
//   page 0  -> byte1 = 0x50 (AuthType 0x5, PageNumber 0), byte2 = LastPageIndex,
//              byte3 = Length, bytes4-7 = Timestamp, bytes8-24 = 17 data octets
//   page N  -> byte1 = 0x5N, bytes2-24 = 23 data octets
//
// Multi-page Auth messages are REASSEMBLED and annotated:
//   * Link (SAM 0x01)    : Broadcast Endorsement (RFC 9575 §4.2 Figure 5) —
//                          VNB, VNA, child DET, child HI, parent DET, Sig.
//   * Wrapper (SAM 0x02) : VNB, VNA, derived wrappedCount = (Length−89)/25
//                          with the §4.3.1 mod-25 / ≤4 validation, each
//                          wrapped message, UA DET, Sig.  (Round-2 R4)
//   * Manifest (SAM 0x03): VNB, VNA, the four §4.4.2 ledger hashes
//                          (Previous‖Current‖Link‖Pack), UA DET, Sig.
//
// A page whose AuthType nibble is not 0x5 is flagged (catches any un-migrated
// encoder still emitting the legacy framing).
// ---------------------------------------------------------------------------

// Max SAM Authentication Data the reassembler will buffer. The Link BE is the
// largest at 137 octets; 256 leaves headroom (ASTM Length is one octet, ≤ 201).
#define DRIP_DBG_SAM_MAX   256

// Print the full hex dump of a transmitted Message Pack to Serial.
//   pack        : the assembled pack (as passed to beacon_tx_send)
//   tx_counter  : the counter byte used in the VSIE
//   cycle_phase : 0 = Wrapper (A), 1 = Link/BE (B), 2 = Manifest (C)
void drip_debug_print_pack(const MessagePack *pack,
                            uint8_t            tx_counter,
                            uint8_t            cycle_phase);
