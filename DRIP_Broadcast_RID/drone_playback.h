#pragma once
#include <stdint.h>
#include "f3411_messages.h"      // DronePosition

// ---------------------------------------------------------------------------
// Real-drone track playback.
//
// Replays recorded flight tracks (compiled into drone_data.h by
// csv_to_drone_data.py) instead of the synthetic square route in flight_sim.
// Pick the active flight at runtime over the serial monitor.
//
// Behaviour (per project decisions):
//   * PACING: each recorded point is held on the wire for its REAL recorded
//     duration (the delta between its timestamp and the next point's), not for
//     one fixed 0.333 s cycle. The transmitter still broadcasts at 3 Hz (DRIP
//     cadence is unaffected) — it simply repeats the SAME position across
//     multiple cycles until real time catches up to the recorded interval.
//     Speed / heading / vertical speed are computed from that real interval
//     (distance / real_seconds), so they reflect true average velocity instead
//     of being inflated by assuming a constant 0.333 s gap. The velocity value
//     is held constant for the whole hold (it represents the motion that
//     carried the drone INTO the point currently being held).
//   * CONSEQUENCE — playback duration is no longer bounded by the point cap.
//     The --cap in csv_to_drone_data.py only limits how many distinct points
//     are stored (flash size / track detail); it no longer bounds how long the
//     ESP32 spends transmitting a flight. Total playback time now equals the
//     real recorded flight duration (last timestamp - first timestamp),
//     regardless of how many points were kept. A flight recorded over 20 real
//     minutes will now take ~20 minutes to play back, even if decimated to a
//     handful of points.
//   * Duplicate/out-of-order recorded timestamps (delta <= 0) advance
//     immediately instead of stalling (PLAYBACK_MIN_DT_S floor).
//   * End of track: playback HOLDS on the final point (it does not wrap to the
//     start). Wrapping would teleport the drone back to takeoff mid-broadcast,
//     which an observer cross-checking position would rightly treat as bogus.
//     Re-select the flight (or send 'reset') to play it again.
//   * Identity: all flights share the single UA DET for now. Each flight has a
//     per-drone identity slot (see drone_playback_det()) for later use.
//   * Timestamp source: controlled by DRONE_REPLAY_RECORDED_TIME below.
// ---------------------------------------------------------------------------

// ===========================================================================
//  *** TEST-ONLY SWITCH — NOT RFC-CONFORMANT WHEN ENABLED ***
//
//  DRONE_REPLAY_RECORDED_TIME
//      1 = the ASTM Location message carries the RECORDED timestamp from the
//          dataset (e.g. 2025-11-09T20:27:29Z), replayed verbatim.
//      0 = the Location message carries the LIVE clock (RFC-conformant).
//
//  WHY THIS IS NOT CONFORMANT
//      ASTM F3411-22a Table 6 defines the Location timestamp as tenths of a
//      second within the CURRENT or previous UTC hour. Replaying a timestamp
//      from a past date makes that field describe a time that is not now, so a
//      receiver cross-checking the broadcast against the real world (RFC 9575
//      §9.1 / §6.3) can no longer use it for freshness.
//
//  SCOPE — what this switch does NOT touch
//      DRIP authentication timestamps (VNB/VNA in the Wrapper, Link and
//      Manifest) come from drip_timestamp(), NOT from this module. They remain
//      on the LIVE clock and stay RFC 9575 §3.2.4.3 conformant. Only the ASTM
//      Location message timestamp field is affected.
//
//  ENABLED ONLY to replay this specific historical dataset on the bench.
//  Set to 0 (or delete the block) before any live/flight use.
// ===========================================================================
#define DRONE_REPLAY_RECORDED_TIME  1

// Seconds between transmission cycles (3 Hz rotation -> ~0.333 s).
// Used only to derive speed/vspeed from the point-to-point delta.
#define PLAYBACK_CYCLE_S   0.3333f

// Initialise playback, select flight 0, and print the flight list.
// Returns false if drone_data.h contains no flights.
bool drone_playback_init();

// True once init() succeeded.
bool drone_playback_ready();

// Number of flights compiled in.
uint16_t drone_playback_count();

// Select a flight by index [0, count) and restart it at point 0.
bool drone_playback_select(uint16_t index);

// Halt transmission on demand (equivalent to reaching end-of-track): the .ino
// checks drone_playback_finished() and stops transmitting. Resume by selecting
// a flight (or 'reset'). No-op if already halted.
void drone_playback_stop();

// Restart the current flight at point 0.
void drone_playback_reset();

// True once the current flight has reached its last point (playback is holding).
bool drone_playback_finished();

// Advance one recorded point (call once per transmission cycle) and return the
// position, with speed/heading/vspeed derived from the previous point.
// Once the track ends, this keeps returning the final point with zero velocity.
//
// `live_unix_time_s` is used for DronePosition.unix_time_s ONLY when
// DRONE_REPLAY_RECORDED_TIME == 0. When it is 1 (test mode) the argument is
// ignored and the point's RECORDED timestamp is returned instead.
DronePosition drone_playback_next(uint32_t live_unix_time_s);

// Operator / launch location for the System message: first point of the track.
void drone_playback_get_launch(double *lat, double *lon, float *alt_m);

// Per-drone identity slot: the selected flight's DET, or nullptr to use the
// shared UA DET (current PoC behaviour).
const uint8_t *drone_playback_det();

// Print the available flights to Serial.
void drone_playback_list();

// Poll the serial monitor for a command. Call once per loop().
//   list      -> print the flight list
//   <number>  -> select that flight
//   info      -> current flight, point index, finished/stopped state
//   next      -> manually advance one point
//   reset     -> restart the current flight
//   stop      -> halt transmission immediately (no Remote ID on the air)
void drone_playback_cmd();
