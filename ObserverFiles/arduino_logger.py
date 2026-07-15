import serial
import time
import sys
import argparse

# ── Settings ──────────────────────────────────────────────
PORT        = "COM4"
BAUD_RATE   = 115200
OUTPUT_FILE = "data_log.txt"
# ──────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="Capture an ESP32 DRIP serial log without resetting the board")
    ap.add_argument("--port", default=PORT)
    ap.add_argument("--baud", type=int, default=BAUD_RATE)
    ap.add_argument("-o", "--output", default=OUTPUT_FILE)
    ap.add_argument("--select", type=int, metavar="N",
                    help="send flight index N over serial right after connecting "
                         "(equivalent to typing N in the Serial Monitor)")
    ap.add_argument("--cmd", default=None,
                    help="send an arbitrary playback command instead of --select "
                         "(e.g. 'reset', 'stop', 'list')")
    args = ap.parse_args()

    print(f"Connecting to {args.port} at {args.baud} baud...")

    # ---------------------------------------------------------------------
    # BUG FIX: opening a serial port normally toggles the DTR/RTS control
    # lines, which on virtually every ESP32 board are wired straight to the
    # EN (reset) and GPIO0 pins -> the board reboots every time this script
    # starts. That reboot is why the log always begins at flight 0: whatever
    # flight was selected over the Serial Monitor is lost on reconnect.
    #
    # Fix: build the Serial object WITHOUT opening it, set dtr/rts to False
    # first, THEN open(). Setting dsrdtr=False/rtscts=False in the
    # constructor does NOT work (confirmed against pyserial's own open()
    # behaviour) - the control lines must be deasserted before open().
    # ---------------------------------------------------------------------
    try:
        ser = serial.Serial()
        ser.port = args.port
        ser.baudrate = args.baud
        ser.timeout = 2
        ser.dtr = False   # do NOT toggle EN
        ser.rts = False   # do NOT toggle GPIO0
        ser.open()
    except serial.SerialException as e:
        print(f"[ERROR] Could not open port: {e}")
        sys.exit(1)

    print("Connected without resetting the board - the currently running "
          "flight keeps playing.")

    # Optionally select a flight (or send any playback command) now that the
    # connection is open and did NOT reset the board. This makes capturing a
    # specific flight's log a single command instead of juggling the Arduino
    # Serial Monitor (to select) and this script (to capture) separately.
    if args.select is not None or args.cmd:
        cmd = args.cmd if args.cmd is not None else str(args.select)
        time.sleep(0.3)                    # let any in-flight serial settle
        ser.write((cmd + "\n").encode("utf-8"))
        print(f"Sent command: '{cmd}'")

    with open(args.output, "w", encoding="utf-8", errors="replace") as f:
        try:
            while True:
                try:
                    raw = ser.readline()
                    if not raw:
                        continue

                    line = raw.decode("utf-8", errors="replace").strip()
                    if line:
                        print(line)
                        f.write(line + "\n")
                        f.flush()

                except serial.SerialException as e:
                    print(f"\n[ERROR] Serial connection lost: {e}")
                    break

        except KeyboardInterrupt:
            print("\nStopped by user (Ctrl+C).")

    if ser.is_open:
        ser.close()
        print("Serial port closed cleanly.")

if __name__ == "__main__":
    main()
