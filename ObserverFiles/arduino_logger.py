import serial
import time
import sys

# ── Settings ──────────────────────────────────────────────
PORT        = "COM4"
BAUD_RATE   = 115200
OUTPUT_FILE = "data_log.txt"
# ──────────────────────────────────────────────────────────

def main():
    print(f"Connecting to {PORT} at {BAUD_RATE} baud...")

    try:
        ser = serial.Serial(PORT, BAUD_RATE, timeout=2)
    except serial.SerialException as e:
        print(f"[ERROR] Could not open port: {e}")
        sys.exit(1)
	

    #ser.reset_input_buffer()
    #ser.reset_output_buffer()
    #ser.close()
    #ser = serial.Serial(PORT, BAUD_RATE, timeout=2)

    with open(OUTPUT_FILE, "w", encoding="utf-8", errors="replace") as f:
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
