import serial
import sys
import struct
import time

port = sys.argv[1]
baud = int(sys.argv[2])

ser = serial.Serial(port, baud, timeout=2)
ser.flushInput()

# cabeçalho global PCAP
header = struct.pack('<IHHiIII',
    0xa1b2c3d4,
    2, 4,
    0,
    0,
    65535,
    105
)
sys.stdout.buffer.write(header)
sys.stdout.buffer.flush()

def read_exactly(n):
    buf = b''
    while len(buf) < n:
        chunk = ser.read(n - len(buf))
        if chunk:
            buf += chunk
    return buf

while True:
    # le os 4 bytes do tamanho
    size_bytes = read_exactly(4)
    length = struct.unpack('<I', size_bytes)[0]

    if length == 0 or length > 2500:
        continue

    # le os dados do pacote
    payload = read_exactly(length)

    # monta timestamp
    ts = time.time()
    ts_sec  = int(ts)
    ts_usec = int((ts - ts_sec) * 1_000_000)

    # escreve cabeçalho do pacote + dados
    pkt_header = struct.pack('<IIII', ts_sec, ts_usec, length, length)
    sys.stdout.buffer.write(pkt_header)
    sys.stdout.buffer.write(payload)
    sys.stdout.buffer.flush()