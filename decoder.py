#!/usr/bin/env python
import struct
from port_agent import Packet, PacketType
import sys

def packet_from_fh(file_handle):
    buffer = bytearray()
    while True:
        byte = file_handle.read(1)
        if byte == '':
            return None

        buffer.append(byte)
        sync_index = buffer.find(Packet.sync)
        if sync_index != -1:
            # found the sync bytes, read the rest of the header
            buffer.extend(file_handle.read(Packet.header_size - len(Packet.sync)))

            if len(buffer) == Packet.header_size:
                _, packet_type, packet_size, checksum, ts_high, ts_low = struct.unpack_from(Packet.header_format,
                                                                                            buffer, sync_index)
                # read the payload
                payload = file_handle.read(packet_size-Packet.header_size)
                packet = Packet(payload, packet_type, header=buffer[sync_index:])
                return packet
            else:
                print repr(buffer), len(buffer)


def main():
    # check that there is only one parameter on the command line
    if len(sys.argv) < 2:
        sys.stderr.write('Expected one or more files to decode, got 0!\n')
        sys.exit(1)

    files = sys.argv[1:]

    for filename in files:
        with open(filename, "rb") as fh:
            while True:
                packet = packet_from_fh(fh)
                if packet is None:
                    break
                print packet

if __name__ == '__main__':
    main()