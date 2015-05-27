#################################################################################
# Port Agent Packet
#################################################################################
import struct
from datetime import datetime
from common import PacketType


class InvalidHeaderException(Exception):
    pass


class PacketHeader(object):
    """
    This class encapsulates the header for all data passing through the port agent

    HEADER FORMAT
    -------------
    SYNC (3 Bytes)
    TYPE (1 Byte, unsigned)
    SIZE (2 Bytes, unsigned)
    CHECKSUM (2 Bytes, unsigned, cumulative XOR of all message bytes excluding checksum)
    TS_high (4 Bytes, unsigned) NTP time, high 4 bytes are integer seconds
    TS_low (4 Bytes, unsigned) low 4 bytes are fractional seconds
    """
    sync = '\xA3\x9D\x7A'
    header_format = '>3sBHHII'
    header_size = struct.calcsize(header_format)
    checksum_format = '>H'
    checksum_size = struct.calcsize(checksum_format)
    checksum_index = 6
    frac_scale = 2 ** 32

    def __init__(self, packet_type=None, payload_size=None, checksum=0, ts_high=None, ts_low=None, packet_time=None):
        self._packet_type = packet_type
        self._packet_size = payload_size + self.header_size
        self._checksum = checksum
        self._ts_high = ts_high
        self._ts_low = ts_low
        self._time = packet_time
        self._repr = None
        if packet_time is not None and any([ts_high is not None, ts_low is not None]):
            raise InvalidHeaderException('Cannot supply ts_high/ts_low and packet_time')
        if all([packet_time is None, ts_high is None, ts_low is None]):
            raise InvalidHeaderException('Must supply a packet time!')

    @staticmethod
    def from_buffer(data_buffer, offset=0):
        _, packet_type, packet_size, checksum, ts_high, ts_low = struct.unpack_from(PacketHeader.header_format,
                                                                                    data_buffer, offset)
        return PacketHeader(packet_type=packet_type, payload_size=packet_size-PacketHeader.header_size,
                            checksum=checksum, ts_high=ts_high, ts_low=ts_low)

    @property
    def packet_type(self):
        return self._packet_type

    @property
    def packet_size(self):
        return self._packet_size

    @property
    def checksum(self):
        return self._checksum

    @property
    def payload_size(self):
        return self.packet_size - self.header_size

    @property
    def ts_high(self):
        if self._ts_high is None:
            if self._time is None:
                raise InvalidHeaderException('No time supplied!')
            self._ts_high = int(self._time)
        return self._ts_high

    @property
    def ts_low(self):
        if self._ts_low is None:
            if self._time is None:
                raise InvalidHeaderException('No time supplied!')
            self._ts_low = (self._time - int(self._time)) * self.frac_scale
        return self._ts_low

    @property
    def time(self):
        if self._time is None:
            if any([self._ts_high is None, self._ts_high is None]):
                raise InvalidHeaderException('No time supplied!')
            self._time = self._ts_high + self._ts_low / self.frac_scale
        return self._time

    def set_checksum(self, payload):
        self._checksum = self.lrc(repr(self), self.lrc(payload))
        self._repr = None

    @staticmethod
    def lrc(data, seed=0):
        data = bytearray(data)
        for byte in data:
            seed ^= byte
        return seed

    def __repr__(self):
        if self._repr is None:
            self._repr = struct.pack(self.header_format, self.sync, self.packet_type,
                                     self.packet_size, self.checksum, self.ts_high, self.ts_low)
        return self._repr


class Packet(object):
    """
    This class encapsulates the data passing through the port agent
    The packet is composed of a PacketHeader + payload
    """
    ntp_epoch = datetime(1900, 1, 1)
    max_payload = 0xffff - PacketHeader.header_size

    def __init__(self, payload=None, header=None):
        self.payload = payload
        self.header = header
        self._logstring = None

    @staticmethod
    def create(payload, packet_type):
        now = (datetime.utcnow() - Packet.ntp_epoch).total_seconds()
        packets = []

        # if payload > max_payload break into multiple packets
        # a payload of size max_payload shall be followed by an empty packet
        while len(payload) >= Packet.max_payload:
            data_slice = payload[:Packet.max_payload]
            payload = payload[Packet.max_payload:]
            header = PacketHeader(packet_type=packet_type, payload_size=len(data_slice), packet_time=now)
            header.set_checksum(data_slice)
            packets.append(Packet(payload=data_slice, header=header))

        header = PacketHeader(packet_type=packet_type, payload_size=len(payload), packet_time=now)
        header.set_checksum(payload)
        packets.append(Packet(payload=payload, header=header))

        return packets

    @staticmethod
    def packet_from_buffer(data_buffer):
        sync_index = data_buffer.find(PacketHeader.sync)
        if sync_index != -1:
            header_stop = sync_index + PacketHeader.header_size

            if len(data_buffer) >= header_stop:
                header = PacketHeader.from_buffer(data_buffer, sync_index)
                payload_stop = sync_index + header.packet_size

                if len(data_buffer) >= payload_stop:
                    payload = data_buffer[header_stop:payload_stop]
                    packet = Packet(payload=payload, header=header)
                    return packet, data_buffer[payload_stop:]

        return None, data_buffer

    @staticmethod
    def packet_from_fh(file_handle):
        data_buffer = bytearray()
        while True:
            byte = file_handle.read(1)
            if byte == '':
                return None

            data_buffer.append(byte)
            sync_index = data_buffer.find(PacketHeader.sync)
            if sync_index != -1:
                # found the sync bytes, read the rest of the header
                data_buffer.extend(file_handle.read(PacketHeader.header_size - len(PacketHeader.sync)))

                if len(data_buffer) >= PacketHeader.header_size:
                    header = PacketHeader.from_buffer(data_buffer, sync_index)
                    # read the payload
                    payload = file_handle.read(header.payload_size)
                    if len(payload) == header.payload_size:
                        packet = Packet(payload=payload, header=header)
                        return packet
                else:
                    return None

    @property
    def valid(self):
        return PacketHeader.lrc(self.data) == 0

    @property
    def data(self):
        return repr(self.header) + self.payload

    @property
    def logstring(self):
        if self._logstring is None:
            crc = 'CRC OK' if self.valid else 'CRC BAD'
            self._logstring = '%15.4f : %15s : %7s : %r' % (self.header.time,
                                                            PacketType.get_key(self.header.packet_type, 'UNKNOWN'),
                                                            crc,
                                                            self.payload)
        return self._logstring

    def __str__(self):
        return self.logstring

    def __repr__(self):
        return self.data
