import unittest
from StringIO import StringIO
from port_agent.common import PacketType
from port_agent.packet import Packet, PacketHeader, InvalidHeaderException


class PacketUnitTest(unittest.TestCase):
    def setUp(self):
        pass

    def test_create_packet(self):
        payload = 'abc123'
        packet_type = PacketType.FROM_INSTRUMENT
        packet = Packet.create(payload, packet_type)[0]

        self.assertEqual(packet.payload, payload)
        self.assertEqual(packet.header.packet_type, packet_type)
        self.assertEqual(packet.header.payload_size, len(payload))
        self.assertTrue(packet.valid)
        self.assertNotEqual(packet.header.time, 0)

    def test_packet_from_buffer(self):
        # create a packet
        payload = 'abc123'
        packet_type = PacketType.FROM_INSTRUMENT
        packet = Packet.create(payload, packet_type)[0]
        # get the packet contents as a string
        data_buffer = packet.data
        # create a new packet from the buffer
        packet, data_buffer = Packet.packet_from_buffer(data_buffer)

        self.assertEqual(packet.payload, payload)
        self.assertEqual(packet.header.packet_type, packet_type)
        self.assertEqual(packet.header.payload_size, len(payload))
        self.assertTrue(packet.valid)
        self.assertNotEqual(packet.header.time, 0)
        # Verify there is no data left
        self.assertEqual(data_buffer, '')

    def test_multiple_packets_from_buffer(self):
        data_buffer = ''
        payload = 'abc123'
        packet_type = PacketType.FROM_INSTRUMENT

        for i in xrange(3):
            # create a packet
            packet = Packet.create(payload, packet_type)[0]
            # get the packet contents as a string
            data_buffer += packet.data

        while True:
            packet, data_buffer = Packet.packet_from_buffer(data_buffer)
            if packet is None:
                break

            self.assertEqual(packet.payload, payload)
            self.assertEqual(packet.header.packet_type, packet_type)
            self.assertEqual(packet.header.payload_size, len(payload))
            self.assertTrue(packet.valid)
            self.assertNotEqual(packet.header.time, 0)

        # Verify there is no data left
        self.assertEqual(data_buffer, '')

    def test_multiple_packets_from_buffer_with_junk(self):
        data_buffer = ''
        payload = 'abc123'
        packet_type = PacketType.FROM_INSTRUMENT
        junk = 'kj34jk3h45'

        for i in xrange(3):
            # create a packet
            packet = Packet.create(payload, packet_type)[0]
            # get the packet contents as a string
            data_buffer += packet.data + junk

        while True:
            packet, data_buffer = Packet.packet_from_buffer(data_buffer)
            if packet is None:
                break

            self.assertEqual(packet.payload, payload)
            self.assertEqual(packet.header.packet_type, packet_type)
            self.assertEqual(packet.header.payload_size, len(payload))
            self.assertTrue(packet.valid)
            self.assertNotEqual(packet.header.time, 0)
            self.assertIn(junk, data_buffer)

        # Verify there is no data left
        self.assertEqual(data_buffer, junk)

    def test_packet_from_fh(self):
        # create a packet
        payload = 'abc123'
        packet_type = PacketType.FROM_INSTRUMENT
        packet = Packet.create(payload, packet_type)[0]
        # get the packet contents as a string
        fh = StringIO(packet.data)

        packet = Packet.packet_from_fh(fh)

        self.assertEqual(packet.payload, payload)
        self.assertEqual(packet.header.packet_type, packet_type)
        self.assertEqual(packet.header.payload_size, len(payload))
        self.assertTrue(packet.valid)
        self.assertNotEqual(packet.header.time, 0)

    def test_packet_from_fh_with_junk(self):
        data_buffer = ''
        payload = 'abc123'
        packet_type = PacketType.FROM_INSTRUMENT
        junk = 'kj34jk3h45'

        for i in xrange(3):
            # create a packet
            packet = Packet.create(payload, packet_type)[0]
            # get the packet contents as a string
            data_buffer += packet.data + junk

        fh = StringIO(data_buffer)
        while True:
            packet = Packet.packet_from_fh(fh)
            if packet is None:
                break

            self.assertEqual(packet.payload, payload)
            self.assertEqual(packet.header.packet_type, packet_type)
            self.assertEqual(packet.header.payload_size, len(payload))
            self.assertTrue(packet.valid)
            self.assertNotEqual(packet.header.time, 0)
            self.assertIn(junk, data_buffer)

    def test_create_invalid_header(self):
        packet_type = PacketType.FROM_INSTRUMENT
        self.assertRaises(InvalidHeaderException, PacketHeader, packet_type=packet_type, payload_size=10)
        self.assertRaises(InvalidHeaderException, PacketHeader,
                          packet_type=packet_type,payload_size=10, ts_high=4, packet_time=5)

    def test_bad_crc(self):
        # create a packet
        payload = 'abc123'
        packet_type = PacketType.FROM_INSTRUMENT
        packet = Packet.create(payload, packet_type)[0]
        # get the packet contents as a string
        data_buffer = packet.data

        # corrupt the data
        data_buffer = data_buffer[:-2] + 'ZZ'

        # create a new packet from the buffer
        packet, _ = Packet.packet_from_buffer(data_buffer)

        # make sure the packet is marked invalid and contains our corrupted payload
        self.assertFalse(packet.valid)
        self.assertEqual(packet.payload, payload[:-2] + 'ZZ')

    def test_max_size_packet(self):
        payload = 'x' * Packet.max_payload
        packet_type = PacketType.FROM_INSTRUMENT
        packets = Packet.create(payload, packet_type)

        self.assertEqual(len(packets), 2)
        self.assertEqual(packets[0].payload, payload)
        self.assertEqual(packets[1].payload, '')
        self.assertEqual(packets[0].header.time, packets[1].header.time)

    def test_large_packet(self):
        payload1 = 'x' * Packet.max_payload
        payload2 = 'abcabc'
        payload = payload1 + payload2
        packet_type = PacketType.FROM_INSTRUMENT
        packets = Packet.create(payload, packet_type)

        self.assertEqual(len(packets), 2)
        self.assertEqual(packets[0].payload, payload1)
        self.assertEqual(packets[1].payload, payload2)
        self.assertEqual(packets[0].header.time, packets[1].header.time)
