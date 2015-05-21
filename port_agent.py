#!/usr/bin/env python
"""
Usage:
    port_agent.py --config <config_file>
    port_agent.py tcp <port> <commandport> <instaddr> <instport> [--sniff=<sniffport>] [--name=<name>]
    port_agent.py rsn <port> <commandport> <instaddr> <instport> <digiport> [--sniff=<sniffport>] [--name=<name>]
    port_agent.py botpt <port> <commandport> <instaddr> <rxport> <txport> [--sniff=<sniffport>] [--name=<name>]
    port_agent.py camhd <port> <commandport> <instaddr> <subport> <reqport> [--sniff=<sniffport>] [--name=<name>]
    port_agent.py datalog <port> <commandport> <files>...

Options:
    -h, --help          Show this screen.
    --sniff=<sniffport> Start a sniffer on this port
    --name=<name>       Name this port agent (for logfiles, otherwise commandport is used)

"""
from __future__ import division
from collections import Counter
import json
import logging
import struct
from datetime import datetime
from twisted.internet.endpoints import TCP4ServerEndpoint
from twisted.internet import reactor
from twisted.internet.protocol import Protocol, connectionDone, ReconnectingClientFactory, Factory
from twisted.protocols.basic import LineOnlyReceiver
from twisted.python import log
from twisted.python.logfile import DailyLogFile
from txzmq import ZmqFactory, ZmqSubConnection, ZmqEndpoint, ZmqREQConnection
import yaml


# Port agent attempts to reconnect to instrument with exponential backoff
# this value sets the maximum backoff value
MAX_RECONNECT_DELAY = 240

# Interval at which router statistics are logged
ROUTER_STATS_INTERVAL = 10

# Command to set the DIGI timestamps to binary mode, sent automatically upon every DIGI connection
BINARY_TIMESTAMP = 'time 2\n'

# Interval between heartbeat packets
HEARTBEAT_INTERVAL = 10

# NEWLINE
NEWLINE = '\n'


#################################################################################
# Enumerations
#################################################################################

class Enumeration(object):
    ALL = 'ALL'

    @classmethod
    def values(cls):
        """Return the values of this enum."""
        return (getattr(cls, attr) for attr in cls.keys())

    @classmethod
    def dict(cls):
        """Return a dict representation of this enum."""
        return {attr: getattr(cls, attr) for attr in cls.keys()}

    @classmethod
    def keys(cls):
        """Return the keys of this enum"""
        return [attr for attr in dir(cls) if all((not callable(getattr(cls, attr)),
                                                  not attr.startswith('__'),
                                                  not attr == 'ALL'))]

    @classmethod
    def has(cls, item):
        """Return if this item in the enum values"""
        return item in cls.values()

    @classmethod
    def get_key(cls, value, default=None):
        d = cls.dict()
        for key in d:
            if d[key] == value:
                return key
        return default


class AgentTypes(Enumeration):
    TCP = 'tcp'
    RSN = 'rsn'
    BOTPT = 'botpt'
    CAMHD = 'camhd'
    DATALOG = 'datalog'


class Format(Enumeration):
    """Enumeration describing the possible output formats"""
    RAW = 'raw'
    PACKET = 'packet'
    ASCII = 'ascii'


class EndpointType(Enumeration):
    INSTRUMENT = 'instrument'  # TCP/RSN
    INSTRUMENT_DATA = 'instrument_data'  # BOTPT
    DIGI = 'digi_cmd'  # RSN
    CLIENT = 'client'
    COMMAND = 'command'
    LOGGER = 'logger'
    DATALOGGER = 'data_logger'
    PORT_AGENT = 'port_agent'
    COMMAND_HANDLER = 'command_handler'


class PacketType(Enumeration):
    UNKNOWN = 0
    FROM_INSTRUMENT = 1
    FROM_DRIVER = 2
    PA_COMMAND = 3
    PA_STATUS = 4
    PA_FAULT = 5
    PA_CONFIG = 6
    DIGI_CMD = 7
    DIGI_RSP = 8
    PA_HEARTBEAT = 9


class RouterStat(Enumeration):
    ADD_ROUTE = 0
    ADD_CLIENT = 1
    DEL_CLIENT = 2
    PACKET_IN = 3
    PACKET_OUT = 4


#################################################################################
# Port Agent Packet
#################################################################################

class Packet(object):
    """
    This class encapsulates the data passing through the port agent

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
    ntp_epoch = datetime(1900, 1, 1)

    def __init__(self, payload, packet_type, header=None):
        self.payload = payload
        self.packet_type = packet_type

        if header is None:
            self._time = (datetime.utcnow() - self.ntp_epoch).total_seconds()
            self._header = None
        else:
            self._time = None
            self._header = header

        self._logstring = None

    @staticmethod
    def packet_from_fh(file_handle):
        data_buffer = bytearray()
        while True:
            byte = file_handle.read(1)
            if byte == '':
                return None

            data_buffer.append(byte)
            sync_index = data_buffer.find(Packet.sync)
            if sync_index != -1:
                # found the sync bytes, read the rest of the header
                data_buffer.extend(file_handle.read(Packet.header_size - len(Packet.sync)))

                if len(data_buffer) == Packet.header_size:
                    _, packet_type, packet_size, checksum, ts_high, ts_low = struct.unpack_from(Packet.header_format,
                                                                                                data_buffer, sync_index)
                    # read the payload
                    payload = file_handle.read(packet_size-Packet.header_size)
                    packet = Packet(payload, packet_type, header=str(data_buffer[sync_index:]))
                    return packet
                else:
                    print repr(data_buffer), len(data_buffer)

    @property
    def time(self):
        if not self._time:
            _, _, _, _, ts_high, ts_low = struct.unpack_from(self.header_format, self._header, 0)
            self._time = ts_high + ts_low / self.frac_scale
        return self._time

    @property
    def header(self):
        if not self._header:
            secs = int(self.time)
            frac = int((self.time - secs) * self.frac_scale)
            size = self.header_size + len(self.payload)
            # checksum is in the middle of the header, insert a zero checksum first
            temp_header = struct.pack(self.header_format, self.sync, self.packet_type, size, 0, secs, frac)
            checksum = self._checksum(temp_header, self.payload)
            # insert the calculated checksum back into the header
            self._header = (temp_header[:self.checksum_index] +
                            struct.pack(self.checksum_format, checksum) +
                            temp_header[self.checksum_index+self.checksum_size:])
        return self._header

    @staticmethod
    def _checksum(header, payload):
        data = bytearray(header + payload)
        lrc = 0
        for byte in data:
            lrc ^= byte
        return lrc

    @property
    def valid(self):
        return self._checksum(self.header, self.payload) == 0

    @property
    def data(self):
        return self.header + self.payload

    @property
    def logstring(self):
        if self._logstring is None:
            crc = 'CRC OK' if self.valid else 'CRC BAD'
            self._logstring = '%15.4f : %15s : %7s : %r' % (self.time,
                                                            PacketType.get_key(self.packet_type, 'UNKNOWN'),
                                                            crc,
                                                            self.payload)
        return self._logstring

    def __str__(self):
        return self.logstring

    def __repr__(self):
        return self.data


#################################################################################
# Port Agent Router
#################################################################################

class Router(object):
    """
    Route data to a group of endpoints based on endpoint type
    """
    def __init__(self):
        """
        Initial route and client sets are empty. New routes are registered with add_route.
        New clients are registered/deregistered with register/deregister

        Messages are routed by packet type. All port agent endpoints will receive the Router.got_data
        callback on initialization. When data is received at an endpoint it will be used to generate a Packet
        which will be passed to got_data.

        All messages will be routed to all clients registered for a specific packet type. A special packet type
        of ALL will indicate that a client wishes to receive all messages.

        The data_format argument to add_route will determine the format of the message passed to the endpoint.
        A value of PACKET indicates the entire packet should be sent (packed), RAW indicates just the raw data
        will be passed and ASCII indicates the packet should be formatted in a method suitable for logging.
        """
        self.routes = {}
        self.clients = {}
        self.statistics = Counter()
        for packet_type in PacketType.values():
            self.routes[packet_type] = set()
        for endpoint_type in EndpointType.values():
            self.clients[endpoint_type] = set()

        self.log_stats()

    def add_route(self, packet_type, endpoint_type, data_format=Format.RAW):
        """
        Route packets of packet_type to all endpoints of endpoint_type using data_format
        """
        self.statistics[RouterStat.ADD_ROUTE] += 1
        if packet_type == PacketType.ALL:
            for packet_type in PacketType.values():
                log.msg('ADD ROUTE: %s -> %s data_format: %s' % (packet_type, endpoint_type, data_format))
                self.routes[packet_type].add((endpoint_type, data_format))
        else:
            log.msg('ADD ROUTE: %s -> %s data_format: %s' % (packet_type, endpoint_type, data_format))
            self.routes[packet_type].add((endpoint_type, data_format))

    def got_data(self, packet):
        """
        Asynchronous callback from an endpoint. Packet will be routed as specified in the routing table.
        """
        self.statistics[RouterStat.PACKET_IN] += 1
        for endpoint_type, data_format in self.routes.get(packet.packet_type, []):
            if data_format == Format.RAW:
                msg = packet.payload
            elif data_format == Format.PACKET:
                msg = repr(packet)
            elif data_format == Format.ASCII:
                msg = '%s\n' % packet
            else:
                msg = packet.payload

            for client in self.clients[endpoint_type]:
                self.statistics[RouterStat.PACKET_OUT] += 1
                client.write(msg)

    def register(self, endpoint_type, source):
        """
        Register an endpoint.
        :param endpoint_type value of EndpointType enumeration
        :param source endpoint object, must contain a "write" method
        """
        self.statistics[RouterStat.ADD_CLIENT] += 1
        log.msg('REGISTER: %s %s' % (endpoint_type, source))
        self.clients[endpoint_type].add(source)

    def deregister(self, endpoint_type, source):
        """
        Deregister an endpoint that has been closed.
        :param endpoint_type value of EndpointType enumeration
        :param source endpoint object, must contain a "write" method
        """
        self.statistics[RouterStat.DEL_CLIENT] += 1
        log.msg('DEREGISTER: %s %s' % (endpoint_type, source))
        self.clients[endpoint_type].remove(source)

    def log_stats(self):
        in_rate = self.statistics[RouterStat.PACKET_IN] / ROUTER_STATS_INTERVAL
        out_rate = self.statistics[RouterStat.PACKET_OUT] / ROUTER_STATS_INTERVAL
        log.msg('Router stats:: IN: %d (%.2f/s) OUT: %d (%.2f/s) REG: %d DEREG: %d' % (
            self.statistics[RouterStat.PACKET_IN],
            in_rate,
            self.statistics[RouterStat.PACKET_OUT],
            out_rate,
            self.statistics[RouterStat.ADD_CLIENT],
            self.statistics[RouterStat.DEL_CLIENT],
        ))
        self.statistics.clear()
        reactor.callLater(ROUTER_STATS_INTERVAL, self.log_stats)


#################################################################################
# Protocols
#################################################################################

class PortAgentProtocol(Protocol):
    """
    General protocol for the port agent.
    """
    def __init__(self, port_agent, packet_type, endpoint_type):
        self.port_agent = port_agent
        self.packet_type = packet_type
        self.endpoint_type = endpoint_type

    def dataReceived(self, data):
        """
        Called asynchronously when data is received from this connection
        """
        self.port_agent.router.got_data(Packet(data, self.packet_type))

    def write(self, data):
        self.transport.write(data)

    def connectionMade(self):
        """
        Register this protocol with the router
        """
        self.port_agent.router.register(self.endpoint_type, self)

    def connectionLost(self, reason=connectionDone):
        """
        Connection lost, deregister with the router
        """
        self.port_agent.router.deregister(self.endpoint_type, self)


class InstrumentProtocol(PortAgentProtocol):
    """
    Overrides PortAgentProtocol for instrument state tracking
    """
    def connectionMade(self):
        self.port_agent.instrument_connected(self)
        self.port_agent.router.register(self.endpoint_type, self)

    def connectionLost(self, reason=connectionDone):
        self.port_agent.instrument_disconnected(self)
        self.port_agent.router.deregister(self.endpoint_type, self)


class DigiProtocol(InstrumentProtocol):
    """
    Overrides InstrumentProtocol to automatically send the binary timestamp command on connection
    """
    def connectionMade(self):
        PortAgentProtocol.connectionMade(self)
        self.transport.write(BINARY_TIMESTAMP)


class CommandProtocol(LineOnlyReceiver):
    """
    Specialized protocol which is not called until a line of text terminated by the delimiter received
    default delimiter is '\r\n'
    """
    digi_commands = ['help', 'tinfo', 'cinfo', 'time', 'timestamp', 'power', 'break', 'gettime', 'getver']

    def __init__(self, port_agent, packet_type, endpoint_type):
        self.port_agent = port_agent
        self.packet_type = packet_type
        self.endpoint_type = endpoint_type

    def lineReceived(self, line):
        packet = Packet(line, self.packet_type)
        self.port_agent.router.got_data(packet)
        self.handle_command(line)

    def handle_command(self, command):
        """
        Handle an incoming command.
        Any known digi command is passed through to the digi (if there is a digi connected)

        get_state - returns connection state of the port agent
        get_config - returns the port agent configuration dictionary (JSON encoded)
        """
        packet = None
        parts = command.split()

        if len(parts) > 0:
            first = parts[0]

            if first in self.digi_commands:
                packet = Packet(command + '\n', PacketType.DIGI_CMD)
            else:
                if command == 'get_state':
                    msg = 'STATE\n'
                    packet = Packet(msg, PacketType.PA_STATUS)
                elif command == 'get_config':
                    msg = json.dumps(self.port_agent.config) + '\n'
                    packet = Packet(msg, PacketType.PA_CONFIG)
                else:
                    packet = Packet('Received bad command on command port: %r' % command, PacketType.PA_FAULT)

        if packet:
            self.port_agent.router.got_data(packet)

    def connectionMade(self):
        self.port_agent.router.register(self.endpoint_type, self)

    def connectionLost(self, reason=connectionDone):
        self.port_agent.router.deregister(self.endpoint_type, self)

    def write(self, data):
        self.transport.write(data)


#################################################################################
# Factories
#################################################################################

class InstrumentClientFactory(ReconnectingClientFactory):
    """
    Factory for instrument connections. Uses automatic reconnection with exponential backoff.
    """
    protocol = InstrumentProtocol
    maxDelay = MAX_RECONNECT_DELAY

    def __init__(self, port_agent, packet_type, endpoint_type):
        self.port_agent = port_agent
        self.packet_type = packet_type
        self.endpoint_type = endpoint_type
        self.connection = None

    def buildProtocol(self, addr):
        log.msg('Made TCP connection to instrument (%s), building protocol' % addr)
        p = self.protocol(self.port_agent, self.packet_type, self.endpoint_type)
        p.factory = self
        self.connection = p
        self.resetDelay()
        return p


class DigiClientFactory(InstrumentClientFactory):
    """
    Overridden to use DigiProtocol to automatically set binary timestamp on connection
    """
    protocol = DigiProtocol


class DataFactory(Factory):
    """
    This is the base class for incoming connections (data, command, sniffer)
    """
    protocol = PortAgentProtocol

    def __init__(self, port_agent, packet_type, endpoint_type):
        self.port_agent = port_agent
        self.packet_type = packet_type
        self.endpoint_type = endpoint_type

    def buildProtocol(self, addr):
        log.msg('Established incoming connection (%s)' % addr)
        p = self.protocol(self.port_agent, self.packet_type, self.endpoint_type)
        p.factory = self
        return p

class CommandFactory(DataFactory):
    """
    Subclasses DataFactory to utilize the CommandProtocol for incoming command connections
    """
    protocol = CommandProtocol

    def buildProtocol(self, addr):
        log.msg('Established incoming command connection (%s), building protocol' % addr)
        p = self.protocol(self.port_agent, self.packet_type, self.endpoint_type)
        p.factory = self
        return p


#################################################################################
# Connections (these are like protocols, but for ZMQ)
#################################################################################

class CamhdSubscriberConnection(ZmqSubConnection):
    def __init__(self, port_agent, packet_type, endpoint_type, factory, endpoint=None, identity=None):
        super(CamhdSubscriberConnection, self).__init__(factory, endpoint, identity)
        self.port_agent = port_agent
        self.packet_type = packet_type
        self.endpoint_type = endpoint_type
        self.port_agent.router.register(endpoint_type, self)
        self.subscribe('')

    def gotMessage(self, message, tag):
        self.port_agent.router.got_data(Packet(tag, self.packet_type))
        self.port_agent.router.got_data(Packet(message + NEWLINE, self.packet_type))


class CamhdCommandConnection(ZmqREQConnection):
    def __init__(self, port_agent, packet_type, endpoint_type, factory, endpoint=None, identity=None):
        super(CamhdCommandConnection, self).__init__(factory, endpoint, identity)
        self.port_agent = port_agent
        self.packet_type = packet_type
        self.endpoint_type = endpoint_type
        self.buf = bytearray()
        self.port_agent.router.register(endpoint_type, self)

    def write(self, data):
        self.buf.extend(data)
        if NEWLINE in self.buf:
            try:
                message = json.loads(str(self.buf[:self.buf.index(NEWLINE)]))
                message = [str(_) for _ in message]
                log.msg('Send command: ', message)
                self.sendMsg(*message)
            except ValueError:
                log.err()
            finally:
                self.buf = bytearray()

    def messageReceived(self, message):
        pass
        # TODO: confirm with instrument developer that all messages are duplicated on SUB port
        # if type(message) == list:
        #     for part in message:
        #         self.port_agent.router.got_data(Packet(part, self.packet_type))
        # else:
        #     self.port_agent.router.got_data(Packet(message, self.packet_type))


#################################################################################
# Port Agents
#################################################################################

class PortAgent(object):
    def __init__(self, config):
        self.config = config
        self.data_port = config['port']
        self.command_port = config['commandport']
        self.sniff_port = config['sniffport']
        self.name = config.get('name', str(self.command_port))

        self.router = Router()
        self.connections = set()

        self._register_loggers()
        self._create_routes()
        self._start_servers()
        self._heartbeat()
        self.num_connections = 0
        log.msg('Base PortAgent initialization complete')

    def _register_loggers(self):
        self.data_logger = DailyLogFile('%s.datalog' % self.name, '.')
        self.ascii_logger = DailyLogFile('%s.log' % self.name, '.')
        self.router.register(EndpointType.DATALOGGER, self.data_logger)
        self.router.register(EndpointType.LOGGER, self.ascii_logger)

    def _create_routes(self):
        # Register the logger and datalogger to receive all messages
        self.router.add_route(PacketType.ALL, EndpointType.LOGGER, data_format=Format.ASCII)
        self.router.add_route(PacketType.ALL, EndpointType.DATALOGGER, data_format=Format.PACKET)

        # from DRIVER
        self.router.add_route(PacketType.FROM_DRIVER, EndpointType.INSTRUMENT, data_format=Format.RAW)

        # from INSTRUMENT
        self.router.add_route(PacketType.FROM_INSTRUMENT, EndpointType.CLIENT, data_format=Format.PACKET)

        # from COMMAND SERVER
        self.router.add_route(PacketType.PA_COMMAND, EndpointType.COMMAND_HANDLER, data_format=Format.PACKET)

        # from PORT_AGENT
        self.router.add_route(PacketType.PA_CONFIG, EndpointType.CLIENT, data_format=Format.PACKET)
        self.router.add_route(PacketType.PA_CONFIG, EndpointType.COMMAND, data_format=Format.RAW)
        self.router.add_route(PacketType.PA_FAULT, EndpointType.CLIENT, data_format=Format.PACKET)
        self.router.add_route(PacketType.PA_HEARTBEAT, EndpointType.CLIENT, data_format=Format.PACKET)
        self.router.add_route(PacketType.PA_STATUS, EndpointType.CLIENT, data_format=Format.PACKET)
        self.router.add_route(PacketType.PA_STATUS, EndpointType.COMMAND, data_format=Format.PACKET)

        # from COMMAND HANDLER
        self.router.add_route(PacketType.DIGI_CMD, EndpointType.DIGI, data_format=Format.RAW)

        # from DIGI
        self.router.add_route(PacketType.DIGI_RSP, EndpointType.CLIENT, data_format=Format.PACKET)
        self.router.add_route(PacketType.DIGI_RSP, EndpointType.COMMAND, data_format=Format.RAW)

    def _start_servers(self):
        self.data_endpoint = TCP4ServerEndpoint(reactor, self.data_port)
        self.data_endpoint.listen(DataFactory(self, PacketType.FROM_DRIVER, EndpointType.CLIENT))

        self.command_endpoint = TCP4ServerEndpoint(reactor, self.command_port)
        self.command_endpoint.listen(CommandFactory(self, PacketType.PA_COMMAND, EndpointType.COMMAND))

        if self.sniff_port:
            self.sniff_port = int(self.sniff_port)
            self.sniff_endpoint = TCP4ServerEndpoint(reactor, self.sniff_port)
            self.sniff_endpoint.listen(DataFactory(self, PacketType.UNKNOWN, EndpointType.LOGGER))
        else:
            self.sniff_endpoint = None

    def _heartbeat(self):
        packet = Packet('HB', PacketType.PA_HEARTBEAT)
        self.router.got_data(packet)
        reactor.callLater(HEARTBEAT_INTERVAL, self._heartbeat)

    def instrument_connected(self, connection):
        self.connections.add(connection)
        if len(self.connections) == self.num_connections:
            log.msg('CONNECTED TO ', connection)
            self.router.got_data(Packet('CONNECTED', PacketType.PA_STATUS))

    def instrument_disconnected(self, connection):
        self.connections.remove(connection)
        log.msg('DISCONNECTED FROM ', connection)
        self.router.got_data(Packet('DISCONNECTED', PacketType.PA_STATUS))


class TcpPortAgent(PortAgent):
    """
    Make a single TCP connection to an instrument.
    Data from the instrument connection is routed to all connected clients.
    Data from the client(s) is routed to the instrument connection
    """
    def __init__(self, config):
        super(TcpPortAgent, self).__init__(config)
        self.inst_addr = config['instaddr']
        self.inst_port = config['instport']
        self.num_connections = 1
        self._start_inst_connection()
        log.msg('TcpPortAgent initialization complete')

    def _start_inst_connection(self):
        factory = InstrumentClientFactory(self, PacketType.FROM_INSTRUMENT, EndpointType.INSTRUMENT)
        reactor.connectTCP(self.inst_addr, self.inst_port, factory)


class RsnPortAgent(TcpPortAgent):
    def __init__(self, config):
        super(RsnPortAgent, self).__init__(config)
        self.inst_cmd_port = config['digiport']
        self._start_inst_command_connection()
        log.msg('RsnPortAgent initialization complete')

    def _start_inst_command_connection(self):
        factory = DigiClientFactory(self, PacketType.DIGI_RSP, EndpointType.DIGI)
        reactor.connectTCP(self.inst_addr, self.inst_cmd_port, factory)


class BotptPortAgent(PortAgent):
    """
    Make multiple TCP connection to an instrument (one TX, one RX).
    Data from the instrument RX connection is routed to all connected clients.
    Data from the client(s) is routed to the instrument TX connection
    """
    def __init__(self, config):
        super(BotptPortAgent, self).__init__(config)
        self.inst_rx_port = config['rxport']
        self.inst_tx_port = config['txport']
        self.inst_addr = config['instaddr']
        self._start_inst_connection()
        self.num_connections = 2
        log.msg('BotptPortAgent initialization complete')

    def _start_inst_connection(self):
        rx_factory = InstrumentClientFactory(self, PacketType.FROM_INSTRUMENT, EndpointType.INSTRUMENT_DATA)
        tx_factory = InstrumentClientFactory(self, PacketType.UNKNOWN, EndpointType.INSTRUMENT)
        reactor.connectTCP(self.inst_addr, self.inst_rx_port, rx_factory)
        reactor.connectTCP(self.inst_addr, self.inst_tx_port, tx_factory)


class CamhdPortAgent(PortAgent):
    def __init__(self, config):
        super(CamhdPortAgent, self).__init__(config)
        self.req_port = config['reqport']
        self.sub_port = config['subport']
        self.inst_addr = config['instaddr']
        self._start_inst_connection()
        self.num_connections = 2
        log.msg('CamhdPortAgent initialization complete')

    def _start_inst_connection(self):
        self.factory = ZmqFactory()
        self.subscriber_endpoint = ZmqEndpoint('connect', 'tcp://%s:%d' % (self.inst_addr, self.sub_port))
        self.subscriber = CamhdSubscriberConnection(self,
                                                    PacketType.FROM_INSTRUMENT,
                                                    EndpointType.INSTRUMENT_DATA,
                                                    self.factory,
                                                    self.subscriber_endpoint)
        self.command_endpoint = ZmqEndpoint('connect', 'tcp://%s:%d' % (self.inst_addr, self.req_port))
        self.commander = CamhdCommandConnection(self,
                                                PacketType.FROM_INSTRUMENT,
                                                EndpointType.INSTRUMENT,
                                                self.factory,
                                                self.command_endpoint)

class DatalogReadingPortAgent(PortAgent):
    def __init__(self, config):
        super(DatalogReadingPortAgent, self).__init__(config)
        self.files = config['files']
        self._filehandle = None
        self.target_types = [PacketType.FROM_INSTRUMENT, PacketType.PA_CONFIG]
        self._start_when_ready()

    def _register_loggers(self):
        """
        Overridden, no logging when reading a datalog...
        """
        pass

    def _start_when_ready(self):
        log.msg('waiting for a client connection', self.router.clients[EndpointType.INSTRUMENT_DATA])
        if len(self.router.clients[EndpointType.CLIENT]) > 0:
            self._read()
        else:
            reactor.callLater(1.0, self._start_when_ready)

    def _read(self):
        """
        Read one packet, publish if appropriate, then return.
        We must not read all packets in a loop here, or we will not actually publish them until the end...
        """
        if self._filehandle is None and not self.files:
            log.msg('Completed reading specified port agent logs, exiting...')
            reactor.stop()
            return

        if self._filehandle is None:
            name = self.files.pop()
            log.msg('Begin reading:', name)
            self._filehandle = open(name, 'r')

        packet = Packet.packet_from_fh(self._filehandle)
        if packet is not None:
            if packet.packet_type in self.target_types:
                self.router.got_data(packet)

        else:
            self._filehandle.close()
            self._filehandle = None

        # allow the reactor loop to process other events
        reactor.callLater(0, self._read)


#################################################################################
# Support methods
#################################################################################

def configure_logging():
    log_format = '%(asctime)-15s %(levelname)s %(message)s'
    logging.basicConfig(format=log_format)
    logger = logging.getLogger('port_agent')
    logger.setLevel(logging.INFO)
    observer = log.PythonLoggingObserver('port_agent')
    observer.start()


def config_from_options(options):
    if options['--config']:
        return yaml.load(open(options['--config']))

    config = {}
    for option in options:
        if option.startswith('<'):
            name = option[1:-1]
            if 'port' in name:
                try:
                    config[name] = int(options[option])
                except (ValueError, TypeError):
                    config[name] = options[option]
            else:
                config[name] = options[option]

    config['type'] = None
    for _type in AgentTypes.values():
        if options[_type]:
            config['type'] = _type

    sniff = options['--sniff']
    if sniff is not None:
        try:
            sniff = int(sniff)
        except (ValueError, TypeError):
            sniff = None
    config['sniffport'] = sniff

    name = options['--name']
    if name is not None:
        config['name'] = name

    return config


def main():
    from docopt import docopt

    configure_logging()
    options = docopt(__doc__)
    config = config_from_options(options)

    agent_type_map = {
        AgentTypes.TCP: TcpPortAgent,
        AgentTypes.RSN: RsnPortAgent,
        AgentTypes.BOTPT: BotptPortAgent,
        AgentTypes.CAMHD: CamhdPortAgent,
        AgentTypes.DATALOG: DatalogReadingPortAgent,
    }

    agent_type = config['type']
    agent = agent_type_map.get(agent_type)
    if agent is not None:
        agent(config)
        exit(reactor.run())
    else:
        exit(1)

if __name__ == '__main__':
    main()
