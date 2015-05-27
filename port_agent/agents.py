from __future__ import division

from twisted.internet.endpoints import TCP4ServerEndpoint
from twisted.internet import reactor
from twisted.python import log
from twisted.python.logfile import DailyLogFile
from common import EndpointType, PacketType, Format, HEARTBEAT_INTERVAL
from factories import DataFactory, CommandFactory, InstrumentClientFactory, DigiInstrumentClientFactory, \
    DigiCommandClientFactory
from packet import Packet
from router import Router


#################################################################################
# Port Agents
#
# The default port agents include TCP, RSN, BOTPT and Datalog
# other port agents (CAMHD, Antelope) may require libraries which may not
# exist on all machines
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
        packets = Packet.create('HB', PacketType.PA_HEARTBEAT)
        self.router.got_data(packets)
        reactor.callLater(HEARTBEAT_INTERVAL, self._heartbeat)

    def instrument_connected(self, connection):
        self.connections.add(connection)
        if len(self.connections) == self.num_connections:
            log.msg('CONNECTED TO ', connection)
            self.router.got_data(Packet.create('CONNECTED', PacketType.PA_STATUS))

    def instrument_disconnected(self, connection):
        self.connections.remove(connection)
        log.msg('DISCONNECTED FROM ', connection)
        self.router.got_data(Packet.create('DISCONNECTED', PacketType.PA_STATUS))


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

    def _start_inst_connection(self):
        factory = DigiInstrumentClientFactory(self, PacketType.FROM_INSTRUMENT, EndpointType.INSTRUMENT)
        reactor.connectTCP(self.inst_addr, self.inst_port, factory)

    def _start_inst_command_connection(self):
        factory = DigiCommandClientFactory(self, PacketType.DIGI_RSP, EndpointType.DIGI)
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
            if packet.header.packet_type in self.target_types:
                self.router.got_data([packet])

        else:
            self._filehandle.close()
            self._filehandle = None

        # allow the reactor loop to process other events
        reactor.callLater(0, self._read)
