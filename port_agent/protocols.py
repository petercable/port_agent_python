#################################################################################
# Protocols
#################################################################################
from collections import deque
import json
from twisted.internet.protocol import Protocol, connectionDone
from twisted.protocols.basic import LineOnlyReceiver
from common import PacketType, BINARY_TIMESTAMP
from packet import Packet


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
        self.port_agent.router.got_data(Packet.create(data, self.packet_type))

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


class DigiInstrumentProtocol(InstrumentProtocol):
    """
    Overrides InstrumentProtocol to automatically send the binary timestamp command on connection
    """
    def __init__(self, port_agent, packet_type, endpoint_type):
        InstrumentProtocol.__init__(self, port_agent, packet_type, endpoint_type)
        self.buffer = deque(maxlen=65535)

    def dataReceived(self, data):
        self.buffer.extend(data)
        data = ''.join(self.buffer)
        packet, remaining = Packet.packet_from_buffer(data)
        if packet is not None:
            self.router.got_data([packet])
            self.buffer.clear()
            self.buffer.extendleft(remaining)

class DigiProtocol(InstrumentProtocol):
    """
    Overrides InstrumentProtocol to automatically send the binary timestamp command on connection
    """
    def __init__(self, port_agent, packet_type, endpoint_type):
        InstrumentProtocol.__init__(self, port_agent, packet_type, endpoint_type)

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
        packets = Packet.create(line, self.packet_type)
        self.port_agent.router.got_data(packets)
        self.handle_command(line)

    def handle_command(self, command):
        """
        Handle an incoming command.
        Any known digi command is passed through to the digi (if there is a digi connected)

        get_state - returns connection state of the port agent
        get_config - returns the port agent configuration dictionary (JSON encoded)
        """
        packets = []
        parts = command.split()

        if len(parts) > 0:
            first = parts[0]

            if first in self.digi_commands:
                packets = Packet.create(command + '\n', PacketType.DIGI_CMD)
            else:
                if command == 'get_state':
                    msg = 'STATE\n'
                    packets = Packet.create(msg, PacketType.PA_STATUS)
                elif command == 'get_config':
                    msg = json.dumps(self.port_agent.config) + '\n'
                    packets = Packet.create(msg, PacketType.PA_CONFIG)
                else:
                    packets = Packet.create('Received bad command on command port: %r' % command, PacketType.PA_FAULT)

        if packets:
            self.port_agent.router.got_data(packets)

    def connectionMade(self):
        self.port_agent.router.register(self.endpoint_type, self)

    def connectionLost(self, reason=connectionDone):
        self.port_agent.router.deregister(self.endpoint_type, self)

    def write(self, data):
        self.transport.write(data)
