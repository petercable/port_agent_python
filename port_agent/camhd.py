import json
from twisted.python import log
from txzmq import ZmqSubConnection, ZmqREQConnection, ZmqFactory, ZmqEndpoint
from common import PacketType, NEWLINE
from common import EndpointType
from packet import Packet
from agents import PortAgent

#################################################################################
# CAMHD Port Agent
#################################################################################

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
        self.port_agent.router.got_data(Packet.create(tag, self.packet_type))
        self.port_agent.router.got_data(Packet.create(message + NEWLINE, self.packet_type))


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