import threading
from twisted.internet import reactor
from agents import PortAgent
from antelope import Pkt
from antelope.orb import orbopen, OrbIncompleteException
from common import PacketType
from packet import Packet
import msgpack


class AntelopePortAgent(PortAgent):
    def __init__(self, config):
        super(AntelopePortAgent, self).__init__(config)
        self.inst_addr = config['instaddr']
        self.inst_port = config['instport']
        self.keep_going = True
        self._start_inst_connection()

    def _register_loggers(self):
        """
        Overridden, no logging on antelope, antelope keeps track of its own data...
        """
        pass

    def disconnect(self):
        self.keep_going = False

    def _start_inst_connection(self):
        reactor.addSystemEventTrigger('before', 'shutdown', self.disconnect)

        class OrbThread(threading.Thread):
            def __init__(self, addr, port, port_agent):
                super(OrbThread, self).__init__()
                self.addr = addr
                self.port = port
                self.port_agent = port_agent

            def run(self):
                with orbopen('%s:%d' % (self.addr, self.port)) as orb:
                    while self.port_agent.keep_going:
                        try:
                            pktid, srcname, pkttime, data = orb.reap(5)
                            orb_packet = Pkt.Packet(srcname, pkttime, data)
                            packets = create_packets(orb_packet)
                            reactor.callFromThread(self.port_agent.router.got_data, packets)
                        except OrbIncompleteException:
                            pass

        thread = OrbThread(self.inst_addr, self.inst_port, self)
        thread.start()


def create_packets(orb_packet):
    packets = []
    for channel in orb_packet.channels:
        d = {'calib': channel.calib,
             'calper': channel.calper,
             'net': channel.net,
             'sta': channel.sta,
             'chan': channel.chan,
             'data': channel.data,
             'nsamp': channel.data,
             'samprate': channel.samprate,
             'time': channel.time,
             'type_suffix': orb_packet.suffix,
             'version': orb_packet.version,
             }

        packets.extend(Packet.create(msgpack.packb(d), PacketType.FROM_INSTRUMENT))
    return packets

