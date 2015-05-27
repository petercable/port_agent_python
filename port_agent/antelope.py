import threading
from twisted.internet import reactor
from agents import PortAgent
from antelope import Pkt
from antelope.orb import orbopen, OrbIncompleteException


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
                            orb_packet = orbpkt2dict(orb_packet)
                            packet = Packet(json.dumps(orb_packet), PacketType.FROM_INSTRUMENT)
                            reactor.callFromThread(self.port_agent.router.got_data, packet)
                        except OrbIncompleteException:
                            pass

        thread = OrbThread(self.inst_addr, self.inst_port, self)
        thread.start()


def orbpkt2dict(orbpkt):
    d = dict()
    channels = []
    d['channels'] = channels
    for orbchan in orbpkt.channels:
        channel = dict()
        channels.append(channel)
        channel['calib'] = orbchan.calib
        channel['calper'] = orbchan.calper
        channel['chan'] = orbchan.chan
        channel['cuser1'] = orbchan.cuser1
        channel['cuser2'] = orbchan.cuser2
        channel['data'] = orbchan.data
        channel['duser1'] = orbchan.duser1
        channel['duser2'] = orbchan.duser2
        channel['iuser1'] = orbchan.iuser1
        channel['iuser2'] = orbchan.iuser2
        channel['iuser3'] = orbchan.iuser3
        channel['loc'] = orbchan.loc
        channel['net'] = orbchan.net
        channel['nsamp'] = orbchan.nsamp
        channel['samprate'] = orbchan.samprate
        channel['segtype'] = orbchan.segtype
        channel['sta'] = orbchan.sta
        channel['time'] = orbchan.time
    d['db'] = orbpkt.db
    d['dfile'] = orbpkt.dfile
    d['pf'] = orbpkt.pf.pf2dict()
    srcname = orbpkt.srcname
    d['srcname'] = dict(
                        net=srcname.net,
                        sta=srcname.sta,
                        chan=srcname.chan,
                        loc=srcname.loc,
                        suffix=srcname.suffix,
                        subcode=srcname.subcode,
                        joined=srcname.join()
                       )
    d['string'] = orbpkt.string
    d['time'] = orbpkt.time
    pkttype = orbpkt.type
    d['type'] = dict(
                        content=pkttype.content,
                        name=pkttype.name,
                        suffix=pkttype.suffix,
                        hdrcode=pkttype.hdrcode,
                        bodycode=pkttype.bodycode,
                        desc=pkttype.desc,
                    ),
    d['version'] = orbpkt.version

    return d
