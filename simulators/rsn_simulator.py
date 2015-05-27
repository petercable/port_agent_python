#!/usr/bin/env python
"""
Usage:
    rsn_simulator.py <port> <rate> <label>
"""
import docopt
import sys

from twisted.internet import protocol, reactor, endpoints
from twisted.internet.protocol import connectionDone
from twisted.python import log
from port_agent.common import PacketType
from port_agent.packet import Packet

log.startLogging(sys.stdout)


class SampleProtocol(protocol.Protocol):
    def dataReceived(self, data):
        log.msg('received: %r' % data)
        self.factory.echo(data)

    def connectionMade(self):
        self.factory.clients.add(self)

    def connectionLost(self, reason=connectionDone):
        self.factory.clients.remove(self)


class SampleFactory(protocol.Factory):
    def __init__(self, rate, label):
        self.clients = set()
        self.protocol = SampleProtocol
        self.delay = .86 / rate  # should be 1.0/rate, but this accounts for some overhead
        self.label = label

    def startFactory(self):
        self.send_sample()

    def buildProtocol(self, addr):
        p = self.protocol()
        p.factory = self
        self.clients.add(p)
        return p

    def send_sample(self):
        reactor.callLater(self.delay, self.send_sample)
        packets = Packet.create(self.label + '\n', PacketType.FROM_INSTRUMENT)
        for client in self.clients:
            for packet in packets:
                client.transport.write(packet.data)

    def echo(self, data):
        packets = Packet.create('%s - %r\n' % (self.label, data), PacketType.FROM_INSTRUMENT)
        for client in self.clients:
            for packet in packets:
                client.transport.write(packet.data)


def main():
    options = docopt.docopt(__doc__)
    port = int(options['<port>'])
    rate = float(options['<rate>'])
    label = options['<label>']

    endpoints.serverFromString(reactor, "tcp:%d" % port).listen(SampleFactory(rate, label))
    reactor.run()


if __name__ == '__main__':
    main()
