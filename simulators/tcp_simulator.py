#!/usr/bin/env python
"""
Usage:
    tcp_instrument.py <port> <rate> <label>
"""
import docopt
import time
import sys

from twisted.internet import protocol, reactor, endpoints
from twisted.internet.protocol import connectionDone
from twisted.python import log

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
        for client in self.clients:
            client.transport.write(self.label + '\n')

    def echo(self, data):
        now = time.time()
        for client in self.clients:
            client.transport.write('%s - %r\n' % (self.label, data))

def main():
    options = docopt.docopt(__doc__)
    port = int(options['<port>'])
    rate = float(options['<rate>'])
    label = options['<label>']

    endpoints.serverFromString(reactor, "tcp:%d" % port).listen(SampleFactory(rate, label))
    reactor.run()


if __name__ == '__main__':
    main()