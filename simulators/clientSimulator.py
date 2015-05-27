from twisted.internet import reactor
from twisted.internet.protocol import ReconnectingClientFactory, Protocol, connectionDone


class ClientProtocol(Protocol):
    def dataReceived(self, data):
        print data

    def connectionMade(self):
        print 'connectionMade'

    def connectionLost(self, reason=connectionDone):
        print 'connectionLost'


class ClientSimulator(ReconnectingClientFactory):
    protocol = ClientProtocol

    def buildProtocol(self, addr):
        print 'build protocol'
        return ReconnectingClientFactory.buildProtocol(self, addr)

    def clientConnectionLost(self, connector, unused_reason):
        print 'clientConnectionLost'
        ReconnectingClientFactory.clientConnectionLost(self, connector, unused_reason)


def main():
    addr = 'localhost'
    port = 1234
    reactor.connectTCP(addr, port, ClientSimulator())
    reactor.run()


if __name__ == '__main__':
    main()
