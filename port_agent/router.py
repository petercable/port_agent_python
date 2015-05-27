from collections import Counter
from twisted.internet import reactor
from twisted.python import log
from common import PacketType, EndpointType, Format, RouterStat, ROUTER_STATS_INTERVAL

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

    def got_data(self, packets):
        """
        Asynchronous callback from an endpoint. Packet will be routed as specified in the routing table.
        """
        for packet in packets:
            self.statistics[RouterStat.PACKET_IN] += 1
            for endpoint_type, data_format in self.routes.get(packet.header.packet_type, []):
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
