#################################################################################
# Constants
#################################################################################

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
    _keys = None
    _values = None
    _dict = None

    @classmethod
    def values(cls):
        """Return the values of this enum."""
        if cls._values is None:
            cls._values = tuple(getattr(cls, attr) for attr in cls.keys())
        return cls._values

    @classmethod
    def dict(cls):
        """Return a dict representation of this enum."""
        if cls._dict is None:
            cls._dict = {attr: getattr(cls, attr) for attr in cls.keys()}
        return cls._dict

    @classmethod
    def keys(cls):
        """Return the keys of this enum"""
        if cls._keys is None:
            cls._keys = tuple(attr for attr in dir(cls) if all((not callable(getattr(cls, attr)),
                                                                not attr.startswith('_'),
                                                                not attr == 'ALL')))
        return cls._keys

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
    ANTELOPE = 'antelope'
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
