#!/usr/bin/env python
"""
Usage:
    port_agent.py --config <config_file>
    port_agent.py tcp <port> <commandport> <instaddr> <instport> [--sniff=<sniffport>] [--name=<name>]
    port_agent.py rsn <port> <commandport> <instaddr> <instport> <digiport> [--sniff=<sniffport>] [--name=<name>]
    port_agent.py botpt <port> <commandport> <instaddr> <rxport> <txport> [--sniff=<sniffport>] [--name=<name>]
    port_agent.py camhd <port> <commandport> <instaddr> <subport> <reqport> [--sniff=<sniffport>] [--name=<name>]
    port_agent.py antelope <port> <commandport> <instaddr> <instport> [--sniff=<sniffport>] [--name=<name>]
    port_agent.py datalog <port> <commandport> <files>...

Options:
    -h, --help          Show this screen.
    --sniff=<sniffport> Start a sniffer on this port
    --name=<name>       Name this port agent (for logfiles, otherwise commandport is used)

"""
import logging
import traceback
from docopt import docopt
from twisted.internet import reactor
from twisted.python import log
import yaml
from common import AgentTypes
from agents import TcpPortAgent, RsnPortAgent, BotptPortAgent, DatalogReadingPortAgent


def configure_logging():
    log_format = '%(asctime)-15s %(levelname)s %(message)s'
    logging.basicConfig(format=log_format)
    logger = logging.getLogger('port_agent')
    logger.setLevel(logging.INFO)
    observer = log.PythonLoggingObserver('port_agent')
    observer.start()


def config_from_options(options):
    if options['--config']:
        return yaml.load(open(options['--config']))

    config = {}
    for option in options:
        if option.startswith('<'):
            name = option[1:-1]
            if 'port' in name:
                try:
                    config[name] = int(options[option])
                except (ValueError, TypeError):
                    config[name] = options[option]
            else:
                config[name] = options[option]

    config['type'] = None
    for _type in AgentTypes.values():
        if options[_type]:
            config['type'] = _type

    sniff = options['--sniff']
    if sniff is not None:
        try:
            sniff = int(sniff)
        except (ValueError, TypeError):
            sniff = None
    config['sniffport'] = sniff

    name = options['--name']
    if name is not None:
        config['name'] = name

    return config

def main():
    configure_logging()
    options = docopt(__doc__)
    config = config_from_options(options)

    agent_type_map = {
        AgentTypes.TCP: TcpPortAgent,
        AgentTypes.RSN: RsnPortAgent,
        AgentTypes.BOTPT: BotptPortAgent,
        AgentTypes.DATALOG: DatalogReadingPortAgent,
    }

    try:
        from camhd import CamhdPortAgent
        agent_type_map[AgentTypes.CAMHD] = CamhdPortAgent
    except ImportError as e:
        traceback.print_exc()
        log.err('Unable to import CAMHD libraries', e)

    try:
        from antelope import AntelopePortAgent
        agent_type_map[AgentTypes.ANTELOPE] = AntelopePortAgent
    except ImportError as e:
        traceback.print_exc()
        log.err('Unable to import Antelope libraries', e)

    agent_type = config['type']
    agent = agent_type_map.get(agent_type)
    if agent is not None:
        agent(config)
        exit(reactor.run())
    else:
        exit(1)

if __name__ == '__main__':
    main()