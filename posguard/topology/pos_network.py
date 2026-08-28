from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel

def create_pos_topology():
    net = Mininet(controller=RemoteController, switch=OVSSwitch)
    c0 = net.addController('c0', ip='127.0.0.1', port=6633)
    s1 = net.addSwitch('s1', protocols='OpenFlow13')

    # POS terminals
    pos1 = net.addHost('pos1', ip='10.0.0.1/24')
    pos2 = net.addHost('pos2', ip='10.0.0.2/24')
    pos3 = net.addHost('pos3', ip='10.0.0.3/24')

    # Gateway & Server
    gateway = net.addHost('gateway', ip='10.0.0.100/24')
    server = net.addHost('server', ip='10.0.0.200/24')

    # Links
    for h in [pos1, pos2, pos3, gateway, server]:
        net.addLink(h, s1)

    net.start()
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    create_pos_topology()
