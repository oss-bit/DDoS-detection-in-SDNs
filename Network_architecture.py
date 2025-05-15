#!/usr/bin/env python

from mininet.node import Host 
from mininet.node import OVSKernelSwitch
from mininet.topo import Topo
from mininet.log import setLogLevel, info

class DDosTestNetwork(Topo):
    def buildselfwork(self):
        setLogLevel( 'info' )

        info( '*** Add switches\n')
        s1 = self.addSwitch('s1', cls=OVSKernelSwitch)
        s2 = self.addSwitch('s2', cls=OVSKernelSwitch, failMode='standalone')
        s3 = self.addSwitch('s3', cls=OVSKernelSwitch, failMode='standalone')
        s4 = self.addSwitch('s4', cls=OVSKernelSwitch, failMode='standalone')
        s5 = self.addSwitch('s5', cls=OVSKernelSwitch, failMode='standalone')
        s6 = self.addSwitch('s6', cls=OVSKernelSwitch, failMode='standalone')

        info( '*** Add hosts\n')
        attacker1 = self.addHost('attacker1', cls=Host, ip='10.0.0.1', defaultRoute=None)
        h2 = self.addHost('h2', cls=Host, ip='10.0.0.2', defaultRoute=None)
        h3 = self.addHost('h3', cls=Host, ip='10.0.0.3', defaultRoute=None)
        h4 = self.addHost('h4', cls=Host, ip='10.0.0.4', defaultRoute=None)
        attacker2 = self.addHost('attacker2', cls=Host, ip='10.0.0.5', defaultRoute=None)
        Server1 = self.addHost('Server1', cls=Host, ip='10.0.0.6', defaultRoute=None)
        attacker3 = self.addHost('attacker3', cls=Host, ip='10.0.0.7', defaultRoute=None)
        h8 = self.addHost('h8', cls=Host, ip='10.0.0.8', defaultRoute=None)
        h9 = self.addHost('h9', cls=Host, ip='10.0.0.9', defaultRoute=None)
        h10 = self.addHost('h10', cls=Host, ip='10.0.0.10', defaultRoute=None)
        attacker4 = self.addHost('attacker4', cls=Host, ip='10.0.0.11', defaultRoute=None)
        h12 = self.addHost('h12', cls=Host, ip='10.0.0.12', defaultRoute=None)
        h13 = self.addHost('h13', cls=Host, ip='10.0.0.13', defaultRoute=None)
        h14 = self.addHost('h14', cls=Host, ip='10.0.0.14', defaultRoute=None)
        attacker5 = self.addHost('attacker5', cls=Host, ip='10.0.0.15', defaultRoute=None)
        h16 = self.addHost('h16', cls=Host, ip='10.0.0.16', defaultRoute=None)
        Server1 = self.addHost('Server1', cls=Host, ip='10.0.0.17', defaultRoute=None)
        h18 = self.addHost('h18', cls=Host, ip='10.0.0.18', defaultRoute=None)
        attacker6 = self.addHost('attacker6', cls=Host, ip='10.0.0.19', defaultRoute=None)
        h20 = self.addHost('h20', cls=Host, ip='10.0.0.20', defaultRoute=None)

        info( '*** Add links\n')
        self.addLink(s1, s2)
        self.addLink(s1, s3)
        self.addLink(s1, s4)
        self.addLink(s1, s5)
        self.addLink(s1, s6)
        self.addLink(s2, attacker1)
        self.addLink(s2, h2)
        self.addLink(s2, h3)
        self.addLink(s2, h4)
        self.addLink(s3, attacker2)
        self.addLink(s3, Server1)
        self.addLink(s3, h8)
        self.addLink(s3, attacker3)
        self.addLink(s4, h9)
        self.addLink(s4, h10)
        self.addLink(s4, attacker4)
        self.addLink(s4, h12)
        self.addLink(s5, h13)
        self.addLink(s5, attacker5)
        self.addLink(s5, h16)
        self.addLink(s5, h14)
        self.addLink(s6, attacker6)
        self.addLink(s6, h20)
        self.addLink(s6, Server1)
        self.addLink(s6, h18)



