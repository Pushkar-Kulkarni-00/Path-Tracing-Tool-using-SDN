"""
Run this from the Mininet host or as a script after starting the network.
Usage: sudo python3 test_scenarios.py
"""
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.log import setLogLevel
from topo import PathTopo
import time

def run_tests():
    setLogLevel('info')
    net = Mininet(topo=PathTopo(),
                  controller=RemoteController('c0', ip='127.0.0.1', port=6633))
    net.start()
    h1, h2 = net.get('h1', 'h2')

    print("\n" + "="*50)
    print("SCENARIO 1: Normal Path Tracing (h1 -> h2)")
    print("="*50)
    result = h1.cmd('ping -c 4 10.0.0.2')
    print(result)

    print("\n" + "="*50)
    print("SCENARIO 2: Throughput Test (iperf)")
    print("="*50)
    h2.cmd('iperf -s &')
    time.sleep(1)
    result = h1.cmd('iperf -c 10.0.0.2 -t 5')
    print(result)

    print("\n" + "="*50)
    print("FLOW TABLE DUMP (all switches)")
    print("="*50)
    for sw in ['s1', 's2', 's3']:
        s = net.get(sw)
        print(f"\n--- {sw} ---")
        print(s.cmd(f'ovs-ofctl -O OpenFlow13 dump-flows {sw}'))

    net.stop()

if __name__ == '__main__':
    run_tests()
