import socket
from scapy.layers.12 import ARP, Ether
from scapy.sendrecv import srp

from threading import Thread, Lock

print_Lock = Lock()

def scanHost(ip, startPort, endPort):
    print('[*] Starting TCP port scan on host %s' % ip)

    tcp_scan(ip, startPort, endPort)
    print('[+] TCP scan on host %s complete' % ip)

def scanRange(network, startPort, endPort):
    print('[*] Starting TCP port scan on network %s.0' % network)

    for host in range(1,255):
        ip = network + "." + str(host)
        tcp_scan(ip, startPort, endPort)

    print('[+] TCP scan on network %s.0 complete' % network)

def tcp_scan(ip, startPort, endPort):
    for port in range(startPort, endPort+1):
        try :
            tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp.settimeout(0.1)
            if not tcp.connect_ex((ip, port)):
                with print_Lock:
                    print('[+] &s:%d/TCP Open' %(ip,port))
                tcp.close()

        except Exception:
            pass

def network_scan(target_ip):

    arp = ARP(pdst=target_ip)

    ether = Ether(dst="ff:ff:ff:ff:ff:ff")

    packet = ether/arp

    result = srp(packet, timeout=3, verbose=0)[0]

    clients = []

    for sent, received in result:
        clients.append({'ip': received.psrc, 'mac':received.hwsrc})

    with print_Lock:
        print("Available devices in the network :")
        print("IP" + " "*18 + "MAC")
        for client in clients:
            print("{:16}    {}".format(client['ip'], client['mac']))

