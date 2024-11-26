from scapy.all import ARP, Ether, srp
from socket import socket, AF_INET, SOCK_STREAM
import networkx as nx
import matplotlib.pyplot as plt

def host_discover(subnet):
	print(f"-- Scanning for hosts on: {subnet} --")
	arp = ARP(pdst=subnet)
	ether = Ether(dst="ff:ff:ff:ff:ff:ff")
	packet = ether / arp

	result = srp(packet, timeout=2, verbose=False)[0]

	hosts = []
	for sent, received in result:
		hosts.append({'ip': received.psrc, 'mac': received.hwsrc})

	print(f"Discovered {len(hosts)} host(s).")
	return hosts

def scan_ports(ip, ports):
	open_ports = []
	for port in ports:
		try:
			s = socket(AF_INET, SOCK_STREAM)
			s.settimeout(1)
			result = s.connect_ex((ip, port))
			if result == 0:
				open_ports.append(port)
			s.close()
		except Exception:
			pass
	return open_ports

def mapper(subnet, ports):

	hosts = host_discover(subnet)
	network_map = []
	for host in hosts:
		print(f"Scanning {host['ip']} ")
		open_ports = scan_ports(host['ip'], ports)
		host['open_ports'] = open_ports
		network_map.append(host)
	return network_map

def network_visual(network_map):
	graph = nx.Graph()
	for device in network_map:
		graph.add_node(device['ip'], mac=device['mac'])
		for port in device['open_ports']:
			graph.add_edge(device['ip'], f"Port {port}")

	pos = nx.spring_layout(graph)
	nx.draw(graph, pos, with_labels=True, node_color="lightblue", edge_color="gray", node_size=1500, font_size=10)
	plt.title("Network_Topology")
	plt.show()

if __name__ == "__main__":
	subnet = input("Enter a subnet (ex: 192.168.0.1/24): ")
	ports = [21, 22, 23, 25, 80, 443, 3389]

	network_map = mapper(subnet, ports)

	print("\nNetwork Map: ") 	
	for device in network_map:
		print(f"IP: {device['ip']}, MAC: {device['mac']}, Open Ports: {device['open_ports']}")

	network_visual(network_map)