from scapy.all import ARP, Ether, srp
from scapy.all import*
conf.use_pcap

#If you are on windows you will need to go to this website and download npcap
# https://npcap.com/#download
target_ip = "192.168.1.1/24"


arp = ARP(pdst=target_ip)



ether = Ether(dst="ff:ff:ff:ff:ff:ff")


packet = ether/arp

result =srp(packet, timeout = 3)[0]

clients = []


for sent,received in result:

	clients.append({'ip': received.psrc, 'mac': received.hwsrc})

print('Available devicesin the network:')
print("IP" + " "*18+"MAC")
for client in clients:
	print("{:16} {}".format(client['ip'], client['mac']))

