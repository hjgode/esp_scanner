import scapy.all as scapy
import csv
import requests

# sudo setcap cap_net_raw=eip $(readlink -f $(which python))

mac_list=[]
mac_tuple=()

def get_title(ip_adress):
    hearders = {'headers':'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:51.0) Gecko/20100101 Firefox/51.0'}
    n = requests.get('http://{}'.format(ip_adress), headers=hearders)
    al = n.text
    title=al[al.find('<title>') + 7 : al.find('</title>')]
    return title

def read_csv():
    reader = csv.DictReader(open('macs_espressif.csv'))
    for row in reader:
        mac_list.append(row['Mac Prefix'])
#        print(row['Mac Prefix'])
#    print("len list={}".format(len(mac_list)))
    mac_tuple = tuple(mac_list)
    return mac_tuple

def get_vendor(mac_adress):
    #if len(mac_tuple)==0:
    #   read_csv()
    #print("len={}".format(len(mac_tuple)))
    myLookup = mac_adress.upper() # 11:22:33:
    #myLookup = (myLookup[0:8])
#    print("myLookup {}".format(myLookup))
    x=0
    if myLookup.startswith(mac_tuple):
        #if myLookup in mac_tuple:
        #x = mac_list.index(mylookup)
#        print("lookup for {} gives x={}".format(myLookup, x))
        x=1
    else:
        x=-1
    return x

def scan(ip_range):
    print(f"Scanning IP range: {ip_range}")
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    print("Sending ARP requests...")
    answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=True)[0]
    if not answered_list:
        print("No responses received.")
    else:
        print("Responses received.")
    devices = []
    for element in answered_list:
        device = {'ip': element[1].psrc, 'mac': element[1].hwsrc}
        x = get_vendor(element[1].hwsrc)
        if x == 1:
            devices.append(device)
            title=get_title(element[1].psrc)
            print("Title: {}".format(title))
            #print(f"Device found: IP = {device['ip']}, MAC = {device['mac']}")

    return devices

def display_devices(devices):
    if devices:
        print("found {} Espressif devices".format(len(devices)))
        print("\nIP\t\t\tMAC Address for Espressif devices")
        print("-----------------------------------------")
        for device in devices:
            print(f"{device['ip']}\t\t{device['mac']}")
    else:
        print("No devices found.")
def scan_network(ip_range):
    devices = scan(ip_range)
    display_devices(devices)

if __name__ == "__main__":
    mac_tuple=read_csv()
    print("comparing to {} known Espressif MAC adresses".format(len(mac_tuple)))
    ip_range = '192.168.0.0/24'
    scan_network(ip_range)

