import scapy.all as scapy
import csv
import requests
import sys

# sudo setcap cap_net_raw=eip $(readlink -f $(which python))

devices=[]
mac_list=[]
mac_tuple=()
_vendor_name="Espressif"

def get_title(ip_adress):
    hearders = {'headers':'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:51.0) Gecko/20100101 Firefox/51.0'}
    n = requests.get('http://{}'.format(ip_adress), headers=hearders)
    al = n.text
    title=al[al.find('<title>') + 7 : al.find('</title>')]
    return title

def get_status_tasmota(ip_adr):
    # http://192.168.0.104/cm?cmnd=status
    return

def read_espressif_csv(vendor_name):
    global mac_tuple
    global mac_list
#    reader = csv.DictReader(open('macs_espressif.csv'))
    reader = csv.DictReader(open('mac-vendors-export.csv'))
    for row in reader:
        if vendor_name.upper() in row['Vendor Name'].upper() : 
            mac_list.append(row['Mac Prefix'])
#            print(row['Mac Prefix'])
#    print("len list={}".format(len(mac_list)))
    mac_tuple = tuple(mac_list)
    return mac_tuple

def get_vendor(mac_adress):
    global mac_tuple
    #if len(mac_tuple)==0:
    #   read_csv()
    #print("len={}".format(len(mac_tuple)))
    myLookup = mac_adress.upper() # 11:22:33:
    #myLookup = (myLookup[0:8])
#    print("myLookup {}".format(myLookup))
    x=0
#    print("myLookup: {} mac_tuple: {}".format(myLookup, mac_tuple))
    
    if myLookup.startswith(mac_tuple):
        #if myLookup in mac_tuple:
        #x = mac_list.index(mylookup)
#        print("lookup for {} gives x={}".format(myLookup, x))
        x=1
    else:
        x=-1
    return x

def scan(ip_range):
    global devices
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

        x = get_vendor(element[1].hwsrc)
        if x == 1:
            title=get_title(element[1].psrc)
            device = {'ip': element[1].psrc, 'mac': element[1].hwsrc, 'title': title}
            devices.append(device)

            #print("Title: {}".format(title))
            #print(f"Device found: IP = {device['ip']}, MAC = {device['mac']}")

    return devices

def display_devices(devices):
    if devices:
        print("found {} Espressif devices".format(len(devices)))
        print("\nIP\t\t\tMAC Address\t\ttitle")
        print("----------------------------------------------------------------")
        for device in devices:
            print(f"{device['ip']}\t\t{device['mac']}\t\t{device['title']}")
    else:
        print("No devices found.")
    return

def scan_network(ip_range):
    devices = scan(ip_range)
    display_devices(devices)
    return

def main():
    global mac_tuple
    _vendor_name="Espressif"
    arglen=len(sys.argv)
    if arglen == 2:
        print("Usage: python espressif-scanner.py <arg1>")
        _vendor_name = sys.argv[1]
        print(f"Argument 1: {_vendor_name}")
    
    mac_tuple=read_espressif_csv(_vendor_name)
    print("comparing to {} known {}  MAC adresses".format(len(mac_tuple), _vendor_name))
    ip_range = '192.168.0.0/24'
    scan_network(ip_range)
    return

if __name__ == "__main__":
    main()

