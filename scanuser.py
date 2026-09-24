
# running the scan commands
from subprocess import run, Popen

# for parsing scan outputs
from re import findall, search,split

# for caching the contents of the hosts
from pickle import dump, load

# for host scan on a network
from lanscan import Host

# for collecting analyzing network traffic
from wirescan import TrafficCollector

from os import listdir

# 
# colors = [
# 
#     "\x1b[1;1071m"
#     Bright Red 91	101
#     Bright Green	92	102
#     Bright Yellow	93	103
#     Bright Blue	94	104
#     Bright Magenta	95	105
#     Bright Cyan	96	106
#     Bright White	97	107
# ]
title_color = "\u001b[97m"
cl = "\u001b[m"

#----------------------------------[ NIC ]----------------------------------#

class IFACE:

    # IFACE class represents a network interface card to read from wireshark with

    def __init__(self, name, ia, ba, nm, s):
        self.name = name
        self.inet_addr = ia
        self.bcst_addr = ba
        self.netmask = nm
        self.status = s
        self.possible_net_addresses = None
        self.CDIR = None


    # prints a debug message
    def debug(self):
        print(f"\nIP: {self.inet_addr}\nBROADCAST: {self.bcst_addr}\nADDRESSES: {self.possible_net_addresses}\n")


    # gets the number of possible ip addresses in the network 
    # and the CDIR notation of the network's netmask
    def get_CDIR(self):
        if self.netmask != None:
            parts = split(r"\.", self.netmask)

            wc = [f"{'{0:08b}'.format(abs(int(parts[i])-255))}" for i in range(len(parts))]

            
            wc = "".join(wc)

            self.possible_net_addresses = 2**len(findall("1", wc))
            self.CDIR = 32 - len(findall("1", wc))
        

    # creates a new interface object from the interface name 
    # and the chunk received from 
    @staticmethod
    def new_iface(name, chunk):

        try:
            ia, ba, nm = findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", chunk)
        except Exception as eerr:
            ia = ba = nm = None
        
        up = search(r"\sUP\s", chunk)

        return IFACE(name, ia, ba, nm, up)







#----------------------------------[ USER ]----------------------------------#




class User:

    def __init__(self, alternate_pcap_dir = None):
        self.ifaces = {}                                    # <ifname>: IFACE
        self.selected_iface = None                          # Iface


        self.pcap_dir = alternate_pcap_dir
        self.pcap_files = []
        # self.selected_file = None
        
        

        self.host_cache = "scan_cache/Hosts.pkl"            # cache file 


        self.tc = None                                      # Traffic Collector


        self.scanned_hosts = {}                             # <ip>: 




    # print a debug message
    def debug(self):

        print(f"\n----------------------------------------\n\nNUM HOSTS SCANNED: {len(self.scanned_hosts)}")
            
        print("\n----------------------------------------\n")



#-----------------------------------[ INIT ]-----------------------------------#

    def init_tc(self):

        if not self.pcap_dir is None:
            self.init_files()
    
        self.init_iface()

        self.tc = TrafficCollector(self.scanned_hosts, self.ifaces, self.pcap_files)





    def init_files(self):
        files = listdir(self.pcap_dir)

        for file in files:
            if ".pcap" in file or ".pcapng" in file:
               self.pcap_files.append(f"{self.pcap_dir}/{file}")


        
    # initializes the NIC for the user
    def init_iface(self):
        command = ["ifconfig"]

        results = run(command, capture_output=True, text=True)
        
        parts = split(r"\n\n", results.stdout)
        
        for i in range(len(parts)):
            matches = findall(r"([\w|\d]*?):", parts[i])
            if len(matches):
                iface = IFACE.new_iface(matches[0], parts[i])
                
                if iface != None:
                    iface.get_CDIR()
                    self.ifaces[matches[0]] = iface

       

            

#-----------------------------------[ LOOKUP ]-----------------------------------#

    # scanns for hosts that are up on a network
    # nmap -sn #.#.#.0/24
    def host_scan(self, ip_range) -> list:
        command = ["nmap", "-sn", ip_range]

        result = run(command, capture_output=True, text=True)

        matches = findall(r"(?:[\d]{1,3}\.){3}\d{1,3}", result.stdout)
        
        return matches


#-----------------------------------[ CACHE ]-----------------------------------#


    # cache loaded hosts in host file
    def cache_hosts(self, hosts):
        with open(self.host_cache, 'wb') as host_file:
            dump(hosts, host_file)


    # load previously scanned hosts from the host cache    
    def load_hosts(self):
        with open(self.host_cache, 'rb') as host_file:
            return load(host_file)


#-----------------------------------[ CACHE ]-----------------------------------#

    def init_promisc(self):
        arg = self.selected_iface()
        run("./promisc_init.sh", arg)
    
#----------------------------------[ RUN ]----------------------------------#

    def file_scan(self):
        pass

    def mon(self):
        if not self.tc is None:
            self.tc.choose_iface()
            new_file = input("new file name: ")
            self.tc.collect_mon_traffic(new_file)

        

    # main functionality of the User using an NIC 
    # TODO: make using files or NIC
    def main(self):
        
        if not self.tc is None:
            # choose file before starting the traffic collector
            if self.tc.selected_file == None:
                if self.tc.choose_file() == False:
                    return
                   

           
            # get_new_hosts
            self.tc.get_new_hosts()
            
            for name, host in self.tc.lan_hosts.items():
                print(f"\n{title_color}----------------------------[ {name} ]--------------------------------{cl}\n")
                print(host)


            print("\n----------------------------------------------------------------------\n")
            
                
            return

            # attempt to load hosts
            try:
                self.scanned_hosts = self.load_hosts()

                if Hosts:
                    print("Successfully loaded hosts from cache!")
                    
                    yn = input("Would you like to rescan?\n(y/n):")

                    if yn == "y":
                        raise(Exception())
            except:
                # scan for hosts if loading 
                # the cached hosts werent successful    
                
                print(f"{self.ip[:-3]}0/{self.selected_nic.CDIR}")
     
                hosts_ips = self.host_scan(f"{self.ip[:-3]}0/{self.selected_nic.CDIR}")

                # list of host objects    
                self.scanned_hosts: list = []

                # add ip addresses to the list of hosts 
                for ipaddr in hosts_ips:
                    if ipaddr != self.ip:
                        self.scanned_hosts.append(Host(ipaddr))
                        print(f"found {ipaddr}")
                else:
                    print("\n")
                    
                # load the connected hosts
                self.cache_hosts(Hosts)

            # hosts have either been loaded from cache
            # or they have been scanned again
            finally:

                # go through the hosts and perfome something
                for host in self.scanned_hosts:
                    print(f"########################  {host.ip} DATA  ########################")
                        
                    # scan tcp ports and get OS/MAC data
                    tcp_results = host.port_sweep()
                    
                    # try:
                    #     host.collect_traffic()
                    # except Exception as e:
                    #     print(f"####################\nERROR{e}\n###################")
                    # else:
                    #     print(host.analyze_traffic())
                    
                    # display port scanning results
                    if len(host.ports):
                        # display port information    
                        for portnum, port in host.ports.items():
                            print(f"{port.proto}  {port.service}   @   {host.ip}:{portnum}")
                        else:
                            print("\n")
                    else:
                        print(f"{host.ip}: No Ports open\n")
                    
                    
                else:
                    print("\n\n##############################################################\n")
                    ############## debug __str__ implementation
                    for host in self.scanned_hosts:
                        print(host)

                    # cache the resulting hosts for future use
                    print("Caching scanned hosts and quiting...\n")
                    self.cache_hosts(self.scanned_hosts)
                    print("\n\n##############################################################\n")

        else:
            raise(Exception("Traffic Collector has yet to be initialized"))



def monitor(selected_dir):
    print("[+] Starting monitor capture\n\n")
    u = User(selected_dir)
    u.init_tc()
    u.mon()  
    print("[+] Finished monitor Mode!\n\n")

def scan_files(selected_dir):
    print("[+] Starting file scan\n\n")
    u = User(selected_dir)
    u.init_tc()
    u.main()

# captures traffic from a file and 
def capture_traffic(cache_dir="scan_cache"):
    print("[+] Starting capture\n\n")
    u = User(cache_dir)
    u.init_tc() # initializes traffic collector and pcap files
    u.tc.choose_iface() # initializes interfaces
    u.tc.collect_traffic() # collect packets from the selected interface
    u.main()
    

# TODO
def promisc():
    print("[+] Starting promiscuous capture, except i havent tested it yet... sorry")
    # u = User()
    # u.init_tc()
    # u.init_pomisc()
    #
   
    
# methods of packet capture:
#   . wifi interface
#   . 
#
#
#


if __name__ == "__main__":

    # change this directory to one with pcap or pcapng files in it
    SEL_DIR = "examples"

    # this directory holds cached objects from captured or scanned requests 
    CACHE_DIR = "scan_cache"


    

    # u = User(SELECTED_FILE)

    menu_options = [
        "\tf:\t# scan a file(pcap, pcappn)",
        "\tm:\t# monitor traffic from wifi interface(monitor mode)",
        "\tp:\t# capture traffic from wifi interface(promiscuous mode)",
        "\tc:\t# collect traffic from iface on network",
        "\tq:\t# quit",
    ]

    
    while True:
        t = input(f"COMMANDS:\n{'\n'.join([m for m in menu_options])})\n\n(f,m,p,c): ")

        match t:
            case "f":
                scan_files(SEL_DIR)
                break
                
            case "m":
                monitor(SEL_DIR)
                break
            case "p":
                promisc()
                break
            case "c":
                capture_traffic(CACHE_DIR)
                break
                
            case "q":
                break

            case _:
                continue
