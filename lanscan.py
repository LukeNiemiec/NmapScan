#--------------------------------------------------------------------------#
# TODO:
#   make spoofing capabilities
#   make aircrack capabilities
#   make tshark capabilities            -> wirescan.py
#
#
#--------------------------------------------------------------------------#


# running the scan commands
from subprocess import run, Popen

# for parsing scan outputs
from re import findall, search

# for caching the contents of the hosts
from pickle import dump, load

# change to your specified interface
IFACE = "wlp0s20f0u1"
MYIP = "192.168.1.16"

#--------------------------------------------------------------------------#


# defines a port object
class Port:
    def __init__(self, protocol: str, service: str):
        self.proto = protocol
        self.service = service
        self.traffic = {
            "sent": [],
            "rcvd": [],
        }
    
            

# defines a host that is up on the network
class Host:
    def __init__(self, ipaddr: str):
    
        # ip address of the host
        self.ip: str = ipaddr

        # mac address of the host
        self.mac: str = ""
        self.vendor: str = ""
        
        # operating system of the host
        self.OS: dict = {
            "Device Type": None,
            "Running": None,
        }

        # port number: Port OBJ
        self.ports: dict = {}
        
        # list of scanned ports to keep track
        self.scanned_ports: list = [] 

        # tells whether the host can be a suitable zombie
        self.zombie = False 

        self.traffic = {
            "sent": [],
            "recieved": [],
        }


    # gets the mac address of the target via arp query
    def get_mac(self):

        command = ["arping", "-f", self.ip]
        result = run(command, capture_output=True, text=True)

        match_mac = findall(r"\[([\S]{17})\]", result.stdout)
        
        ################### debug
        if match_mac:
            self.mac = match_mac[0]
        else:
            print(f"couldnt arp mac address... {result.stdout}")
        
    # scan for open TCP ports
    def port_sweep(self):

        command = ["nmap", "-Pn", "-v", "-O", "-sS", "-r", self.ip]
        result = run(command, capture_output=True, text=True)

        matches = findall(r"([\d]{1,5})\/([\w]{3})\s*?open\s*?([\s\S]*?)\n", result.stdout)
        dev_type = search(r"Device\stype:\s([\S]*?)(?:\s|\\n|\n)", result.stdout)
        dev_os = search(r"Running:\s([\S\s]*?)(?:\\n|\n)", result.stdout)
        
        if dev_type:
            self.OS["Device Type"] = dev_type.group()
        
        if dev_os:
            self.OS["Running"] = dev_os.group()
            
        # checks if host can be used in an idle scan
        if search(r"[I|i]ncremental", result.stdout):
            self.zombie = True
            
        # add all open ports to the host's portlist
        for (port, proto, serv) in matches:
            self.ports[port] = Port(proto, serv.strip())
                
        # identifies the mac address of the hosts NIC and vendor if specified
        mac_matches = findall(r"MAC Address:\s([\S]{17})\s(\([\s\S]*?\))\n", result.stdout)

        # set the mac address of the host 
        if mac_matches:
            self.mac = mac_matches[0][0]
            self.vendor = mac_matches[0][1]
        else:
            self.get_mac()


    # format the host's results
    def __str__(self):
        port_str = "\n"
        
        if len(self.ports):
            for num, port in self.ports.items():
                port_str = f"{port_str}\n{num}/{port.proto}: {port.service}"

            else:
                port_str = f"{port_str}\n"
        else:
            port_str = "No Open Ports"

        return f"""
----------------------------------------------
HOST:       IP: {self.ip}      MAC: {self.mac}

DEV DETAILS: 

    VENDOR: {self.vendor}

    TYPE: {self.OS['Device Type']}

    OS: {self.OS['Running']}

    ZOM: {self.zombie}
    
PORTS: {port_str}

"""


#--------------------------------------------------------------------------#


# scanns for hosts that are up on a network
# nmap -sn #.#.#.0/24
def host_scan(ip_range) -> list:
    command = ["nmap", "-sn", ip_range]

    result = run(command, capture_output=True, text=True)

    matches = findall(r"(?:[\d]{1,3}\.){3}\d{1,3}", result.stdout)
    
    return matches

#--------------------------------------------------------------------------#


# cache loaded hosts in host file
def cache_hosts(hosts):
    with open('scan_cache/Hosts.pkl', 'wb') as host_file:
        dump(hosts, host_file)


# load previously scanned hosts from the host cache    
def load_hosts():
    with open('scan_cache/Hosts.pkl', 'rb') as host_file:
        return load(host_file)


#--------------------------------------------------------------------------#


# run main functionality if script is ran directly
if __name__ == "__main__":    

    Hosts = None

    # attempt to load hosts
    try:
        assert Hosts
        Hosts = load_hosts()

        if Hosts:
            print("Successfully loaded hosts from cache!")
        
    except:
        # scan for hosts if loading 
        # the cached hosts werent successful    
        print("Couldnt load hosts cache, scanning again...\n")

    
        # gets a list of ip addresses
        # of hosts ip addresses on the network
        hosts_ips = host_scan("192.168.1.0/24")

        # list of host objects    
        Hosts: list = []

        # add ip addresses to the list of hosts 
        for ipaddr in hosts_ips:
            if ipaddr != MYIP:
                Hosts.append(Host(ipaddr))
                print(f"found {ipaddr}")
        else:
            print("\n")
            
        # load the connected hosts
        cache_hosts(Hosts)

    # hosts have either been loaded from cache
    # or they have been scanned again
    finally:

        # go through the hosts and perfome something
        for host in Hosts:
            print(f"########################  {host.ip} DATA  ########################")
                
            # scan tcp ports and get OS/MAC data
            tcp_results = host.scan_TCP()
            
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
            for host in Hosts:
                print(host)

            # cache the resulting hosts for future use
            print("Caching scanned hosts and quiting...\n")
            cache_hosts(Hosts)
            print("\n\n##############################################################\n")

