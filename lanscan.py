#--------------------------------------------------------------------------#
# TODO:
#   make spoofing capabilities
#   make aircrack capabilities
#   make tshark capabilities            -> wirescan.py
#   make nmap udp scan
#   make argparse work
#   
#   make 
# allow the program to automatically detect ip address
# moreover, allow the program to detect the netmask to list posssible scan addresses

#
#-----------------------------------[ MODULES ]-----------------------------------#


# running the scan commands
from subprocess import run, Popen

# for parsing scan outputs
from re import findall, search





#-----------------------------------[ CLI ]-----------------------------------#


#
#   -h        prints this information
#   -l        does a host lookup



    # program desc
# parser = argparse.ArgumentParser(
#     prog="NmapScan",
#     description="A tool to scan networks and systems for open ports and other data.",
#     usage='%(prog)s [options] <destination>'
# )
# 
# # destination
# parser.add_argument("destination", type=str, help="the destination address for the scan")
# 
# # options  
# parser.add_argument("-l", "--hostscan", type=str, help="perform a system scan on LAN");
# 
# parser.add_argument("-h", "--help", type=int, help="displays this message") #? 
# 
# args = parser.parse_args()
# 
# print(
#     f"\ndestination: {args.destination}\nhostscan: {args.l}\n{args.help}"
# )
# 
# args = parser.parse_args()
# 
# print(args) 
# 
# exit(0) 




ip_color = "\u001b[1;38;5;162m"
proto_color = "\u001b[1;38;5;111m"
num_color = "\u001b[1;38;5;9m"
bar_color = "\u001b[1;38;5;162m"
g_color = "\u001b[m"
g_color = "\u001b[m"
g_color = "\u001b[m"
cl = "\u001b[m"
bc = "\u001b[1;37m"

#-----------------------------------[ HOST ]-----------------------------------#





class File:
    def __init__(self, file, length, content, location = None):
        self.file = file
        self.content = content
        self.length = length
        self.location = location

class Request:
    def __init__(self, method, file):
        self.method = method
        self.file = file
        


# defines a port object
class Port:
    def __init__(self, host, protocol: str, service: str):
        self.host = host
        self.proto = protocol
        self.service = service
        
        self.inbound_sessions = []
        self.outbound_sessions = []


    # makes a string representation of all of the inbound sessions found on the port
    def inbound(self):
        i_str = "INBOUND: "
        if len(self.inbound_sessions) > 0:
            for sesh in self.inbound_sessions:
                if sesh.protocol == "HTTP":
                    i_str = f"{i_str}\n{self.proto}{sesh.get_http(self.host)}"
                else:
                    i_str = f"{i_str}\n\n{sesh.get_sum(self.host)}"

            i_str = f"{i_str}\n"
            
        else:
            i_str = f"{i_str}None"
    
        return i_str

    
#     def outbound(self):
#         o_str = "OUTBOUND: "
#         if len(self.outbound_sessions) > 0:
#             for sesh in self.outbound_sessions:
#                 if sesh.protocol == "HTTP":
#                     o_str = f"{o_str}\n\n{sesh.get_http(self.host)}"
#                 else:
#                     o_str = f"{o_str}\n\n{sesh.get_sum(self.host)}"
# 
#             o_str = f"{o_str}\n"
# 
#         else:
#             o_str = f"{o_str}None"
# 
#         return o_str



# defines a host that is up on the network
class Host:
    def __init__(self, ipaddr: str, macaddr: str = ""):
    
        # ip address of the host
        self.ip: str = ipaddr

        # mac address of the host
        self.mac = macaddr
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


        # TODO for future development with wireshark incorperated scan
        self.inbound = {}
        self.outbound = {}
        

    # gets the mac address of the target via arp query
    def get_mac(self):
        if self.mac == "":
            command = ["arping", "-f", self.ip]
            result = run(command, capture_output=True, text=True)

            match_mac = findall(r"\[([\S]{17})\]", result.stdout)
            
            ################### debug
            if match_mac:
                self.mac = match_mac[0]
            else:
                print(f"couldnt arp mac address... {result.stdout}")



    # TODO:                                                 TEST
    # gets the service information on all open ports
    def get_service_version(self):
        if len(self.ports.keys()) > 0:

            # serialize all ports for arguments
            port_str = ",".join([str(port) for port in self.ports.keys()])
            
            command = ["nmap", "-sS" "-p", port_str, self.ip]
            result = run(command, capture_output=True, text=True)

            print(result)  # TEST
                
        
    # scan for open TCP ports
    def port_sweep(self):

        command = ["nmap", "-Pn", "-v", "-O", "-sS", "", self.ip]
        result = run(command, capture_output=True, text=True)

        if result.stderr:
            print(f"PORTSWEEP ERROR: \n\n{result.stderr}\n\n")

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
        port_str = "\n==================================\n\n"
        
        out_ports = {}
        in_ports = {}
        if len(self.ports):
            for num, port in self.ports.items():
                port_str = f"{port_str}"
                
                if len(port.inbound_sessions) > 0:
                    if num in in_ports.keys():
                    
                        in_ports[num].append(port.inbound_sessions)
                    else:
                        in_ports[num] = [port.inbound_sessions]
                        
                if len(port.outbound_sessions) > 0:
                    if num in out_ports.keys():
                        
                        out_ports[num].append(port.outbound_sessions)
                    else:
                        out_ports[num] = [port.outbound_sessions]


               

            else:

                port_str = f"{port_str}INBOUND: \n"
                
                for port, sessions in in_ports.items():
                    
                    for sesh in sessions:
                        for s in sesh:
                            if s.protocol == "HTTP":
                                port_str = f"{port_str}{self.ports[port].proto} {s.get_http(self.ip)}\n"
                            else:
                                port_str = f"{port_str}{self.ports[port].proto} {s.get_sum(self.ip)}\n"
            
                port_str = f"{port_str}==================================\nOUTBOUND: \n"
                
                for port, sessions in out_ports.items():

                    for sesh in sessions:
                        for s in sesh:
                            if s.protocol == "HTTP":
                                port_str = f"{port_str}{self.ports[port].proto} {s.get_http(self.ip)}\n"
                            else:
                                port_str = f"{port_str}{self.ports[port].proto} {s.get_sum(self.ip)}\n"
                                
        else:
            port_str = "No Open Ports"

        return f"""
{bar_color}==================================
HOST:       
    IP: {ip_color}{self.ip}{cl}      
    MAC: {self.mac}
    PORTS: {port_str}

"""



