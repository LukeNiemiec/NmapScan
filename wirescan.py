
#--------------------------------------------------------------------------#

from subprocess import run, Popen

# for parsing scan outputs
from re import findall, search, split

# for implementing new hosts
from lanscan import Host, Port, File, Request

# filesystem functionality
from os import listdir, mkdir, rmdir

import threading as th
from concurrent.futures import ThreadPoolExecutor, as_completed

#--------------------------------------------------------------------------#



ip_color = "\u001b[1;38;5;162m"
proto_color = "\u001b[1;38;5;111m"
num_color = "\u001b[1;38;5;9m"
bar_color = "\u001b[1;38;5;162m"
b = "\u001b[1m"

cl = "\u001b[m"
bc = "\u001b[1;37m"


#--------------------------------------------------------------------------#


HTTP_RM = ["GET","POST","PUT","DELETE","PATCH","HEAD","OPTIONS","CONNECT","TRACE"]


# Outlines a TCPSession between two systems 
class TCPSession:
    def __init__(self, initiator, sp, requestor, dp, protocol, session_num, start_time, file):
        self.initiator = initiator 
        self.src_port = sp
        self.requestor = requestor
        self.dst_port = dp
        self.protocol = protocol
        self.session_num = int(session_num)
        self.start_time = start_time
        self.file = file
        self.object_dir = f"scan_cache/{self.session_num}/"
        
        self.session_len = 0
        
        self.data = {
            f"{initiator.ip}": None, 
            f"{requestor.ip}": None
        }

    # returns a summary of packets that the specified ip address within this conversation 
    # TODO: make sure the information makes sense on the output
    def get_sum(self, ip):
    
        if ip == self.initiator.ip:
           return f"/ {self.protocol} To {ip_color}{self.requestor.ip}{cl}:{self.dst_port}"
            
        elif ip == self.requestor.ip:
            return f"/ {self.protocol} From {ip_color}{self.initiator.ip}{cl}:{self.src_port}"

    
        else:
            return "?"
            # return why the fuck string

    # returns a summary like get_sumn() however, it outputs more on the 
    def get_http(self, ip):
    
        if ip == self.initiator.ip:
            req = self.data[self.requestor.ip]
            
            return f"/ {self.protocol} {num_color}{req.content}{cl} To {ip_color}{self.requestor.ip}{cl}:{self.dst_port}{req.file}"
            # return string 

            
        elif ip == self.requestor.ip:
            host = self.data[self.initiator.ip]
            
            return f" / {self.protocol} REQ {proto_color}{host.method} {host.file}{cl} From {ip_color}{self.initiator.ip}{cl}:{self.src_port} {num_color}{self.data[ip].content}{cl}"
    
        else:
            return "?"
            # return why the fuck string


    # creates the object directory
    def clean_objects(self):
        mkdir(self.object_dir)

        
    # gets the protocol of the TCP session
    def get_protocol(self):
        command = ["tshark", 
            "-r", self.file, 
            "-q",  "-z",
            f"follow,tcp,ascii,{self.session_num}"
        ]


    # analyze http requests in the TCP session
    def analyze_http(self):
        command = ["tshark", "-r", self.file, 
            "-T","fields",
            "-o","tcp.desegment_tcp_streams:TRUE",
            "-Y", f"tcp.stream == {self.session_num} && tcp.port == 80",
            "-e"," http.request.method",
            "-e","http.content_type",
            "-e","http.request.uri",
            "-e", "http.content_length",
            "-E","separator=,"
        ]
        result = run(command, capture_output=True, text=True)

        # check for errors analyzing the HTTP data
        if result.stderr:  
            print(f"\n[ANALYZE HTTP]: ERROR\n{result.stderr}\n\n")
            return

        # if there is http data within the session
        elif result.stdout:
         
            c = list(set([r.strip() for r in result.stdout.split(",") if len(r) > 2]))
            uri = "/"
            ct = rm = l = ""
            
            for s in c:
                try:
                    l = int(s)
                except:
                    
            
                    if s in HTTP_RM:
                        rm = s
                    elif "." in s:
                        uri = s
                    else:
                        ct = s

                else:
                    continue


            src, dst = self.initiator.ip, self.requestor.ip
            
            
            self.data[dst] = File(uri, l, ct)
            self.data[src] = Request(rm, uri)
            self.protocol = "HTTP"
            
            return

        # no data in the HTTP session
        else:
            print(f"\n[ANALYZE HTTP]: no http data found for stream #{self.session_num}")       
            # result = run(command, capture_output=True, text=True)
            # print(f"ANALYZE HTTP METADATA:\n {result.stdout}\n")
    
    # analyzes FTP  
    def analyze_ftp(self):
        command = ["tshark",  "-r", self.file, "-Y",f"tcp.stream == {self.session_num} && tcp.port == 21","--export-objects", f"ftp-data,{self.object_dir}"]
        
        result = run(command, capture_output=True, text=True)     
        if result.stderr:  
            print(f"\n[ANALYZE FTP]: ERROR\n{result.stderr}\n\n")
        else:
            print(f"\n[ANALYZE FTP]: \n{result.stdout}\n\n")        
        
        # make protocol FTP

    # TODO: Analyzes telnet session 
    def analyze_telnet(self):
        # if self.src_port == 23 or self.dst_port == 23:
        command = ["tshark",  "-r", self.file, "-Y",f"tcp.stream == {self.session_num} && tcp.port == 23","-T","fields","-e", "telnet.data"]
            
        result = run(command, capture_output=True, text=True)       
        if result.stderr:  
            print(f"\n[ANALYZE TELNET]: ERROR\n{result.stderr}\n\n")
        elif result.stdout:                                         # CHECK IF WORKS!!!
            print(f"\n[ANALYZE TELNET]: \n{result.stdout}\n\n")    
            
            
        # make protocol telnet

    # TODO: comment this 
    def analyze_stream(self):
#         command = ["tshark", 
#             "-r", self.file, 
#             "-q",  "-z",
#             f"follow,tcp,hex,{self.session_num}"
#         ]
# 
#         results = run(command, capture_output=True, text=True)
        # print(f"STREAM #{self.session_num}\n{results.stdout}\n")

        self.clean_objects()
        self.analyze_http()

    # makes a info string containing the 
    def __str__(self):
        rx_bytes = len(self.data[self.initiator.ip])
        tx_bytes = len(self.data[self.requestor.ip])
    
        s_str = f"({num_color}{self.start_time}{cl}) #{self.session_num}:  {ip_color}{self.initiator.ip}{cl} Sent {num_color}{rx_bytes}{cl} Bytes and Received {num_color}{tx_bytes}{cl} Bytes using {proto_color}{self.protocol}{cl} "
        return s_str

""" TCPSession defines communication done between two systems all of the same port and protocol 
        def analyze_stream(self):
        def analyze_telnet(self):
        def analize_ftp(self):
        def analyze_http(self):
        def get_sum(self):
        def get_prototcol(self):
        def clean_objects(self)

"""


# Conversation class is a classification of packets defined by communication between two
# parties over a period of time that can include many different protocols. This class provides 
# aggregates packets from the selected file.
class Conversation:
    def __init__(self, requestor, responder, pcap_file):
        self.scan_file = pcap_file
        self.p1 = requestor
        self.p2 = responder
        self.records = []
        self.protocols = {}
        self.sessions = []

    # sorts the packets in each protocol by the time they were 
    # recieved relative to the time packet collection started
    def sort_protocols(self):
        for name, record in self.protocols.items():
            self.protocols[name] = dict(sorted(record.items()))



    # Analyzes TCP communication between the two IP addresses
    def analyze_tcp(self):
        print(f"[+] Conversations({self.p1.ip}, {self.p2.ip}) Analyzing tcp now.")
        # diffrientiate tcp sessions
        command = ["tshark", 
            "-r", self.scan_file, 
            "-Y",   f"ip.addr == {self.p1.ip} && ip.addr == {self.p2.ip} && tcp.flags.syn == 1 && tcp.flags.ack == 0",
            "-T", "fields", 
            "-e","frame.time_relative",
            "-e","ip.src",
            "-e","tcp.srcport",
            "-e","ip.dst",   
            "-e","tcp.dstport",   
            "-e","_ws.col.Protocol",        
            "-e", "tcp.stream",
             "-E","separator=,",           
        ]

        
        
        result = run(command, capture_output=True, text=True)
        session_starts = result.stdout.split("\n")[:-1]

        for parts in session_starts:

            t, src, sp, dst, dp, p, sn = parts.split(",")
            
            if src == self.p1.ip:
                
                self.sessions.append(TCPSession(self.p1, sp, self.p2, dp, p, sn, t, self.scan_file))
                
            else:                            
                self.sessions.append(TCPSession(self.p2, sp, self.p1, dp, p, sn, t, self.scan_file))


        if len(self.sessions) > 0:
            for session in self.sessions:
                session.analyze_stream()


    # Analyzes UDP packets between the two IP Addresses
    def analyze_udp(self):
        print(f"[+] Conversations({self.p1.ip}, {self.p2.ip}) Analyzing udp now.")
        # diffrientiate tcp sessions
        command = ["tshark", 
            "-r", self.scan_file, 
            "-Y",   f"ip.addr == {self.p1.ip} && ip.addr == {self.p2.ip} && tcp.flags.syn == 1 && tcp.flags.ack == 0",
            "-T", "fields", 
            "-e","frame.time_relative",
            "-e","ip.src",
            "-e","udp.srcport",
            "-e","ip.dst",   
            "-e","udp.dstport",   
            "-e","_ws.col.Protocol",        
             "-E","separator=,",           
        ]

        
        
        result = run(command, capture_output=True, text=True)
        session_starts = result.stdout.split("\n")[:-1]

        for parts in session_starts:

            t, src, sp, dst, dp, p, sn = parts.split(",")
            
            if src == self.p1.ip:
                
                self.sessions.append(TCPSession(self.p1, sp, self.p2, dp, p, sn, t, self.scan_file))
                
            else:                            
                self.sessions.append(TCPSession(self.p2, sp, self.p1, dp, p, sn, t, self.scan_file))


        if len(self.sessions) > 0:
            for session in self.sessions:
                session.get_stream()


    # Retreives all packets contained in the session
    def get_records(self):
        print(f"[+] Conversations({self.p1.ip}, {self.p2.ip}) Getting records now.")
        ip1, ip2 = self.p1.ip, self.p2.ip
        
        # print(f"getting records for {ip1} and {ip2}")
        
        command = ["tshark", 
            "-r", self.scan_file, 
            "-Y",   f"ip.addr == {self.p1.ip} && ip.addr == {self.p2.ip}",
            "-T", "fields", 
            # "-e",  # fields specified here 
            "-e","tcp.srcport",
            "-e","tcp.dstport",
            "-e","udp.srcport",
            "-e","udp.dstport",
            "-e","_ws.col.Protocol",
            "-e","frame.time_relative",
            "-e", "frame.number",
            # maybe record packet number to analyze further later
            "-E","separator=,",
        ]
        

        result = run(command, capture_output=True, text=True)
        self.records = result.stdout.split("\n")[:-1]

        
        self.analyze_records()
        self.analyze_tcp()


    # extracts packets from the selected file and adds them to the conversation
    def analyze_records(self):
        frames = {}
        
        for record in self.records:
            if record:
                ts,td,us,up,p,t,f = record.split(",")
                
                if not p in frames.keys():
                    frames[p] = [record]
                else:
                    frames[p].append(record)

        
        for name, records in frames.items():
            for record in records:
                ts,td,us,up,p,t,f = record.split(",")

                # adding the record sorted by protocols
                if not p in self.protocols.keys():
                    self.protocols[p] = {t: record}
                    
                else:
                    self.protocols[p].update({t: record})

                if not p in self.p1.outbound.keys():
                    self.p1.outbound[p] = self.p2
                
                if not p in self.p2.inbound.keys():
                    self.p2.inbound[p] = self.p1

        self.sort_protocols()

        
    
    # returns a summary of the conversation between the two hosts
    def __str__(self):
        proto_str = ""
        
        for proto, packets in self.protocols.items():
            proto_str = f"{proto_str}\n  {proto_color}{proto}{cl} -> {num_color}{len(packets)}{cl} total packets transferred"
        
        return f"""{bc}======================================{cl}
{ip_color}{self.p1.ip}{cl} <-> {ip_color}{self.p2.ip}{cl}
--------------------------------------\n
{num_color}{len(self.records)}{cl} packets transfered between hosts\n
Protocols Used: {proto_str}
"""

    # checks if another Host belongs to this conversation
    def __eq__(self, other):
        return (other.p1 == self.p1 and other.p2 == self.p2) or (other.p1 == self.p2 and self.p1 == other.p2)







class TrafficCollector:
    def __init__(self, hosts, nics, pcap_files):
        self.lan_hosts = hosts
        self.capture_duration = 10
        self.foreign_hosts = {}
        self.conversations = []
        
        self.pcap_files = pcap_files
        self.nics = nics

        self.pids = {}


        self.records = [f"scan_cache/{r}" for r in listdir("scan_cache/") if ".pcapng" in r or ".pcap" in r] 

        self.selected_iface  = None
        self.selected_file = None
        self.object_dir = "scan_cache/objects/"


    # clears the object file where http, ftp... data can be stored
    def clean_objects(self):
        print(f"[+] Cleaning objects in {self.object_dir}")
        run(["rm", "-r", self.object_dir])
        mkdir(self.object_dir)
        

    # selects a NIC for the User to use and starts 
    # the traffic collector for the selected nic
    def choose_iface(self):
        nics = self.nics.keys()
                    
        if len(nics) == 1:
            self.selected_iface = self.nics[next(iter(nics))]
            
        else:
            choice = input(f"\nSelect a NIC:\n\t{'\n\t'.join(nics)}\n: ")
            self.selected_iface = self.nics[choice]
    
    
    # selects file to use for analysis
    def select_file(self, file_name):
        if file_name in self.records or file_name in self.pcap_files:
            self.selected_file = file_name

        else:
            raise(Exception(f"Couldnt find {file_name} in records"))


    # user chooses a file 
    def choose_file(self):

        files = self.pcap_files + self.records

        print(f"Choose file to analyze: ")

        
        for i in range(len(files)):
            print(f"  [{num_color}{i}{cl}] {files[i]}")
        

        while True:
            try:
                choice = input("\n: ").strip()

                if choice == "q":
                    return False
                    
                elif eval(choice) in range(len(files)):
                    
                
                    file = eval(choice)
                    
                    self.select_file(files[file])
                    
                else:
                    continue
                
            except Exception as Err:
                print(f"ERROR choosing file to scan:  {Err}")
                break
                
            else:
                print(f"[+] Successfully chose {self.selected_file}")
                return True

            

            
    # gets new hosts from the selected file  and put it into the output file
    def get_new_hosts(self):
        self.clean_objects()
    
        print("[+] TC getting new hosts now.")
        
        if not self.selected_file is None:

            command = ["tshark", 
                "-r", self.selected_file, 
                # "-Y",   # protocols parsed here
                "-T", "fields", 
                # "-e",  # fields specified here
                "-e","eth.src", 
                "-e","eth.dst", 
                "-e","ip.src",
                "-e","ip.dst",
                "-e","tcp.srcport",
                "-e","tcp.dstport",
                "-e","udp.srcport",
                "-e","udp.dstport",
                "-e","_ws.col.Protocol",
                # maybe record packet number to analyze further later
                "-E","separator=,",
            ]
            

            result = run(command, capture_output=True, text=True)
            
            packets = result.stdout.split("\n")

            for packet in packets[1:]:

                try:
                    e_src, e_dst, srcip, dstip, tsp, tdp, usp, udp, pr = packet.split(",")

                except ValueError:
                    continue

                except Exception as err:
                    print(err)
                    return
                    
                src_p_n = dst_p_b = None

                if tsp:
                    src_p_n, dst_p_n = tsp, tdp 
                else:
                    src_p_n, dst_p_n = usp, udp
                    
                if not srcip in self.lan_hosts.keys():
                    self.lan_hosts[srcip] = Host(srcip, e_src)

                if not dstip in self.lan_hosts.keys():
                    self.lan_hosts[dstip] = Host(dstip, e_dst)

                new_convo = Conversation(self.lan_hosts[srcip], self.lan_hosts[dstip], self.selected_file)
                inside = False
                
                for convo in self.conversations:
                    if new_convo == convo:
                        inside = True
                        
                        
                if not inside:
                    self.conversations.append(new_convo)

                    
                if not src_p_n in self.lan_hosts[srcip].ports.keys():
                    self.lan_hosts[srcip].ports[src_p_n] = Port(srcip, src_p_n, pr)   

                                     
                if not dst_p_n in self.lan_hosts[dstip].ports.keys():
                    self.lan_hosts[dstip].ports[dst_p_n] = Port(dstip, dst_p_n, pr)                


            # this gets records of each conversation and 
            
            print("[+] TC analyzing conversations now.")
            if len(self.conversations) > 0:
                threads = []
                for convo in self.conversations:
                    # print("-----------------34241324------------", convo)
                    threads.append(th.Thread(target=convo.get_records))
                

                for t in threads:
                    t.start()

                for t in threads:
                    t.join()

                for convo in self.conversations:
                     
                    for sesh in convo.sessions:
                        src_ip, sp, dst_ip, dp = sesh.initiator.ip, sesh.src_port, sesh.requestor.ip, sesh.dst_port
                
                        self.lan_hosts[src_ip].ports[sp].outbound_sessions.append(sesh)
                        self.lan_hosts[dst_ip].ports[dp].inbound_sessions.append(sesh)    
                       


    # TODO: find where used
    def get_records(self, convo):
        convo.get_records()
        return 1
                
        

    # saves collected traffic to scan_cache/
    def collect_traffic(self):
        if not self.selected_iface is None: 
            new_file = f"scan_cache/wirescan{len(self.records)}.pcap"
            print(f"[+] collecting traffic from {self.selected_iface.name} to {new_file}")
            
            
            
            # run tshark for a desired amount of time 
            # and save to a file in the scan_cache dir           
            command = ["tshark", "-i", self.selected_iface.name, "-a", f"packets:{self.capture_duration}", "-x", "-w", new_file]
            result = run(command)
            
            if not result:
                raise(Exception("Couldnt Collect Tshark Traffic"))

            else:
                if not new_file in self.records:
                    self.records.append(new_file)
                    
                self.select_file(new_file)
                
        else:
            raise(Exception("No Selected NIC"))


    # saves collected traffic to scan_cache/
    def collect_mon_traffic(self):
        if not self.selected_iface is None: 
            print(f"[+] collecting monitor traffic from {self.selected_iface.name} to {new_file}")
            
            new_file = f"scan_cache/wirescan{len(self.records)}.pcap"
            
            # run tshark for a desired amount of time 
            # and save to a file in the scan_cache dir           
            command = ["tshark", "-i", self.selected_iface.name, "-I", "-a", f"packets:{self.capture_duration}", "-x", "-w", new_file]
            result = run(command)
            
            if not result:
                raise(Exception("Couldnt Collect Tshark Traffic"))

            else:
                self.records.append(new_file)
                self.select_file(new_file)
                
        else:
            raise(Exception("No Selected NIC"))




"""
    Traffic Collector: 
    
    def collect_mon_traffic(self, new_file):    collects traffic from a wifi interface using monitor mode (detecting wifi networks)
    def collect_traffic(self):                  collects traffic from a wifi interface
    def get_records(self, task, convo):         get records from a conversation for further analysis
    def get_new_hosts(self):                    further analyzes collected traffic 
    def choose_file(self):                      selects a pcapng file to  traffic from 
    def choose_iface(self):                     selects an interface to use to collect traffic from
    def clean_objects(self):                    cleans object files in the scan_cache/objects/ directory
"""

if __name__ == "__main__":

    # create a traffic collector object with  an interface a
    tc = TrafficCollector({}, "wlp0s3")

    
    tc.get_new_hosts()

    print(tc.conversations)
 

