import socket
import ssl
import json
import time
import random
from scapy.all import *
from probes.all import *
from utility import *

class Probe:
    def __init__(self, sock, server_side, vplist = None, rglist = None):
        self.sockcl = sock
        self.server_side = server_side
        self.peer_ip = formatAddress(self.sockcl.getpeername()[0])
        self.self_ip = formatAddress(self.sockcl.getsockname()[0])
        self.next_mac = None
        self.iface = []
        self.vplist = vplist
        self.rglist = rglist
        self.ssid = getSSID()
        self.plat = getPlatform()
        self.peer_ssid = ""
        self.peer_plat = ""
        self.result = { "data" : [] }

    def record(self):
        self.result["probe_time"] = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(time.time() + 8 * 3600))
        self.result["src_ip"] = self.self_ip
        self.result["src_ssid"] = self.ssid
        self.result["src_plat"] = self.plat
        self.result["dst_ip"] = self.peer_ip
        self.result["dst_ssid"] = self.peer_ssid
        self.result["dst_plat"] = self.peer_plat

    def firm(self):
        #modify scapy route table, use only nic with ip interacting
        all_set = set()
        save_set = set()
        for r in conf.route6.routes:
            for src in r[4]:
                all_set.add(r[3])
                if compareAddress(src, self.self_ip):
                    save_set.add(r[3])
        self.iface = list(save_set)
        for iff in all_set:
            if not iff in save_set:
                conf.route6.ifdel(iff)

    def start(self):
        #client side
        if self.server_side != True:
            #interact platform and prober list
            peer_env = self.sockcl.recv(256).decode('utf-8').split(",")
            self.peer_ssid = peer_env[0]
            self.peer_plat = peer_env[1]
            print("=== Probe: " + self.self_ip + "(" + self.ssid + "," + self.plat + ") to " + self.peer_ip + "(" + self.peer_ssid + "," + self.peer_plat + ") ===")
            self.record()
            sendhuge(self.sockcl, json.dumps((self.vplist, self.rglist)))

            #prepare traffic generating environment
            self.firm()
            conf.iface = self.iface[0]
            self.next_mac = observeDestMac(self.peer_ip)

            #connectivity testing
            t0 = TestNoForge(self.sockcl, self.server_side, self.self_ip, self.peer_ip, self.next_mac)
            t0.perform()
            self.result["data"].append(t0.result)
            if t0.receive_cnt <= (t0.packet_cnt // 2):
                return

            #execute traceroute
            node_addr = routeTrace(self.peer_ip, self.next_mac)
            self.sockcl.sendall((json.dumps(node_addr)).encode('utf-8'))

            #ip spoofing test
            #self subnet
            for i in self.rglist[0]:
                t1 = TestLayer3(self.sockcl, self.server_side, randomAddress(self.self_ip, i), self.peer_ip, self.next_mac)
                t1.perform()
                self.result["data"].append(t1.result)
            #peer subnet
            for i in self.rglist[1]:
                t1 = TestLayer3(self.sockcl, self.server_side, randomAddress(self.peer_ip, i), self.peer_ip, self.next_mac)
                t1.perform()
                self.result["data"].append(t1.result)
            #other prober subnet
            for addr in list(self.vplist.keys())[:self.rglist[2]]:
                if addr != self.self_ip and addr != self.peer_ip:
                    for i in self.rglist[3]:
                        t1 = TestLayer3(self.sockcl, self.server_side, randomAddress(addr, i), self.peer_ip, self.next_mac)
                        t1.perform()
                        self.result["data"].append(t1.result)
            #router subnet
            for addr in node_addr:
                if addr != self.self_ip and addr != self.peer_ip:
                    for i in self.rglist[4]:
                        t1 = TestLayer3(self.sockcl, self.server_side, randomAddress(addr, i), self.peer_ip, self.next_mac)
                        t1.perform()
                        self.result["data"].append(t1.result)
            #random
            for i in self.rglist[5]:
                t1 = TestLayer3(self.sockcl, self.server_side, randomAddress(self.self_ip, 128), self.peer_ip, self.next_mac)
                t1.perform()
                self.result["data"].append(t1.result)

            #mac spoofing test
            #real ip with spoofed mac
            org_mac = observeSorcMac(self.peer_ip)
            for i in self.rglist[6]:
                t2 = TestLayer2(self.sockcl, self.server_side, randomMac(org_mac, i), self.peer_ip, self.next_mac)
                t2.perform()
                self.result["data"].append(t2.result)
            #spoofed ip and mac
            for i in self.rglist[7]:
                for j in self.rglist[8]:
                    t3 = TestLayerMix(self.sockcl, self.server_side, randomAddress(self.self_ip, j) + "," + randomMac(org_mac, i), self.peer_ip, self.next_mac)
                    t3.perform()
                    self.result["data"].append(t3.result)
            #other prober ip and mac
            for addr in list(self.vplist.keys())[:self.rglist[2]]:
                if addr != self.self_ip:
                    t3 = TestLayerMix(self.sockcl, self.server_side, addr + "," + self.vplist[addr], self.peer_ip, self.next_mac)
                    t3.perform()
                    self.result["data"].append(t3.result)

            #infer filter node
            if len(node_addr) > 0:
                last_cnt = 6
                find_sav = False
                for addr in node_addr:
                    t4 = TestOnRouter(self.sockcl, self.server_side, addr, self.peer_ip, self.next_mac)
                    t4.perform()
                    self.result["data"].append(t4.result)
                    if t4.forge_cnt == 0 and last_cnt > 0:
                        print("(sav probably deployed here)")
                        find_sav = True
                    last_cnt = t4.forge_cnt
                if not find_sav:
                    print("(no sav found)")

        #server side
        else:
            #interact platform and prober list
            self.sockcl.sendall((self.ssid + "," + self.plat).encode('utf-8'))
            (self.vplist, self.rglist) = json.loads(recvhuge(self.sockcl))

            #prepare traffic generating environment
            self.firm()

            #connectivity testing
            t0 = TestNoForge(self.sockcl, self.server_side, iface = self.iface)
            t0.perform()
            if t0.receive_cnt <= (t0.packet_cnt // 2):
                return

            #receive traceroute result
            node_addr = json.loads(self.sockcl.recv(2048).decode('utf-8'))

            #ip spoofing test
            #self subnet
            for i in self.rglist[0]:
                t1 = TestLayer3(self.sockcl, self.server_side, iface = self.iface)
                t1.perform()
            #peer subnet
            for i in self.rglist[1]:
                t1 = TestLayer3(self.sockcl, self.server_side, iface = self.iface)
                t1.perform()
            #other prober subnet
            for addr in list(self.vplist.keys())[:self.rglist[2]]:
                if addr != self.self_ip and addr != self.peer_ip:
                    for i in self.rglist[3]:
                        t1 = TestLayer3(self.sockcl, self.server_side, iface = self.iface)
                        t1.perform()
            #router subnet
            for addr in node_addr:
                if addr != self.self_ip and addr != self.peer_ip:
                    for i in self.rglist[4]:
                        t1 = TestLayer3(self.sockcl, self.server_side, iface = self.iface)
                        t1.perform()
            #random
            for i in self.rglist[5]:
                t1 = TestLayer3(self.sockcl, self.server_side, iface = self.iface)
                t1.perform()

            #mac spoofing test
            #real ip with spoofed mac
            for i in self.rglist[6]:
                t2 = TestLayer2(self.sockcl, self.server_side, iface = self.iface)
                t2.perform()
            #spoofed ip and mac
            for i in self.rglist[7]:
                for j in self.rglist[8]:
                    t3 = TestLayerMix(self.sockcl, self.server_side, iface = self.iface)
                    t3.perform()
            #other prober ip and mac
            for addr in list(self.vplist.keys())[:self.rglist[2]]:
                if addr != self.peer_ip:
                    t3 = TestLayerMix(self.sockcl, self.server_side, iface = self.iface)
                    t3.perform()

            #infer filter node
            if len(node_addr) > 0:
                for addr in node_addr:
                    t4 = TestOnRouter(self.sockcl, self.server_side, iface = self.iface)
                    t4.perform()
