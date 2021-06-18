import socket
import ssl
import time
import random
from scapy.all import *
from utility import *

class Test:
    def __init__(self, sock, server_side, info = None, dst_ip = None, dst_mac = None, iface = None):
        self.sockcl = sock
        self.server_side = server_side
        self.entry_name = ""
        self.info = info
        self.dst_ip = dst_ip
        self.dst_mac = dst_mac
        self.iface = iface
        self.result = {}

        self.magic_num = 0
        self.packet_cnt = 6
        self.receive_cnt = 0
        self.forge_cnt = 0
        self.guard_pass = False

    def create(self, payload):
        return (IPv6())

    def handout(self, pkt):
        send(pkt, verbose = False)

    def valid(self, pkt):
        return True

    def send(self):
        payload = [0] * 20
        payload[8] = ((self.magic_num >> 24) & 0xFF)
        payload[9] = ((self.magic_num >> 16) & 0xFF)
        payload[10] = ((self.magic_num >> 8) & 0xFF)
        payload[11] = (self.magic_num & 0xFF)
        payload = bytes(payload)
        packet = self.create(payload)
        for i in range(self.packet_cnt):
            if i >= (self.packet_cnt // 2) and UDP in packet:
                packet.dport = 20000 + random.randint(0, 9999)
            self.handout(packet)
            print("sent: " + str(i + 1))
            time.sleep(0.1)
        payload = bytearray(payload)
        payload[7] = 0xFF
        payload = bytes(payload)
        packet = Ether(dst = self.dst_mac) / IPv6(dst = self.dst_ip) / UDP() / payload
        sendp(packet, verbose = False)
        print("sent guard packet")

    def receive(self):
        sniff(iface = self.iface, lfilter = self.check, stop_filter = self.count, timeout = (self.packet_cnt // 4 + 1))

    def check(self, pkt):
        if len(pkt) != 82:
            return False
        bpkt = bytes(pkt)
        if (bpkt[70] << 24) + (bpkt[71] << 16) + (bpkt[72] << 8) + bpkt[73] != self.magic_num:
            return False
        return True

    def count(self, pkt):
        if bytes(pkt)[69] == 0xFF:
            self.guard_pass = True
            print("received guard packet")
        else:
            self.receive_cnt += 1
            if self.valid(pkt):
                self.forge_cnt += 1
            print("received: " + str(self.receive_cnt) + "\t" + "forged: " + str(self.forge_cnt))
        if self.receive_cnt >= self.packet_cnt and self.guard_pass == True:
            return True
        return False

    def record(self):
        self.result["send_num"] = self.packet_cnt
        self.result["receive_num"] = self.receive_cnt
        self.result["forge_num"] = self.forge_cnt
        self.result["connect_pass"] = self.guard_pass

    def perform(self):
        #client side
        if self.server_side != True:
            #send spoofer info
            self.sockcl.sendall(self.info.encode('utf-8'))
            print("- " + self.entry_name + ": " + self.info + " -")
            #receive magic number
            self.magic_num = int(self.sockcl.recv(256))
            #batch send spoofer packets
            time.sleep(0.1)
            self.send()
            #receive summary
            summary = self.sockcl.recv(256).decode('utf-8')
            data = summary.split(",")
            self.receive_cnt = int(data[0])
            self.forge_cnt = int(data[1])
            self.guard_pass = bool(int(data[2]))
            print("expected: " + str(self.packet_cnt) + "\t" + "received: " + str(self.receive_cnt) + "\t" + "forged: " + str(self.forge_cnt) + "\t" + "guard packet passed: " + str(self.guard_pass))
            self.record()
        #server side
        else:
            #receive spoofer info
            self.info = self.sockcl.recv(256).decode('utf-8')
            print("- " + self.entry_name + ": " + self.info + " -")
            #send magic number
            self.magic_num = int(RandInt())
            self.sockcl.sendall(str(self.magic_num).encode('utf-8'))
            #batch receive spoofer packets
            self.receive()
            #send summary
            summary = str(self.receive_cnt) + "," + str(self.forge_cnt) + "," + str(int(self.guard_pass))
            self.sockcl.sendall(summary.encode('utf-8'))
            print("expected: " + str(self.packet_cnt) + "\t" + "received: " + str(self.receive_cnt) + "\t" + "forged: " + str(self.forge_cnt) + "\t" + "guard packet passed: " + str(self.guard_pass))
