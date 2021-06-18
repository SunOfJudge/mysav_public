from probes.basic import *

class TestLayerMix(Test):
    def __init__(self, sock, server_side, info = None, dst_ip = None, dst_mac = None, iface = None):
        Test.__init__(self, sock, server_side, info, dst_ip, dst_mac, iface)
        self.entry_name = "spoofed ip,mac"

    def create(self, payload):
        src_ip = self.info.split(",")[0]
        src_mac = self.info.split(",")[1]
        return (Ether(src = src_mac, dst = self.dst_mac) / IPv6(src = src_ip, dst = self.dst_ip) / UDP() / payload)

    def handout(self, pkt):
        sendp(pkt, verbose = False)

    def valid(self, pkt):
        src_ip = self.info.split(",")[0]
        return compareAddress(pkt[IPv6].src, src_ip)

    def record(self):
        self.result["test_type"] = "mix"
        self.result["use_ip"] = self.info.split(",")[0]
        self.result["use_mac"] = self.info.split(",")[1]
        Test.record(self)
