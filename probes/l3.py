from probes.basic import *

class TestLayer3(Test):
    def __init__(self, sock, server_side, info = None, dst_ip = None, dst_mac = None, iface = None):
        Test.__init__(self, sock, server_side, info, dst_ip, dst_mac, iface)
        self.entry_name = "spoofed ip"

    def create(self, payload):
        return (Ether(dst = self.dst_mac) / IPv6(src = self.info, dst = self.dst_ip) / UDP() / payload)

    def handout(self, pkt):
        sendp(pkt, verbose = False)

    def valid(self, pkt):
        return compareAddress(pkt[IPv6].src, self.info)

    def record(self):
        self.result["test_type"] = "ip"
        self.result["use_ip"] = self.info
        Test.record(self)
