from probes.basic import *

class TestLayer2(Test):
    def __init__(self, sock, server_side, info = None, dst_ip = None, dst_mac = None, iface = None):
        Test.__init__(self, sock, server_side, info, dst_ip, dst_mac, iface)
        self.entry_name = "spoofed mac"

    def create(self, payload):
        return (Ether(src = self.info, dst = self.dst_mac) / IPv6(dst = self.dst_ip) / UDP() / payload)

    def handout(self, pkt):
        sendp(pkt, verbose = False)

    def valid(self, pkt):
        return True

    def record(self):
        self.result["test_type"] = "mac"
        self.result["use_mac"] = self.info
        Test.record(self)
