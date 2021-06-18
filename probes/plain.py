from probes.basic import *

class TestNoForge(Test):
    def __init__(self, sock, server_side, info = None, dst_ip = None, dst_mac = None, iface = None):
        Test.__init__(self, sock, server_side, info, dst_ip, dst_mac, iface)
        self.entry_name = "real ip"

    def create(self, payload):
        return (Ether(dst = self.dst_mac) / IPv6(dst = self.dst_ip) / UDP() / payload)

    def handout(self, pkt):
        sendp(pkt, verbose = False)

    def valid(self, pkt):
        return False

    def record(self):
        self.result["test_type"] = "plain"
        self.result["use_ip"] = self.info
        Test.record(self)
