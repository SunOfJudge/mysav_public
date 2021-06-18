import socket
import ssl
import threading
import time
import json
import configparser
from probe import *
from utility import *

class Prober:
    controllerAddress = "::1"       #controller address
    proberAddress = ""              #this prober address

    registerPort = 5677             #register port
    reportPort = 5680               #report port
    acceptPort = 25679              #accept port

    result = []                     #result of a probe
    mutex = threading.Lock()        #mutex
    counter = 0                     #standby time counter
    assigned = False                #if assigned this round

    def __init__(self):
        configer = configparser.ConfigParser()
        configer.read("config/prober.cfg")
        self.controllerAddress = configer.get("address", "controller")
        self.registerPort = int(configer.get("port", "register"))
        self.reportPort = int(configer.get("port", "report"))
        self.acceptPort = int(configer.get("port", "accept"))

    def __str__(self):
        addrstr = "controller at " + self.controllerAddress + ", self at " + self.proberAddress
        portstr = "register at %d, report at %d, accept on %d" % (self.registerPort, self.reportPort, self.acceptPort)
        return addrstr + "\n" + portstr

    #register to controller
    def register(self):
        while True:
            self.mutex.acquire()
            conf.route6.resync()
            self.mutex.release()
            currentAddress = IPv6(dst = self.controllerAddress).src
            if currentAddress == "::1":
                currentAddress = self.controllerAddress
            if currentAddress == "::":
                time.sleep(60)
                continue
            #update address and re-register when network changes
            self.counter = 0
            self.proberAddress = currentAddress
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.load_verify_locations("cert/ca.crt")
            ctx.load_cert_chain("cert/prober.crt", "cert/prober.key")
            ctx.verify_mode = ssl.CERT_REQUIRED
            sockcl = socket.socket(socket.AF_INET6, socket.SOCK_STREAM, 0)
            sockcl.settimeout(600)
            try:
                sockcl.bind((self.proberAddress, 0))
                sockcl.connect((self.controllerAddress, self.registerPort))
                sockcl = ctx.wrap_socket(sockcl, server_side = False)
                print("register succeeded")
                #connect other probers
                (vplist, rglist) = json.loads(sockcl.recv(4096).decode('utf-8'))
                threading.Thread(target = self.probe, args = (vplist, rglist,)).start()
            except Exception as e:
                print("register failed", e)
            finally:
                sockcl.close()
            time.sleep(60 * 60)

    #send result to controller
    def report(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.load_verify_locations("cert/ca.crt")
        ctx.load_cert_chain("cert/prober.crt", "cert/prober.key")
        ctx.verify_mode = ssl.CERT_REQUIRED
        sockcl = socket.socket(socket.AF_INET6, socket.SOCK_STREAM, 0)
        sockcl.settimeout(600)
        try:
            sockcl.bind((self.proberAddress, 0))
            sockcl.connect((self.controllerAddress, self.reportPort))
            sockcl = ctx.wrap_socket(sockcl, server_side = False)
            sendhuge(sockcl, json.dumps(self.result))
            print("report done")
        except Exception as e:
            print("report failed", e)
        finally:
            sockcl.close()

    #probe with other probers
    def probe(self, vplist, rglist):
        print("start a list probe")
        self.result = []
        if "::1" in vplist:
            vplist[self.controllerAddress] = vplist["::1"]
            vplist.pop("::1")
        for addr in vplist:
            if addr == self.proberAddress:
                continue
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.load_verify_locations("cert/ca.crt")
            ctx.load_cert_chain("cert/prober.crt", "cert/prober.key")
            ctx.verify_mode = ssl.CERT_REQUIRED
            sockcl = socket.socket(socket.AF_INET6, socket.SOCK_STREAM, 0)
            sockcl.settimeout(60)
            try:
                sockcl.bind((self.proberAddress, 0))
                sockcl.connect((addr, self.acceptPort))
                sockcl = ctx.wrap_socket(sockcl, server_side = False)
                print("probing " + addr)
                #start a probe
                sockcl.sendall("PROB".encode('utf-8'))
                p = Probe(sockcl, server_side = False, vplist = vplist, rglist = rglist)
                self.mutex.acquire()
                p.start()
                self.mutex.release()
                self.result.append(p.result)
            except Exception as e:
                print("probe failed with " + addr, e)
                if self.mutex.locked():
                    self.mutex.release()
            finally:
                sockcl.close()
        self.report()

    #accept connection from controller / other probers
    def accept(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_verify_locations("cert/ca.crt")
        ctx.load_cert_chain("cert/prober.crt", "cert/prober.key")
        ctx.verify_mode = ssl.CERT_REQUIRED
        socksv = socket.socket(socket.AF_INET6, socket.SOCK_STREAM, 0)
        socksv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        socksv.bind(("", self.acceptPort))
        socksv.listen(1)
        while True:
            sockcl, cli_addr = socksv.accept()
            sockcl.settimeout(60)
            try:
                try:
                    sockcl = ctx.wrap_socket(sockcl, server_side = True)
                except ssl.SSLError as e:
                    sockcl.close()
                    continue
                ctrl = sockcl.recv(4).decode('utf-8')
                #from controller
                if ctrl == "CTRL":
                    #connect other probers
                    self.assigned = True
                    (vplist, rglist) = json.loads(sockcl.recv(4096).decode('utf-8'))
                    threading.Thread(target = self.probe, args = (vplist, rglist,)).start()
                #from a prober
                elif ctrl == "PROB":
                    #accept a probe
                    addr = formatAddress(cli_addr[0])
                    print("probed by " + addr)
                    p = Probe(sockcl, server_side = True)
                    p.start()
            except:
                pass
            finally:
                sockcl.close()

    def start(self):
        threading.Thread(target = self.register).start()

if __name__ == "__main__":
    prober = Prober()
    prober.start()
