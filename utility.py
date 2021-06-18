import socket
import platform as sysplat
import random
import os
import re
import time
from scapy.all import *

def formatAddress(addr):
    """
    * @brief convert an address string to a unified format
    * @param addr, the address string
    * @return str, the formatted address string
    """
    return socket.inet_ntop(socket.AF_INET6, socket.inet_pton(socket.AF_INET6, addr))

def compareAddress(addr_a, addr_b):
    """
    * @brief check whether two address strings are the same
    * @param addr_a, one address string
    * @param addr_b, the other address string
    * @return bool, True for same and False for not same
    """
    return (socket.inet_pton(socket.AF_INET6, addr_a) == socket.inet_pton(socket.AF_INET6, addr_b))

def getSSID():
    """
    * @brief get the ssid which is currently connected
    * @return str, the ssid, "Other" for no ssid
    """
    try:
        import pywifi
        wifi = pywifi.PyWiFi()
        for ifa in wifi.interfaces():
            for profile in ifa.network_profiles():
                if profile.ssid == "MAGAIN":
                    continue
                return profile.ssid
    except:
        try:
            info = os.popen("/System/Library/PrivateFrameworks/Apple80211.framework/Resources/airport -I")
            profile = info.read()
            info.close()
            return re.search("\sSSID:\s(.*)", profile)[1]
        except:
            pass
    return "Other"

def getPlatform():
    """
    * @brief get the type and version of operating system
    * @return str, the operating system information
    """
    return sysplat.system() + "-" + sysplat.release()

def randomMac(addr, scope):
    """
    * @brief generate a random mac from given
    * @param addr, given mac string
    * @param scope, random count of last bits (ranges [0, 48])
    * @return str, the new mac string
    """
    if scope == 0:
        return addr
    bin_addr = "".join(bin(i)[2:].zfill(8) for i in mac2str(addr))
    new_bin_addr = bin_addr[:-scope] + "".join(str(random.randint(0, 1)) for i in range(scope))
    new_bin_addr = new_bin_addr[:7] + "0" + new_bin_addr[8:]
    if new_bin_addr == bin_addr:
        index = -random.randint(1, scope)
        new_bin_addr = new_bin_addr[:index] + str(1 - int(new_bin_addr[index])) + new_bin_addr[(index + 1):]
    newaddr = str2mac(bytes([int(new_bin_addr[i * 8:(i + 1) * 8], 2) for i in range(6)]))
    return newaddr

def randomAddress(addr, scope):
    """
    * @brief generate a random address from given
    * @param addr, given address string
    * @param scope, random count of last bits (ranges [0, 128])
    * @return str, the new address string
    """
    if scope == 0:
        return addr
    bin_addr = "".join(bin(i)[2:].zfill(8) for i in socket.inet_pton(socket.AF_INET6, addr))
    new_bin_addr = bin_addr[:-scope] + "".join(str(random.randint(0, 1)) for i in range(scope))
    if new_bin_addr == bin_addr:
        index = -random.randint(1, scope)
        new_bin_addr = new_bin_addr[:index] + str(1 - int(new_bin_addr[index])) + new_bin_addr[(index + 1):]
    newaddr = socket.inet_ntop(socket.AF_INET6, bytes([int(new_bin_addr[i * 8:(i + 1) * 8], 2) for i in range(16)]))
    return newaddr

def routeTrace(dst_ip, dst_mac):
    """
    * @brief collect route information to an address
    * @param dst_ip, the destination address string
    * @param dst_mac, the next hop mac address string
    * @return array, address of nodes on route
    """
    res = []
    for hlim in range(1, 30):
        ans, unans = srp(Ether(dst = dst_mac) / IPv6(dst = dst_ip, hlim = hlim) / ICMPv6EchoRequest(), retry = -2, timeout = 2, verbose = False)
        for s, r in ans:
            src_ip = r[IPv6].src
            res.append(src_ip)
            if src_ip == dst_ip:
                return res
        if len(res) == 0 and hlim > 3:
            break
    return res

def observeSorcMac(dst_ip):
    """
    * @brief find out mac address of the device
    * @param dst_ip, the destination address string
    * @return str, the device mac address string
    """
    return (Ether() / IPv6(dst = dst_ip))[Ether].src

def observeDestMac(dst_ip):
    """
    * @brief find out mac address of next hop
    * @param dst_ip, the destination address string
    * @return str, the next hop mac address string
    """
    try:
        sniffer = AsyncSniffer(filter = "dst host " + dst_ip, count = 1)
        sniffer.start()
        pingger = os.popen("ping " + dst_ip)
        time.sleep(3)
        pingger.close()
        if sniffer.running:
            sniffer.stop()
        result = sniffer.results.res[0][Ether].dst
    except:
        result = None
    return result

def sendhuge(sock, message, length = 1024):
    """
    * @brief send huge message with socket
    * @param sock, the socket used
    * @param message, the message string to send
    * @param length, size of message sent per time (default 1024)
    """
    ptr = 0
    endding = len(message)
    while ptr < endding:
        sock.sendall((message[ptr : ptr + length]).encode('utf-8'))
        ptr = ptr + length
        ack = sock.recv(4)
    sock.sendall(b'afin')

def recvhuge(sock, length = 1024):
    """
    * @brief receive huge message with socket
    * @param sock, the socket used
    * @param length, size of message received per time (default 1024)
    * @return str, the message string received
    """
    result = ""
    while True:
        buffer = sock.recv(length)
        if buffer == b'afin':
            break
        sock.sendall(b'aack')
        result += buffer.decode('utf-8')
    return result
