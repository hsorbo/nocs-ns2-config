#!/usr/bin/env python
import socket
import struct
import argparse

# TODO:
# - Wep++
# - DNS-SD discovery
# - Firmware update
# - Helpful messages

GET_SSID = b'\x03\x00' #getWirelessNetworkInfo
SET_SSID = b'\x03\x01' #setSSID / handleAPRCDevRetSetSSID
UNK1 =     b'\x03\x02' #setWirelessSecurity
UNK2 =     b'\x03\x03' #setCipher
SET_WPA =  b'\x03\x04' #setPassphrase
GET_NAME = b'\x02\x00' #getDeviceName 
SET_NAME = b"\x02\x01" #setDeviceName / handleAPRCDevRetSetDeviceNameCommand
GET_VERS = b'\x00\x04' #getFirmwareVersion 
REBOOT   = b"\x03\x07" #applyWirelessNetworkConfiguration

def checksum(data:bytes):
    cksum = 0
    for x in data:
        cksum += x
    return cksum % 0x100

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

def cmd(cmd:bytes, data:bytes = None, read:bool = True):
    send_data = cmd+data if data != None else cmd
    hdr = struct.pack(">hB",len(send_data)+1,checksum(send_data))
    s.sendall(hdr+send_data)
    if not read: return None
    response = bytearray()
    while True:
        (pkg_len, cksum) = struct.unpack(">hB",s.recv(3))
        read_data = s.recv(pkg_len-1)
        if cksum != checksum(read_data): raise("NOOO")
        if read_data[0:2] != cmd: raise("NAAAH")
        response += bytearray(read_data[2:])
        if len(read_data) < 130: break
    return bytes(response)

def config(ssid:bytes, wpa:bytes): #name:bytes, 
    cmds = [
        #(SET_NAME, name),
        (SET_SSID, ssid),
        (UNK1, b"\x03\x00\x00\x00"),
        (UNK2, b"\x01\x00\x00\x00"),
        (SET_WPA, wpa)
    ]
    for (c,data) in cmds:
        cmd(c,data)

    cmd(REBOOT, read=False)
   

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Config Nocs NS2 speakers')
    parser.add_argument('hostname', metavar='hostname', type=str, nargs=1,
                    help='host/ip of nocs speaker, on reset it will be 192.168.1.1, can be found using dns-sd -B _http._tcp')
    parser.add_argument('--get-wifi', action='store_true', help="Shows available wifis")
    parser.add_argument('--set-wpa', help="name,ssid,key")
    parser.add_argument('--get-name', action='store_true', help="Gets speaker name")
    parser.add_argument('--set-name', help="Sets speaker name (changes mdns hostname)")
    parser.add_argument('--get-version', action='store_true', help="Gets firmware version")
    args = parser.parse_args()
    
    s.connect((args.hostname[0],40001))
    if(args.get_wifi):
        print(cmd(GET_SSID).decode('utf-8'))
    if(args.get_name):
        print(cmd(GET_NAME).decode('utf-8'))
    if(args.set_name):
        cmd(SET_NAME, bytes(args.set_name, 'utf-8'))
    if(args.get_version):
        print(cmd(GET_VERS).decode('utf-8'))
    if(args.set_wpa):
        c = args.set_wpa.split(',')
        config(bytes(c[0],'utf-8'), bytes(c[1],'utf-8'))
    s.close() 
