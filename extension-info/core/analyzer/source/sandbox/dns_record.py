#!/usr/bin/env python
# -*- coding: utf8 -*-

from scapy.all import *
import pymongo
import simplejson as json
from datetime import datetime
import os
import sys
import time, threading
from functools import partial
import socket   
from collections import defaultdict

cwd = os.path.abspath(os.path.dirname(sys.argv[0]))
log_dns_path = cwd +r"/log/log_dns.txt"
file_log = open(log_dns_path, "a+")

hostname = socket.gethostname()    
IPAddr = socket.gethostbyname(hostname)  

# disable verbose mode
conf.verb = 0

collection_default = {
    "idx":"default",
    "request": {
        "source_ip": "",
        "source_port": 0,
        "dest_ip": "",
        "dest_port": 0,
        "qname": ""
    },
    "time": 0,
    "transaction": 0
}

logger_dns = {}
count = 0

def init_database(collection):
    myclient = pymongo.MongoClient("mongodb://localhost:27017/")
    mydb = myclient["ChromeExtension"]
    mycol = mydb[collection]
    return mycol

def insert_request(idx,count, timestamp, source_ip, source_port, dest_ip, dest_port, qname, transaction):
    collection = collection_default.copy()
    collection["idx"] = idx
    collection["count"] = count
    collection["time"] = timestamp
    collection["transaction"] = transaction
    collection["request"]["source_ip"] = source_ip
    collection["request"]["source_port"] = source_port
    collection["request"]["dest_ip"] = dest_ip
    collection["request"]["dest_port"] = dest_port
    collection["request"]["qname"] = qname.decode("ascii")
    return collection

def insert_db(mycol, data):
    try:
        x = mycol.insert_one(data)
        print(x.inserted_id)
    except Exception as e:
        file_log.write(str(e)+"\n")
        file_log.write(str(logger_dns)+"\n")
        print("==>" + str(e))

mycol = init_database("DNS")
count = 0
def parse_dnspkt(idx,pkt):
    """ parse dns request / response packet """
    if pkt and pkt.haslayer('UDP') and pkt.haslayer('DNS'):
        ip = pkt['IP']
        udp = pkt['UDP']
        dns = pkt['DNS']
        # dns query packet
        if (int(udp.dport) == 53 and ip.src == IPAddr):
            print("[+] Request Called!")
            global count
            count = count + 1
            now = datetime.now()
            timestamp = datetime.timestamp(now)
            collection_request = {}
            collection_request = insert_request(
                idx,count, timestamp, ip.src, udp.sport, ip.dst, udp.dport, dns.qd.qname, dns.id)
            insert_db(mycol, collection_request)
        # dns reply packet
        elif (int(udp.sport) == 53 and ip.dst == IPAddr):
            #print("[+] Response Called!")
            # dns DNSRR count (answer count)
            request_info = mycol.find_one({"transaction": dns.id,"request.dest_ip":ip.src})
            if(request_info is not None):
                res_default = {
                    "source_ip": "0",
                    "source_port": 0,
                    "dest_ip": "0",
                    "dest_port": 0,
                    "resolver": {
                        "domain": "",
                        "CNAME": [],
                        "IP": []
                    }
                }
                res = dict(res_default)
                id_collection = request_info["_id"]
                res["source_ip"] = ip.src
                res["source_port"] = udp.sport
                res["dest_ip"] = ip.dst
                res["dest_port"] = udp.dport
                for i in range(dns.ancount):
                    dnsrr = dns.an[i]
                    rrname = dnsrr.rrname.decode("ascii")
                    if(i == 0):
                        res["resolver"]["domain"] = rrname[:-1]
                    rdata = dnsrr.rdata
                    if(type(rdata) is bytes):
                        rdata = rdata.decode("ascii")
                        res["resolver"]["CNAME"].append(str(rdata)[:-1])
                    else:
                        res["resolver"]["IP"].append(str(rdata))
                try:
                    x = mycol.update_one({"_id":id_collection},{"$set":{"response":res}})
                    #print(x.modified_count)
                except Exception as e:
                    file_log.write(str(e)+"\n")
                    print("==>" + str(e))
            else:
                print("[-] Not have request but have response")
            # print(logger_dns)
#return parse_dnspkt

def sniffer(idx):
    #os.system("ipconfig /flushdns")
    sniff(filter="udp port 53", prn=partial(parse_dnspkt,idx))
    
