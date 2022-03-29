#!/usr/bin/env python -W ignore::DeprecationWarning
# -*- coding: utf8 -*-
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from proxymanger import *
from dns_record import *
import time
import pprint
import json
import threading
from testcase import *
import argparse
import os
import sys
from multiprocessing import Process
from Analyzer import *
import sqlite3
import requests
from pathlib import Path
from bson.objectid import ObjectId

cwd = os.path.abspath(os.path.dirname(sys.argv[0]))
database = cwd + r"/ExtensionDb.db"
mycol_network = init_database("NETWORK")
mycol_report = init_database("REPORT_FINAL")
mycol_risk = init_thesis("Risk")

def ConnectDB(db):
    conn = sqlite3.connect(db)
    return conn
def send_real_idx(idx):
    conv = {'id': idx}
    s = json.dumps(conv)
    res = requests.post("http://127.0.0.1:5001/real_id", json=s).json()
    return (res['Reponse'])
def GetListExt(db):
    conn = ConnectDB(db)
    cursor = conn.cursor()
    cursor.execute("SELECT ID,Path FROM Extensions")
    ret = cursor.fetchall()
    CloseDB(conn)
    if ret is None:
        return
    return ret

def GetExtensionHighRisk():
    high_risk_extension_id = []
    x = mycol_risk.find({"risk":"High risk"})
    for idx in x:
        high_risk_extension_id.append(idx["id"])
    return high_risk_extension_id

def CloseDB(conn):
    conn.close()

def SearchByID(id):  
    connDB = ConnectDB(database)
    c = connDB.cursor()
    stmt = "SELECT ID,Path FROM Extensions WHERE ID like '%{}%'".format(id)
    c.execute(stmt)
    result = c.fetchall()
    CloseDB(connDB)
    if not result:
        return (None, ""), ""
    else:
        return result

def AnalyzerDynamic(mycol,IDX,PathExt, mongoId = None):
    proxy = ProxyManger()
    server = proxy.start_server()
    client = proxy.start_client()
    har_options = {"captureHeaders": True,
                "captureContent": True, "captureBinaryContent": False}
    client.new_har(IDX, har_options)
    
    # Start process DNS logger 
    # Capture DNS and store it in mongodb
    p = Process(target=sniffer, args=(IDX,))
    p.start()
    time.sleep(2)
    
    # Setup option selenium browser:
    # Proxy
    # Profile 
    # Load extension   
    # 
    #profile_path = os.getenv('LOCALAPPDATA') + r"\Google\Chrome\User Data\Profile 1"     
    profile_path = r"/home/kali/.config/google-chrome/temp"
    #profile_path = r"/home/kali/Desktop/extension-analyzer/extension-info/core/analyzer/source/sandbox"
    options_chrome = webdriver.ChromeOptions()
    #unpacked_extension_path = extension_folder + "\\" + extension
    options_chrome.add_argument("--proxy-server={}".format(client.proxy))
    options_chrome.add_argument("--user-data-dir=" + profile_path)
    options_chrome.add_argument('--load-extension={}'.format(PathExt))
    options_chrome.add_argument("--start-maximized")
    options_chrome.add_argument('--ignore-ssl-errors=yes')
    options_chrome.add_argument('--ignore-certificate-errors')
    options_chrome.add_argument("--headless")
    options_chrome.add_argument("--disable-dev-shm-usage")
    options_chrome.add_argument("--no-sandbox")
    options_chrome.add_experimental_option("excludeSwitches", ["enable-automation"])
    options_chrome.add_experimental_option('useAutomationExtension', False)
    def HoneyPage():
        run = Testcase()
        run.setup_method(option=options_chrome)
        run.facebook()
        run.google()
        run.timo()
        run.extension_tab()
        run.paypal()
        run.amazon()
        run.shopee()
        run.twitter()
        run.bitdefender()
        run.norton()
        run.kaspersky()
        run.eset()
        run.teardown_method('GET')  
    HoneyPage()
    def write_network_log(mycol,IDX,client):
        network_log = cwd +"/log/" + IDX + ".har"
        #network_log = r"G:\New\Extensions\KhoaLuan\source\log" +"\\"+ IDX + ".har"       
        data_store_db = {}
        data_store_db["idx"] = IDX
        data_store_db["Path"] = network_log
        try:
            x = mycol.insert_one(data_store_db)
            print(x.inserted_id)
            json_parse = json.dumps(client, indent=4)
            open(network_log, "w").write(json_parse)
        except Exception as e:
            print(e)
            open(network_log, "w",encoding="utf-8").write(str(client))
            #pprint.pprint(client.har,network_lo`g)
    write_network_log(mycol,IDX,client.har)
    #Terminate DNS Logger process
    #Terminate Chrome browser 
    p.terminate()    
    server.stop()
    #Analyssssssssssss
    AnalyzerOnlyOneExtension(IDX, mongoId)
    return True

def checking_report(idx):
    x = mycol_report.count_documents({"id":idx})
    if(x != 0):
        return True
    return False
if __name__ == "__main__":
    #Inet database connection
    if(sys.argv[1] == "-a"): #
        for count in range(len(GetListExt(database))):            
            IDX, PathExt = GetListExt(database)[count]
            print("[+] Extension:",IDX)
            if(checking_report(IDX) == True):
                print(" |- Report exist\n")
            else:
                AnalyzerDynamic(mycol_network,IDX,PathExt)
    
    if(sys.argv[1] == "-l"):  #
        id_ext,name_ext = GetExtID(sys.argv[2])        
        if(checking_report(id_ext) == True):
            print("[+] OK - @@@%s@@@" %(id_ext))
            exit()

        IDX,PathExt = SearchByID(id_ext)[0]

        send_real_idx(IDX)        
        if(IDX is None):
            print("None")
            exit()
        else:
            AnalyzerDynamic(mycol_network,IDX,PathExt, sys.argv[4])

    if(sys.argv[1] == "-m"):  #
        print("[+]Starting...")
        high_risk_extension_id = GetExtensionHighRisk()
        for idx in high_risk_extension_id:
            IDX,PathExt = SearchByID(idx)[0]
            send_real_idx(IDX)
            print("[+] Extension:",IDX)
            if(checking_report(IDX) == True):
                print(" |- Report exist\n")
            else:
                AnalyzerDynamic(mycol_network,IDX,PathExt)
