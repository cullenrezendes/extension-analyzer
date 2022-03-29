 #!/usr/bin/env python -W ignore::DeprecationWarning

import pymongo
import json
from collections import Counter 
from operator import itemgetter
import os	
import sys	
from bson.objectid import ObjectId
import pdb

cwd = os.path.abspath(os.path.dirname(sys.argv[0]))	
api_file = cwd +r"\api.json"	
path_white_list_dns = cwd + r"/white_list_dns.json"

white_list_testcase =["facebook","fb","google","timo","paypal","amazon","shopee","twitter","bitdefender","norton","kaspersky","eset","myvisualiq","eservice","beacons"]

def init_thesis(collection):
    myclient = pymongo.MongoClient("mongodb://localhost:27017/")
    mydb = myclient["Thesis"]
    mycol = mydb[collection]
    return mycol

def init_database(collection):
    myclient = pymongo.MongoClient("mongodb://localhost:27017/")
    mydb = myclient["ChromeExtension"]
    mycol = mydb[collection]
    return mycol

mycol = init_database("API")

# get behavior form file api.json define
# Return json behavior 
def GetBehaviorMalicious(behavior):
    with open(api_file) as f:	
        _behavior = json.load(f)
    return _behavior[behavior]

def GetApiCalledByExtension(idx):
    list_api_from_database = mycol.find({"extensionId": idx})
    return list_api_from_database

def GetExtID(arg):	
    if arg.startswith('http://'):	
        arg = arg.replace('http://', 'https://')   #http -> https	
    if arg.startswith('https://'):	
        return (arg.split('/')[-1]).split('?')[0], arg.split("/")[-2]   #split ID, and extension name from link	

def UninstallBehaviorTracking(api_of_extension):
    _behavior_info = GetBehaviorMalicious("uninstall_other_extension")
    for api_of_behavior in (_behavior_info):
        if "behavior" in api_of_behavior:
            list_api_behavior = api_of_behavior["behavior"]
    
    #Checking 
    if(api_of_extension in list_api_behavior):
        return True
    return False

def PreventsUninstallTracking(api_of_extension):
    _behavior_info = GetBehaviorMalicious("prevents_extension_uninstall")
    for api_of_behavior in (_behavior_info):
        if "behavior" in api_of_behavior:
            list_api_behavior = api_of_behavior["behavior"]

    list_name_api_of_behavior = []
    for api_behavior in list_api_behavior:
        list_name_api_of_behavior.append(api_behavior["apiCall"])

    if(api_of_extension["apiCall"] in list_name_api_of_behavior): 
        if("argUrl" in api_of_extension.keys() and api_of_extension["argUrl"] in "chrome://extensions/"):
            return True
    return False

def KeyloggerTracking(api_of_extension):
    # Kiem tra apiCall co nam trong danh sach api hanh vi cua keylloging hay khong, cu the la:blinkAddEventListener
    # Neu có api blinkAddEventListener thi kiem tra args duoc truyen vao
    # args [ "#document", "keypress"] hoac "args": [ "#document", "keydown" ] thi return True 
    # -> Extension chua hanh vi cua keylogger
    _behavior_info = GetBehaviorMalicious("keylogging_functionality")
    for api_of_behavior in (_behavior_info):
        if "behavior" in api_of_behavior:
            list_api_behavior = api_of_behavior["behavior"]
 
    list_name_api_of_behavior = []
    list_args = []
    for api_behavior in list_api_behavior:
        if(api_behavior["apiCall"] != "" and api_behavior["apiCall"] not in list_name_api_of_behavior):
            list_name_api_of_behavior.append(api_behavior["apiCall"])
        list_args.append(api_behavior["args"])
    
    
    if(api_of_extension["apiCall"] in list_name_api_of_behavior): 
        if(json.loads(api_of_extension["args"]) in list_args):
            return True
    return False

def StealInformationFormTracking(api_of_extension):
    # Kiem tra blinkAddEventListener api co gia tri args ["FORM","submit"]
    # Neu co thi lay pageUrl 
    # Kiem tra pageUrl co activityType la content_script
    # Neu co thi extension da inject script vao page de get form thong tin
    # Den day kiem tra xem pageUrl co api blinkAddEventListener voi tham so ["XMLHttpRequest","load"]
    # Neu co kha nang cao se gui thong tin dang nhap ra ngoai
    args_checking_https = ["https://","http://"]
    _behavior_info = GetBehaviorMalicious("steal_information_form")
    for api_of_behavior in (_behavior_info):
        if "behavior" in api_of_behavior:
            list_api_behavior = api_of_behavior["behavior"]
    
    list_name_api_of_behavior = []
    list_args = []
    list_activityType = []
    for api_behavior in list_api_behavior:
        # Kiem tra api trong list_name_api_of_behavior hay khong chua, khong add cac api null
        # Neu chua co thi them vao list
        if(api_behavior["apiCall"] != "" and api_behavior["apiCall"] not in list_name_api_of_behavior):
            list_name_api_of_behavior.append(api_behavior["apiCall"])
        list_args.append(api_behavior["args"])
        if("activityType" in api_behavior):
            list_activityType.append(api_behavior["activityType"])

    #Kiem tra cac behavior
    if(api_of_extension["apiCall"] in list_name_api_of_behavior): 
        if(api_of_extension["args"] in "[\"FORM\",\"submit\"]"):
            find_activity = mycol.find({"extensionId": api_of_extension["extensionId"],"pageUrl":api_of_extension["pageUrl"],"activityType":"content_script"})
            for obj in find_activity:
                for argv in json.loads(obj["args"]):
                    matches = [x for x in args_checking_https if x in argv]
                    if(len(matches)!=0):
                        matches2 =  [x for x in white_list_testcase if x in argv]
                        if(len(matches2)==0):
                            return True
                    else:
                            continue           
    return False

def BlockAntiVirusSiteTracking(api_of_extension):
    # Kiem tra api co phai Apicall co phai la webRequestInternal.addEventListener
    # Neu la api do thi kiem tra args
    # Args chua hanh dong blocking thi kieu tra tham so domain
    # Neu tham domain co chua cac domain antivius thi return True

    _behavior_info = GetBehaviorMalicious("block_antivirus_site")
    for api_of_behavior in (_behavior_info):
        if "behavior" in api_of_behavior:
            list_api_behavior = api_of_behavior["behavior"]
    
    list_name_api_of_behavior = []
    list_args = []
    for api_behavior in list_api_behavior:
        # Kiem tra api trong list_name_api_of_behavior hay khong chua, khong add cac api null
        # Neu chua co thi them vao list
        if(api_behavior["apiCall"] != "" and api_behavior["apiCall"] not in list_name_api_of_behavior):
            list_name_api_of_behavior.append(api_behavior["apiCall"])
        list_args = (api_behavior["args"])
 
    #Kiem tra behavior
   # matches = [x for x in white_list_testcase if x in i["request"]["url"]]
    if(api_of_extension["apiCall"] in list_name_api_of_behavior):
        
        if("webRequest" in api_of_extension["other"]):
            cancel_stt = json.loads(api_of_extension["other"]["webRequest"])
            if("cancel" in cancel_stt):
                matches = [x for x in list_args if x in api_of_extension["pageUrl"]]
                if(cancel_stt["cancel"] == True and len(matches) != 0 ):
                    return True
        #if(list_args in api_of_extension["apiCall"] ) :
        #    print(api_of_extension)        
    return False

def DeleteReponseHeaderTracking(api_of_extension):
    # Kiem tra activityType co phai web_request hay khong
    # Neu phai thi chuyen sang kiem tra apiCall co phai la webRequest.onHeadersReceived
    # Kiem tra thuoc tinh other co chua webRequest["deleted_response_headers"]
    # Kiem tra webRequest["deleted_response_headers"] co chua cac gia tri header bao mat hay khong
    
    _behavior_info = GetBehaviorMalicious("deleted_response_headers")
    for api_of_behavior in (_behavior_info):
        if "behavior" in api_of_behavior:
            list_api_behavior = api_of_behavior["behavior"]
    
    list_name_api_of_behavior = []
    
    for api_behavior in list_api_behavior:
        # Kiem tra api trong list_name_api_of_behavior hay khong chua, khong add cac api null
        # Neu chua co thi them vao list
        if(api_behavior["apiCall"] != "" and api_behavior["apiCall"] not in list_name_api_of_behavior):
            list_name_api_of_behavior.append(api_behavior["apiCall"])
    
    # Checking
    if((api_of_extension["apiCall"] in list_name_api_of_behavior)):
        if("webRequest" in api_of_extension["other"]):
            if("deleted_response_headers" in api_of_extension["other"]["webRequest"]):
                return True
    return False

def InjectsDynamicJsTracking(api_of_extension):
    _behavior_info = GetBehaviorMalicious("injects_dynamic_javascript")
    for api_of_behavior in (_behavior_info):
        if "behavior" in api_of_behavior:
            list_api_behavior = api_of_behavior["behavior"]

    list_name_api_of_behavior = []
    list_args = []
    for api_behavior in list_api_behavior:
        # Kiem tra api trong list_name_api_of_behavior hay khong chua, khong add cac api null
        # Neu chua co thi them vao list
        if(api_behavior["apiCall"] != "" and api_behavior["apiCall"] not in list_name_api_of_behavior):
            list_name_api_of_behavior.append(api_behavior["apiCall"])
        list_args = (api_behavior["args"])
   
    #Tracking APi
    if((api_of_extension["apiCall"] in list_name_api_of_behavior)):
        for args_in_apicall in  json.loads(api_of_extension["args"]):
            matches = [x for x in list_args if x in args_in_apicall]                
            if(len(matches)!=0):
                matches2 =  [x for x in white_list_testcase if x in args_in_apicall]
                if(len(matches2)==0):
                    return True
                else:
                    continue 
    return False

def GetAllCookiesTracking(api_of_extension):
    _behavior_info = GetBehaviorMalicious("get_all_cookies")
    for api_of_behavior in (_behavior_info):
        if "behavior" in api_of_behavior:
            list_api_behavior = api_of_behavior["behavior"]

    list_name_api_of_behavior = []
    for api_behavior in list_api_behavior:
        # Kiem tra api trong list_name_api_of_behavior hay khong chua, khong add cac api null
        # Neu chua co thi them vao list
        if(api_behavior["apiCall"] != "" and api_behavior["apiCall"] not in list_name_api_of_behavior):
            list_name_api_of_behavior.append(api_behavior["apiCall"])

    #Tracking APi
    if((api_of_extension["apiCall"] in list_name_api_of_behavior)):
        return True
    return False

white_list_http = ["https://fbsbx.com/ajax/bz","https://www.paypal.com/signin/client-log","https://www.amazon.com/gp/recent-history-footer/external/rhf-handler.html","https://www.paypal.com/auth/verifychallenge"]
def NetworkRequest4xxTracking(idx):
    http_request_4xx = []
    try:
        mycol = init_database("NETWORK")
        my_network = mycol.find({"idx":idx})
        for info in my_network:
            path_file_network = info["Path"]
            with open(path_file_network, 'r') as f:
                entry = json.load(f)
            entries = entry["log"]["entries"]
            for i in entries:
                if(i["response"]["status"] >= 400 and i["response"]["status"] < 500):
                    matches = [x for x in white_list_testcase if x in i["request"]["url"]]
                    if(len(matches)!=0):
                        continue
                    if(i["request"]["url"] not in white_list_http):
                        http_request_4xx.append({i["request"]["url"]:i["response"]["status"]})
    except Exception as E:
        print("NETWORK:",idx)
    return http_request_4xx

def DnsResponseTracking(idx):
    dns_domain_whitelist = []
    with open(path_white_list_dns, 'r') as f:
        entry = json.load(f)
    dns_domain_whitelist = entry["domain"]

    dns_no_response = []
    mycol = init_database("DNS")
    list_dns_of_idx = mycol.find({"idx":idx})
    for dns_record in list_dns_of_idx:
        if(dns_record["request"]["qname"][:-1] in dns_domain_whitelist):
            continue
        matches = [x for x in white_list_testcase if x in dns_record["request"]["qname"][:-1]]
        if(len(matches)!=0):
           continue
        if("response" not in dns_record):
            dns_no_response.append(dns_record)
    return dns_no_response  

def AnalyzerOnlyOneExtension(idx, mongoId = None):
    total_call = 0
    count_api = {}
    api_called = []
    # Get api called of chrome extension from mongodb with id
    # Count total api called
    # Save element of info to report

    list_api_from_database = GetApiCalledByExtension(idx)
    for api_call in list_api_from_database:
        api_called.append(api_call)
        total_call += 1
        if(api_call["apiCall"] in count_api.keys()):
            count_api[api_call["apiCall"]] += 1
        else:
            count_api[api_call["apiCall"]] = 1
    beauty_report = {"id": idx, "total_api": total_call, "apis": count_api,"api_called":api_called}
    print("==========================================")
    list_api = GetApiCalledByExtension(idx)
    uninstall_other_extension=[]
    prevents_extension_uninstall=[]
    keylogging_functionality=[]
    steal_information_form=[]
    block_antivirus_site=[]
    deleted_response_headers=[]
    injects_dynamic_javascript=[]
    get_all_cookies=[]
    http_request_4xx = []
    dns_no_response = []
    is_malicious = False
    is_suspicious = False
    for api in list_api:
        if (UninstallBehaviorTracking(api)):
            uninstall_other_extension.append(api)
            is_malicious = True
            continue
        # detect PreventsUninstallTracking
        
        if(PreventsUninstallTracking(api)):
            prevents_extension_uninstall.append(api)
            is_malicious = True
            continue
        if(KeyloggerTracking(api)):
            keylogging_functionality.append(api)
            is_malicious = True
            continue
        if(StealInformationFormTracking(api)):
            all_info_behavior = []
            all_info_behavior.append(api)
            find_activity = mycol.find({"extensionId": api["extensionId"],"pageUrl":api["pageUrl"],"activityType":"content_script"})
            for api_content_script in find_activity:
                all_info_behavior.append(api_content_script)
            steal_information_form.append(all_info_behavior)
            is_malicious = True
            continue
        if(BlockAntiVirusSiteTracking(api)):
            block_antivirus_site.append(api)
            is_malicious = True
            continue
        if(DeleteReponseHeaderTracking(api)):
            deleted_response_headers.append(api)
            is_malicious = True
            continue
        if(InjectsDynamicJsTracking(api)):
            injects_dynamic_javascript.append(api)
            if(is_malicious == False):
                is_suspicious = True
            continue
        if(GetAllCookiesTracking(api)):
            get_all_cookies.append(api)
            if(is_malicious == False):
                is_suspicious = True
            continue
        
    http_request_4xx = NetworkRequest4xxTracking(idx)
    if (len(http_request_4xx) != 0):
        if(is_malicious == False):
            is_suspicious = True
    dns_no_response = DnsResponseTracking(idx)
    beauty_report["uninstall_other_extension"] = uninstall_other_extension
    beauty_report["prevents_extension_uninstall"] = prevents_extension_uninstall
    beauty_report["keylogging_functionality"] = keylogging_functionality
    beauty_report["steal_information_form"] = steal_information_form
    beauty_report["block_antivirus_site"] = block_antivirus_site
    beauty_report["deleted_response_headers"] = deleted_response_headers
    beauty_report["injects_dynamic_javascript"] = injects_dynamic_javascript
    beauty_report["get_all_cookies"] = get_all_cookies
    beauty_report["http_request_4xx"] = http_request_4xx
    beauty_report["dns_no_response"] = dns_no_response
    beauty_report["status"] = True
    if (is_malicious == True):
        beauty_report['final_result'] = "Malicious"
    elif (is_suspicious == True):
        beauty_report['final_result'] = "Suspicious"
    else:
        beauty_report['final_result'] = "Clean"

    col = init_database("REPORT_FINAL")
    col.replace_one({ '_id': ObjectId(mongoId) }, beauty_report, upsert=True)
    print("[+] Inserted: @@@%s@@@"%(idx))
    
def AnalyzerAllExtension():
# Doc tung report trong Database "REPORT" bang mycol.find
    malicious = 0
    suspicious = 0
    clean = 0
    top_10_extension_malicious = [] 
    top_10_api_called = {}
    info = {}
    uninstall_other_extension= 0
    prevents_extension_uninstall=0
    keylogging_functionality=0
    steal_information_form=0
    block_antivirus_site=0
    deleted_response_headers=0
    injects_dynamic_javascript=0
    get_all_cookies=0
    http_request_4xx = 0

    _list_uninstall_other_extension= []
    _list_prevents_extension_uninstall=[]
    _list_keylogging_functionality=[]
    _list_steal_information_form=[]
    _list_block_antivirus_site=[]
    _list_deleted_response_headers=[]
    _list_injects_dynamic_javascript=[]
    _list_get_all_cookies=[]
    _list_http_request_4xx = []

    dns_no_response = 0
    mycol = init_database("REPORT_FINAL")
    total = mycol.estimated_document_count()
    print("[+] Total %d reports"%(total))
    for ext in mycol.find():       
        is_malicious = False
        is_suspicious = False
        count_m = 0 
        count_s = 0
        behavior = []
        if(len(ext["uninstall_other_extension"]) != 0):
            count_m += 1
            uninstall_other_extension +=1
            _list_uninstall_other_extension.append(ext["id"])
            behavior.append("uninstall_other_extension")
            is_malicious = True

        if(len(ext["prevents_extension_uninstall"]) != 0):
            count_m += 1
            prevents_extension_uninstall +=1
            _list_prevents_extension_uninstall.append(ext["id"])
            behavior.append("prevents_extension_uninstall")
            is_malicious = True

        if(len(ext["keylogging_functionality"]) != 0):
            count_m += 1
            keylogging_functionality +=1
            _list_keylogging_functionality.append(ext["id"])
            behavior.append("keylogging_functionality")
            is_malicious = True

        if(len(ext["steal_information_form"]) != 0):
            count_m += 1
            steal_information_form +=1
            _list_steal_information_form.append(ext["id"])
            behavior.append("steal_information_form")
            is_malicious = True

        if(len(ext["block_antivirus_site"]) != 0):
            count_m += 1
            block_antivirus_site +=1
            _list_block_antivirus_site.append(ext["id"])
            behavior.append("block_antivirus_site")
            is_malicious = True

        if(len(ext["deleted_response_headers"]) != 0):
            count_m += 1
            deleted_response_headers +=1
            _list_deleted_response_headers.append(ext["id"])
            behavior.append("deleted_response_headers")
            is_malicious = True

        if(len(ext["injects_dynamic_javascript"]) != 0):
            count_s += 1
            injects_dynamic_javascript +=1
            _list_injects_dynamic_javascript.append(ext["id"])
            behavior.append("injects_dynamic_javascript")
            if(is_malicious == False):
                is_suspicious = True

        if(len(ext["get_all_cookies"]) != 0):
            count_s += 1
            get_all_cookies +=1
            _list_get_all_cookies.append(ext["id"])
            behavior.append("get_all_cookies")
            if(is_malicious == False):
                is_suspicious = True

        if(len(ext["http_request_4xx"]) != 0):
            count_s += 1
            http_request_4xx +=1
            _list_http_request_4xx.append(ext["id"])
            behavior.append("http_request_4xx")
            if(is_malicious == False):
                is_suspicious = True

        if(len(ext["dns_no_response"]) != 0):
            #count += 1
            dns_no_response +=1
            #behavior.append("dns_no_response")


        if(is_malicious):
            malicious +=1
        elif(is_suspicious):
            suspicious +=1
        else:
            clean +=1

        count_all = count_m + count_s
        info["id"] = ext["id"]
        info["count"] = count_all
        info["count_m"] = count_m
        info["behavior"] = behavior
        datatest = info.copy()
        top_10_extension_malicious.append(datatest)

        for api_name in ext["apis"]:
            if(api_name not in top_10_api_called):
                top_10_api_called[api_name] =ext["apis"][api_name]
            else:
                top_10_api_called[api_name] += ext["apis"][api_name]

    top_10_api_called = Counter(top_10_api_called)      
    top_10_api_called_sorted = dict(top_10_api_called.most_common(10))
    info_uninstall_other_extension = {"name":"uninstall_other_extension","count":uninstall_other_extension,"extension":_list_uninstall_other_extension}
    info_prevents_extension_uninstall = {"name":"prevents_extension_uninstall","count":prevents_extension_uninstall,"extension":_list_prevents_extension_uninstall}
    info_keylogging_functionality = {"name":"keylogging_functionality","count":keylogging_functionality,"extension":_list_keylogging_functionality}
    info_steal_information_form = {"name":"steal_information_form","count":steal_information_form,"extension":_list_steal_information_form}
    info_block_antivirus_site = {"name":"block_antivirus_site","count":block_antivirus_site,"extension":_list_block_antivirus_site}
    info_deleted_response_headers = {"name":"deleted_response_headers","count":deleted_response_headers,"extension":_list_deleted_response_headers}
    info_injects_dynamic_javascript = {"name":"injects_dynamic_javascript","count":injects_dynamic_javascript,"extension":_list_injects_dynamic_javascript}
    info_get_all_cookies = {"name":"get_all_cookies","count":get_all_cookies,"extension":_list_get_all_cookies}
    info_http_request_4xx = {"name":"http_request_4xx","count":http_request_4xx,"extension":_list_http_request_4xx}
    top_behavior = [info_uninstall_other_extension,info_prevents_extension_uninstall,info_keylogging_functionality,info_steal_information_form,info_block_antivirus_site,info_deleted_response_headers,info_injects_dynamic_javascript,info_get_all_cookies,info_http_request_4xx,]

    print("[+] Malicious:",malicious)
    print("[+] Suspicious:",suspicious)
    print("[+] Clean",clean)
    print("[+] Top 10 Api Called:")
    print(top_10_api_called_sorted)
    print("[*] Top 10 Extension:")
    top_10_extension_malicious_sorted = sorted(sorted(top_10_extension_malicious, key = lambda i: i['count'],reverse=True),key = lambda i: i['count_m'],reverse=True)[:10]
    print(top_10_extension_malicious_sorted)
    print("[*] Top behavior:")
    top_behavior_sorted = sorted(top_behavior,key = lambda i: i['count'],reverse=True)
    print(top_behavior_sorted)

    result = {}
    result["Total"] = total
    result["Malicious"] = malicious
    result["Suspicious"] = suspicious
    result["Clean"] = clean
    result["top_10_api_called"] = top_10_api_called_sorted
    result["top_10_extension_malicious"] = top_10_extension_malicious_sorted
    result["top_behavior_sorted"] = top_behavior_sorted
    #Write to file
    json_parse = json.dumps(result, indent=4)
    open("Report_dynamic.json", "w").write(json_parse)
if __name__ == "__main__": 
    # for idx in open(r"G:\New\Extensions\KhoaLuan_Git\extesion_monitored.txt").readlines():
    #     idxr = idx.replace("\n","")
    #     AnalyzerOnlyOneExtension(idxr)
    pdb.set_trace()
    AnalyzerAllExtension()
