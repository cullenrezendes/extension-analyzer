import os
import sys
import json
import io, re
import sqlite3
from typing import Dict, Any
import logging
import operator
import requests, argparse, zipfile
import jsbeautifier
from multiprocessing import Pool as ProcessPool
import pdb
from mongodb import * 
from bson.objectid import ObjectId

cwd = os.path.abspath(os.path.dirname(sys.argv[0]))
database = cwd + r"/source/sandbox/ExtensionDb.db"
DataDir = cwd +r"/Data"

def FileConcat(file, pattern, string):   #Noi file?
    t = ReadFile(file).find(pattern) + len(pattern)
    tmp1 = ReadFile(file)[:t:]
    tmp2 = ReadFile(file)[t::]
    return tmp1 + string + tmp2


def FileConcatReverse(file, pattern, string): #Noi file reverse?
    t = ReadFile(file).rfind(pattern)
    tmp1 = ReadFile(file)[:t:]
    tmp2 = ReadFile(file)[t::]
    return tmp1 + string + tmp2


def StringConcat(src, pattern, string):
    t = src.find(pattern) + len(pattern)
    tmp1 = src[:t:]
    tmp2 = src[t::]
    return tmp1 + string + tmp2


def StringInsert(src, index, string):
    tmp1 = src[:index:]
    tmp2 = src[index::]
    return tmp1 + string + tmp2


def ReadFile(filename):
    with open(filename, "r") as f:
        return f.read()


def ReadLine(filename):
    with open(filename) as f:
        lines = [line.rstrip('\n') for line in f]
        return lines


def ConnectDB(db):
    conn = sqlite3.connect(db)
    return conn


def InserttoDB(conn, cursor, ID, name, path):
    cursor.execute("INSERT INTO Extensions VALUES ('{0}', '{1}', '{2}')".format(ID, name, path))
    conn.commit()


def CloseDB(conn):
    conn.close()


def CheckDownloaded(cursor, ID):
    cursor.execute("SELECT ID FROM Extensions WHERE ID='{0}'".format(ID))
    if cursor.fetchone() == None:
        return False
    return True


def WriteFile(filename, string):
    with open(filename, "w") as f:
        f.write(string)


def CreateDir(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)


def GetListExt(db):
    conn = ConnectDB(db)
    cursor = conn.cursor()
    cursor.execute("SELECT ID,Path FROM Extensions")
    ret = cursor.fetchall()
    CloseDB(conn)
    if ret is None:
        return
    return ret

def ListDirTree(path):
    for root, dir, files in os.walk(path):
        level = root.replace(path, '').count(os.sep)
        indent = ' ' * 4 * level
        print('{}{}'.format(indent, os.path.basename(root)))
        subindent = ' ' * 4 * (level + 1)
        for f in files:
            print('{}{}'.format(subindent, f))


def ListJSFile(path):
    files = [val for sublist in
             [[os.path.join(root, js) for js in files if js.endswith('.js')] for root, dir, files in os.walk(path)] for
             val in sublist]      #Understand now
    return files


#This functions used to export permissions
def ManifestParser(file, root_path):   #file = 'manifest.json' of an extension
    try:
        global name
        with io.open(file, 'r', encoding='utf-8-sig') as f:    #open 'manifest.json'
            tmpjson = remove_comments(f.read())
            tmpjson = remove_trailing_commas(tmpjson)
            data = json.loads(tmpjson, strict=False) #Convert JSON into Python's dict
            
            #my code
            # with open('testing_permission.txt', 'w') as permissions_file:
            #     # breakpoint()
            #     permissions_file.write(str(data['permissions']))    #still right

            if 'name' in data:
                if ('__MSG_' in data['name']):
                    temp = data['name'].replace('__MSG_', '').replace('__','')
                    path = root_path + r'\_locales\en\messages.json'
                    with open(path, 'r', encoding="utf8") as f:
                        tmpjson = json.loads(f.read(), strict=False)
                        temp_name = tmpjson[temp]['message']
                    name = temp_name
                else: 
                    name = data['name']
            permissions = []
            if 'permissions' in data:
                    permissions = data['permissions']
            if "content_security_policy" in data:
                csp = data['content_security_policy']
            else:
                csp = "script-src 'self'; object-src 'self'"
            content_scripts = []
            if 'content_scripts' in data:
                for e in data['content_scripts']:
                    if e.get('js') is not None:
                        temp = dict(js=e.get('js'), matches=e.get('matches'))
                        content_scripts.append(temp)
        result = dict(name=name, permissions={}, csp=csp, content_scripts=content_scripts)

        with open('permissions.json') as f:  
            data = json.load(f)
            for i in permissions:
                if type(i) == str:
                    if i in data:
                        temp: Dict[Any, Any] = {i: data[i]}
                        result['permissions'].update(temp)
                        continue
                    temp: Dict[Any, Any] = {i:{ "description": "None", "isWarning": False, "warning": "None"}} #Thieu sot la o day. FIXED!
                    result['permissions'].update(temp)
                    
        return result
    except KeyboardInterrupt:
        print(KeyboardInterrupt)


def JSBeautify(file):  #Beautify to be able to read
    with io.open(file, 'r', encoding='utf-8', errors='ignore') as f:
        beautifier = jsbeautifier.beautify(f.read())
    with io.open(file, 'w', encoding='utf-8', errors='ignore') as f:
        f.write(beautifier)


def APIParser(file):
    JSBeautify(file)
    with io.open(file, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.read().splitlines()
    with open('api.json') as f:
        api = json.load(f)    #convert json to dict in Python
        pattern_list = [key for key, value in api.items()]
    result = {}
    js_file = os.path.basename(file)
    for index, line in enumerate(lines, 0):
        for pattern in pattern_list:
            found = False
            if "AND" in pattern:
                found = True
                cond = pattern.split(" AND ")
                for e in cond:
                    if e not in line:
                        found = False
                        break
            if pattern in line or found:
                line_before = line_after = ''
                if index > 0:
                    line_before = lines[index - 1]
                if index < len(lines) - 1:
                    line_after = lines[index + 1]
                content = [{'line_1': index, 'code_1': line_before.lstrip().rstrip()},
                           {'line_2': index + 1, 'code_2': line.lstrip().rstrip()},
                           {'line_3': index + 2, 'code_3': line_after.lstrip().rstrip()}]
                if pattern not in result:
                    temp: Dict[Any, Any] = {pattern: api[pattern]}
                    result.update(temp)
                    result[pattern]['lines_found'] = []
                lines_found = {'file': js_file, 'lines': content}
                result[pattern]['lines_found'].append(lines_found)
                break
    return result


def ValidFilename(value, deletechars):
    for c in deletechars:
        value = value.replace(c, '-')
    return value


def remove_comments(json_like):
    comments_re = re.compile(r'//.*?$|/\*.*?\*/|\'(?:\\.|[^\\\'])*\'|"(?:\\.|[^\\"])*"', re.DOTALL | re.MULTILINE)

    def replacer(match):
        s = match.group(0)
        if s[0] == '/': return ""
        return s

    return comments_re.sub(replacer, json_like)


def remove_trailing_commas(json_like):
    trailing_object_commas_re = re.compile(
        r'(,)\s*}(?=([^"\\]*(\\.|"([^"\\]*\\.)*[^"\\]*"))*[^"]*$)')
    trailing_array_commas_re = re.compile(
        r'(,)\s*\](?=([^"\\]*(\\.|"([^"\\]*\\.)*[^"\\]*"))*[^"]*$)')
    objects_fixed = trailing_object_commas_re.sub("}", json_like)
    objects_fixed = re.sub(";$", ",", objects_fixed)
    # objects_fixed = re.sub(r'\\', r'\\\\', objects_fixed)
    return trailing_array_commas_re.sub("]", objects_fixed)

def SearchByName(keyword):          #searching in DB
    keyword = keyword.replace(" ", "-")
    connDB = ConnectDB(database)
    c = connDB.cursor()
    stmt = "SELECT ID,Name,Path FROM Extensions WHERE Name like '%{}%'".format(keyword)
    c.execute(stmt)
    result = c.fetchall()
    CloseDB(connDB)
    if not result:
        return "Extension not found. Please enter link to extension to analyze"
    else:
        result = [(res[0], res[1], "Output\\" + res[0]) for res in result]
        
        return result


def SearchByID(id):                 #searching in DB
    connDB = ConnectDB(database)
    c = connDB.cursor()
    stmt = "SELECT ID,Name,Path FROM Extensions WHERE ID like '%{}%'".format(id)
    #stmt = "SELECT name FROM sqlite_master WHERE type = 'table';"
    c.execute(stmt)
    result = c.fetchall()
    CloseDB(connDB)
    if not result:
        return "Extension not found. Please enter link to extension to analyze"
    else:
        result = [(res[0], res[1], res[2]) for res in result]
        return result


def GetExtID(arg):
    if arg.startswith('http://'):
        arg = arg.replace('http://', 'https://')   #http -> https
    if arg.startswith('https://'):
        return (arg.split('/')[-1]).split('?')[0], arg.split("/")[-2]   #split ID, and extension name from link



def GetCrxUrl(extension_id):
    if '?' in extension_id:
        extension_id = extension_id[:extension_id.find('?')]
    return('https://clients2.google.com/service/update2/crx?response=redirect&os=win&arch=x64&os_arch=x86_64&nacl_arch=x86-64&prod=chromiumcrx&prodchannel=beta&prodversion=79.0.3945.53&lang=en&acceptformat=crx3&x=id%3D{extension_id}%26installsource%3Dondemand%26uc'.format(extension_id=extension_id))
    #This is the original line of code
    #return ('https://clients2.google.com/service/update2/crx?response=redirect&prodversion=49.0'
    #        '&x=id%3D{extension_id}%26installsource%3Dondemand%26uc'.format(extension_id=extension_id))


def DownloadAndExtractExt(ExtID,ExtName):
    connDB = ConnectDB(database)   #connect to db
    c = connDB.cursor()             #?
    filename = '{0}.crx'.format(ExtName)    
    dst_path = DataDir + "/" + filename         
    dst_dir = DataDir + "/" + filename[:-4]

    # if CheckDownloaded(c, ExtID):
    #     return "Already"
    crx_url = GetCrxUrl(ExtID)
    try:
        req = requests.get(crx_url, stream=True)
        status_code = req.status_code
    except Exception as e:
        print ('[!]Couldn\'t request the crx file ({0})'.format(e))
        return "Error"
    if status_code == 200:
        try:
            with open(dst_path, 'wb') as fd:
                for chunk in req.iter_content(chunk_size=128):
                    fd.write(chunk)
        except Exception as e:
            print ('[!]Couldn\'t download the crx file ({0})'.format(e))
            return "Error"
        else:
            """print ('[*]Chrome extension crx file downloaded successfully')
            print ("[*]Save to " + dst_path)"""
            ExtractCRX(filename, dst_path, dst_dir)
            os.remove(dst_path)
            InserttoDB(connDB, c, ExtID, filename[:-4], dst_dir) #add to db
            CloseDB(connDB)
            return dst_dir
    else:
        print ('[!]Couldn\'t download the crx file (status code: {0})'.format(status_code))
        return "Error"

def ExtractCRX(filename, path, dst_dir):
	CreateDir(dst_dir)
	#print ('[+]Directory {dir} created'.format(dir=filename[:-4]))
	try:
		#print ('[+]Extracting the contents of {0}...'.format(filename))
		zip_ref = zipfile.ZipFile(path, 'r')
		zip_ref.extractall(dst_dir)
		zip_ref.close()
	except Exception as e:
		print ('[!]Couldn\'t extract the contents of the crx file ({0})'.format(e))
		return False
	else:
		#print ('[*]Extracted successfully')
		return True

def ExtensionAnalyzer(collection, ext_id, root_path, mongoid):
    logging.basicConfig(filename='Error_analyzer.log', level=logging.DEBUG)

    try:
        manifest_file = root_path + "/manifest.json"
        final_output = {}
        if os.path.exists(manifest_file) and os.path.getsize(manifest_file): #Update permissions
            manifest_output = ManifestParser(manifest_file, root_path)   #something wrong here. FIXED!
        else:
            manifest_output = dict(permissions={})
        js_files = [e.replace('/', "/") for e in ListJSFile(root_path)] 
        api_output = dict(api={})

        pool = ProcessPool(8)         
        results = pool.map(APIParser, js_files)  
        pool.close()
        pool.join()
        
        for result in results:
            for api, value in result.items():
                if api in api_output['api']:
                    result[api]['lines_found'] = api_output['api'][api]['lines_found'] + result[api]['lines_found']
            api_output['api'].update(result)
        final_output.update(manifest_output)
        final_output.update(api_output)

        try:
            # final_output.
            temp = {"id" : ext_id, 'status': True}
            temp.update(final_output)
            collection.replace_one({'_id': ObjectId(mongoid)} ,temp, upsert=True)
            #collection.update({'_id': ObjectId(mongoid)} ,temp, check_keys=False)

        except Exception as E:
            print(E)
            print(ext_id, root_path, sep=" - ",end="\n")
        # output_file = 'Output\\' + ValidFilename(ext_id, ":<|>\"/\\?*") + '.json'  #concat name
        # with io.open(output_file, 'w', encoding='utf-8') as f: #write file
        #     json.dump(final_output, f, ensure_ascii=False)
    except Exception as E:
        log = "\n----------------------\n"
        log += ":" + root_path
        logging.exception(log)
        print(E)

def GetReport(id): #Lay report
    print("Output\\"+ValidFilename(id, ":<|>\"/\\?*")+".json")

def GenReport(collection): #Generate file Report.json and insert "Report" document to MongdoDB from database
    print("Generating reports...\n")
    result = dict(perms_avg=0, perms_highest={}, warn_perms_avg=0, top_10_ext_perms=[], 
    top_10_ext_warn_perms=[], top_10_ext_high_risk=[], top_perms=[], top_warn_perms=[], 
    analyzed_ext=0, above_50=0, above_30=0, above_15=0, below_15=0, etc=0, api_avg=0, 
    top_api=[], top_domain_perms=[], top_content_scripts_domain=[])
    
    result['perms_highest'] = dict(name=[], quantity=0)
    total_perms = 0
    total_extensions = 0
    total_warn_perms = 0
    total_api = 0
    total_top_perms = {}
    total_top_warn_perms = {}
    total_top_api = {}
    total_top_domain_perms = {}
    top_content_scripts_domain = {}
    top_10_ext_perms = {}
    top_10_ext_high_risk = {}
    top_10_ext_warn_perms = {}
    
    for content in collection.find({}):
        total_extensions += 1
        perms_quantity = len(content['permissions']) #number of permissions
        total_perms += perms_quantity
        total_api += len(content['api']) #number of API
        if perms_quantity == result['perms_highest'].get('quantity'):  #append permissions highest
            result['perms_highest']['name'].append(content['name'])
        elif perms_quantity > result['perms_highest'].get('quantity'):   #Change permissions highest
            result['perms_highest']['name'] = []
            result['perms_highest']['name'].append(content['name'])
            result['perms_highest']['quantity'] = perms_quantity
        
        #Dict contain top 10 permissions
        temp: Dict[Any, Any] = {content['id']: perms_quantity}
        top_10_ext_perms.update(temp)

        warns_perms_ext = 0
        for perm, value in content['permissions'].items():   #permission loop
            
            if value['isWarning'] is True:
                total_warn_perms += 1
                warns_perms_ext += 1
                if perm in total_top_warn_perms: #If that permission is in top_warn_perms then plus 1
                    total_top_warn_perms[perm] += 1
                else:
                    temp: Dict[Any, Any] = {perm: 1}  #add new permission
                    total_top_warn_perms.update(temp)
            temp: Dict[Any, Any] = {content['id']: warns_perms_ext}
            top_10_ext_warn_perms.update(temp)        
            
            #My code
            try:        
                if perm == re.search(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', perm).group():
                    if perm in total_top_domain_perms: #If that permission is in total_top_domain_perms then plus 1
                        total_top_domain_perms[perm] += 1
                    else:
                        temp: Dict[Any, Any] = {perm: 1}  #add new domain permission
                        total_top_domain_perms.update(temp) 
            except Exception as e:
                pass

            if perm in total_top_perms:
                total_top_perms[perm] += 1
            else:
                temp: Dict[Any, Any] = {perm: 1}
                total_top_perms.update(temp)
        for api, value in content['api'].items(): #api loop
            if api in total_top_api:
                total_top_api[api] += 1
            else:
                temp:  Dict[Any, Any] = {api: 1}
                total_top_api.update(temp)
        
        high_risk = 0
        for api, value in content['api'].items(): #Count High risk
            if value['risk'] == "High risk":
                high_risk += 1
        temp: Dict[Any, Any] = {content['id']: high_risk}
        top_10_ext_high_risk.update(temp)

        api_quantity = len(content['api']) #number of API
        risk_collection = ConnectMongoDB("Risk")
        risk_temp = {"id": content['id']}
        
        if api_quantity != 0:
            percentage = high_risk / api_quantity
            if percentage >= 0.5:
                result['above_50'] += 1
                risk_temp.update({"risk": "High risk"})
                risk_collection.insert(risk_temp)
            elif percentage >= 0.3:
                result['above_30'] += 1
                risk_temp.update({"risk": "Medium risk"})
                risk_collection.insert(risk_temp)
            elif percentage >= 0.15:
                result['above_15'] += 1
                risk_temp.update({"risk": "Low risk"})
                risk_collection.insert(risk_temp)
            else:
                result['below_15'] += 1
                
        try:
            if ((content['content_scripts'] is not None) and (len(content['content_scripts']) > 0)):

                for domain in content['content_scripts'][0].get('matches'):
                    
                    if domain in top_content_scripts_domain:
                        top_content_scripts_domain[domain] += 1
                    else:
                        temp: Dict[Any, Any] = {domain: 1}  #add new domain
                        top_content_scripts_domain.update(temp)         
        except Exception as E:
            print(content['id'], E)
    result['etc'] = total_extensions - result['above_50'] - result['above_30'] - result['above_15'] - result['below_15']
    result['analyzed_ext'] = total_extensions
    result['perms_avg'] = total_perms // total_extensions
    result['warn_perms_avg'] = total_warn_perms // total_extensions
    result['api_avg'] = total_api // total_extensions

    count = 0
    for e in sorted(top_10_ext_perms.items(), key=operator.itemgetter(1), reverse=True): #sort total top permissions
        count += 1
        if count > 10:
            break
        result['top_10_ext_perms'].append(e)

    count = 0
    for e in sorted(top_10_ext_warn_perms.items(), key=operator.itemgetter(1), reverse=True): #sort total top permissions
        count += 1
        if count > 10:
            break
        result['top_10_ext_warn_perms'].append(e)

    count = 0
    for e in sorted(top_10_ext_high_risk.items(), key=operator.itemgetter(1), reverse=True): #sort total top permissions
        count += 1
        if count > 10:
            break
        result['top_10_ext_high_risk'].append(e)

    count = 0
    for e in sorted(total_top_perms.items(), key=operator.itemgetter(1), reverse=True): #sort total top permissions
        count += 1
        if count > 10:
            break
        result['top_perms'].append(e)
    count = 0
    for e in sorted(total_top_warn_perms.items(), key=operator.itemgetter(1), reverse=True): #sort top warning permissions
        count += 1
        if count > 10:
            break
        result['top_warn_perms'].append(e)
    count = 0
    for e in sorted(total_top_api.items(), key=operator.itemgetter(1), reverse=True): #sort top API
        count += 1
        if count > 10:
            break
        result['top_api'].append(e)
    count = 0
    for e in sorted(total_top_domain_perms.items(), key=operator.itemgetter(1), reverse=True): #sort total top permissions
        count += 1
        if count > 10:
            break
        result['top_domain_perms'].append(e)
    count = 0
    for e in sorted(top_content_scripts_domain.items(), key=operator.itemgetter(1), reverse=True): #sort total top permissions
        count += 1
        if count > 10:
            break
        result['top_content_scripts_domain'].append(e)    
    with open("Report.json", "w") as f:
        json.dump(result, f)    #convert  to JSON format
    print("Done! Check Report.json and Reports collection.")
    return result
