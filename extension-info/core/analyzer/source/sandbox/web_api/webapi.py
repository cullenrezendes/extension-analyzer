from flask import Flask
from flask import request
import pymongo
import json
import sqlite3
import pdb

client = pymongo.MongoClient("mongodb://localhost:27017/")

database = client["ChromeExtension"]
col = database["API"]
collist = database.list_collection_names()
if "API" in collist:
    print("The collection exists.")
else:
    print("Not found")
app = Flask(__name__)
real_id = {}
#f = open("../log/api.log", "w+")
@app.route('/hello', methods=['POST'])
def hello_world():
    # @sdata = request.form['javascript_data']
    jsondata = request.get_json()
    pdb.set_trace()
    try:
        log_output = open("output.log",'a')
        real_id_json = json.loads(real_id)
        log_output.write("real_id_json: " +str(real_id_json))
        log_output.write("jsondata['extensionId']: " + str(jsondata['extensionId']))
        log_output.write("real_id_json['id']: " +str(real_id_json['id']))
        log_output.close()
        if(jsondata["extensionId"] is not real_id_json["id"] ):
            jsondata["extensionId"] = real_id_json["id"]
        x = col.insert_one(jsondata)
    except:
        print("Install DB error")
    result = {'Reponse': "Accepted"}
    return json.dumps(result)

@app.route('/real_id', methods=['POST'])
def get_real_id():
    # @sdata = request.form['javascript_data']
    global real_id
    real_id = request.get_json()  
    print(real_id)
    result = {'Reponse': "Accepted"}
    return json.dumps(result)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
