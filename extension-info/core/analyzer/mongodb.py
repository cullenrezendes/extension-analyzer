import pymongo
import os
def ConnectMongoDB(collection):
  client = pymongo.MongoClient("localhost",27017)
  my_mongo_db = client["Thesis"]    #database
  print("Here is my collection: " + str(collection))
  return my_mongo_db[collection]    #collection

def InsertMongoDB(ext_id):
  collection = ConnectMongoDB("Analyzer")
  try:
    collection.insert_one({"ID": ext_id, "is_reported": 0})
    return 1
  except Exception as E:
    print(E)
    return None

def CheckMongoDB(ext_id):
  collection = ConnectMongoDB("Analyzer")
  a = collection.find_one({"id": ext_id})
  if (a is not None):
    return 1
  else:
    return None

def PutReportIntoDB(result):
  report_collection = ConnectMongoDB("Reports")
  try:
    # result.update({"count": ext_number})
    report_collection.insert(result)
  except Exception as E:
    print(E)
# def GetReportfromDB(ext_id):
