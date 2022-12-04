import requests
import xml.etree.ElementTree as Xet
import base64
from datetime import timedelta, date
import os as _os
import pandas as pd 



#collecting data from XML 
def tryToGetAttribute(Object,inputString):
    try:
        output = Object.find(inputString).text
    except:
        output = "Null"
    
    return output

#collecting data from XML 
def tryToGetObj(Object,inputString):
    try:
        output = Object.find(inputString)
    except:
        output = "Null"
    
    return output


#used to get the access token
def getToken(USERNAME,PASSWORD):
    AuthStringRaw = USERNAME+":"+PASSWORD
    base64_bytes = AuthStringRaw.encode("ascii")
    authtoken = base64.b64encode(base64_bytes)
    base64_authtoken = authtoken.decode("ascii")
    return base64_authtoken

#calculate time delta
def getSearchTime(delta):
    today = date.today()
    lastweek_date = today - timedelta(days=delta)
    DateForSearch=lastweek_date.strftime("%Y-%m-%dT%H:%M:%SZ")
    return DateForSearch
#return timestemp 
def getStempTime():
    today = date.today()
    dt_string = today.strftime("%Y-%m-%dT%H:%M:%SZ")
    return dt_string



#Creates the XML to be used as payload 
def getXmlTagPayload(tag):
    payload = "<ServiceRequest> \r\n <filters> \r\n <Criteria field=\"tagName\" operator=\"EQUALS\">"+str(tag)+"</Criteria> \r\n </filters> \r\n</ServiceRequest>"
    return payload
#will be used by host API to get host based on time critira 
def getXmlPayload(id,delta):
    payload = "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\r\n<ServiceRequest>\r\n    <filters>\r\n        <Criteria field=\"lastVulnScan\" operator=\"GREATER\">"+str(getSearchTime(delta))+"</Criteria>\r\n <Criteria field=\"id\" operator=\"GREATER\">"+str(id)+"</Criteria>\r\n    </filters>\r\n</ServiceRequest>"
    return payload

##Override - Delete - remove the False=True option
def getXmlHeader(USERNAME={},PASSWORD={}):
    headers = {
    "Content-Type": "application/xml",
    "Accept": "application/xml",
    "X-Requested-With": "QualysPostman",
    "Authorization": "Basic "+getToken(USERNAME,PASSWORD)
    }
    return headers


#Used to get the header of the request
def getHeader(USERNAME,PASSWORD):
    headers = {
    "Content-Type": "application/json",
    "Accept": "application/json",
    "X-Requested-With": "QualysPostman",
    "Authorization": "Basic "+getToken(USERNAME,PASSWORD)
    }
    return headers

#Used to get the header of the request
def getHeaderBearer(token):
    headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'X-Requested-With': 'QualysPostman',
    'Authorization': 'Bearer '+ token
    }
    return headers

#Used to get the header of the request
def getTokenHeader():
    headers = {
    "Content-Type": "application/x-www-form-urlencoded",
    "Accept": "application/json",
    "X-Requested-With": "QualysPostman",
    }
    return headers

#Used to Post requests
def postRequest(URL,payload,headers,files=[]):
    print("POSTING to "+ URL)
    print("Payload: "+ str(payload))
    try:
        response = requests.request("POST", URL, headers=headers, data=payload, files=files)
    except:
        print("Failed to send request to API")
        return str(response.status_code)

    if (response.ok != True):
        print("Failed to get response from API")
        return {"Error"}
    else:
        return  response


def getRequest(URL,payload,headers,files=[]):
    print("POSTING to "+ URL)
    print("Payload: "+ str(payload))
    try:
        response = requests.request("GET", URL, headers=headers, data=payload)
    except:
        print("Failed to send request to API")
    
    if (response.ok != True):
        print("Failed to get response from API")
        return {"Error"}
    else:
        return  response


def deleteTempFiles(files):
    for file in files:
        if _os.path.exists(file):
            _os.remove(file)



# #Used to process multiple requests
# def checkForMoreRecords(RESPONSEXML):
#     tree = Xet.parse(RESPONSEXML)
#     root = tree.getroot()   
#     Data = root.find("hasMoreRecords")
#     return str(Data.text)

# #Used to check if this is the last record during multiple requests
# def getLastRecord(RESPONSEXML):
#     tree = Xet.parse(RESPONSEXML)
#     root = tree.getroot()   
#     Data = root.find("lastId")
#     return str(Data.text)

# #get list of hosts
# def getHostAssets(RESPONSEXML):
#     index = 0
#     rows = []
#     tree = Xet.parse(RESPONSEXML)
#     root = tree.getroot()
#     Data = root.find("data")
#     HostAssets  = Data.findall("HostAsset")
#     for host in HostAssets:
#         print("procecing host ",str(index))
#         id = tryToGetAttribute(host,"id")
#         rows.append({"HOST_ID": id})
#         index+=1
#     return rows

