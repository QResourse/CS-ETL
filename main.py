import Config as Conf
import Lib.Functions as Func
import json
import pandas as pd 

BASE = Conf.base
RESPONSE_IMG = Conf.RESPONSE_IMG
RESPONSE_CNT = Conf.RESPONSE_CNT
URL = "/csapi/v1.1/"
ACTION = "images/list?"
tag = Conf.TAG
payload = {}
header = Func.getHeader(Conf.USERNAME,Conf.PASSWORD) 
REQUEST_URL = BASE + URL + ACTION


# response = Func.getRequest(REQUEST_URL,payload,header)

# if (response.ok != True):
#   print("Failed to get response from API")
#   exit()

# with open(RESPONSE_IMG, "w") as f:
#     f.write(response.text.encode("utf8").decode("ascii", "ignore"))
#     f.close()

# print("result of action can be found under the folder : " + RESPONSE_IMG)

# ACTION = "containers/list?"
# REQUEST_URL = BASE + URL + ACTION

# response = Func.getRequest(REQUEST_URL,payload,header)

# if (response.ok != True):
#   print("Failed to get response from API")
#   exit()

# with open(RESPONSE_CNT, "w") as f:
#     f.write(response.text.encode("utf8").decode("ascii", "ignore"))
#     f.close()


with open(RESPONSE_IMG) as f:
   data = json.load(f)
   print("Type:", type(data))


ImageData = data['data'] 
IMG_Header = ['created','updated','imageId','lastScanned','hostname',\
  'host-uuid','lastUpdated','host-ip','qid','software.name','software.version',\
    'software.fix','lastFound','firstFound','typeDetected']

rows = Func.convertImageFileToCsv(ImageData)



      
Mydata = pd.DataFrame(rows,columns=IMG_Header)
Mydata.to_csv(Conf.CSV_IMG)

################################
with open(RESPONSE_CNT) as f:
   dataContainers = json.load(f)
   print("Type:", type(dataContainers))

CONTAINER_Header = ['created','updated','imageId','lastScanned','sensorUuid','hostname',\
  'host-uuid','lastUpdated','host-ip','qid','software.name','software.version',\
    'software.fix','lastFound','firstFound','typeDetected','source','state','imageUuid','containerId']

containerData = dataContainers['data']
container = containerData[0]
#def convertContainerFileToCsv(containerData):

rows = Func.convertContainerFileToCSV(containerData)

Mydata = pd.DataFrame(rows,columns=CONTAINER_Header)
Mydata.to_csv(Conf.CSV_CONTAINERS)