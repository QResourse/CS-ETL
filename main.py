import Config as Conf
import Lib.Functions as Func
import json
import pandas as pd 
import time 
import numpy as np


BASE = Conf.base
GATEWAY = BASE.replace("qualysapi","gateway")
RESPONSE_IMG = Conf.RESPONSE_IMG
RESPONSE_CNT = Conf.RESPONSE_CNT
cleanPassword = Conf.PASSWORD.replace("%","%25")
safePassword = cleanPassword.replace("&","%26")
safePassword = safePassword.replace("#","%23")
payload = 'username='+Conf.USERNAME+"&password="+safePassword+"&token=true"
header = Func.getTokenHeader() 
REQUEST_URL = GATEWAY+"/auth"
response = Func.postRequest(REQUEST_URL,payload,header)
if (response.ok != True):
  print("Failed to get response from API")
  exit()

token = response.text


URL = "/csapi/v1.3/"
ACTION = "images/list?limit=250"
tag = Conf.TAG


REQUEST_URL = GATEWAY + URL + ACTION
header = Func.getHeaderBearer(token)
payload = {}
#getting a list of all images
response = Func.getRequest(REQUEST_URL,payload,header)

if (response.ok != True):
  print("Failed to get response from API")
  exit()

ImageListDataArray = []
def processImageResponse(response,ImageListDataArray):
  ImageListDataArray.append(json.loads(response.text))
  responseHeaders = response.headers
  if (len(responseHeaders)== 18):
    nextString = responseHeaders["link"]
    nextArray = nextString.split(";")
    NEXT_URL = nextArray[0].strip("'<>")
    response = Func.getRequest(NEXT_URL,payload,header)
    if (response.ok != True):
      print("Failed to get response from API")
      exit()
    processImageResponse(response,ImageListDataArray)
  else:
    return response

response = processImageResponse(response,ImageListDataArray)
if (response == True):
  ImageListDataArray.append(json.loads(response.text))

imageIds = []
for ImageListData in ImageListDataArray:
  for image in ImageListData['data']:
        imageIds.append(image['sha'])


df = pd.DataFrame(imageIds)
df = df.replace(to_replace='None', value=np.nan).dropna()
imageIdsList = df[0].unique()


rows = []
tagRows = []
TAG_HEADER = {'imageId','tag'}
IMAGE_VULN_Header = ['created','updated','author','label','uuid','sha','operatingSystem',\
  'imageId','lastScanned','totalVulCount',\
  'scanStatus','lastFound','firstFound','severity','customerSeverity','typeDetected',\
   'risk','category','discoveryType','qid','cvssInfo.baseScore','cvss3Info.baseScore']
for image in imageIdsList:
  print("ImageId :" + image)
  ACTION = "images/"+image
  REQUEST_URL = GATEWAY + URL + ACTION
  time.sleep(2)
  response = Func.getRequest(REQUEST_URL,payload,header)
  if (response == {'Error'}):
    print("Failed to get response from API or no data for image")
  else:
    print(image + " - OK")
    data = json.loads(response.text)
    repos = data['repo']
    for repo in repos:
      tagRows.append(
        {'imageId': data['imageId'],'tag' : repo['tag']})
    vulns = data['vulnerabilities']
    for vuln in vulns:
      row = {
        'created' : data['created'],
        'updated' : data['updated'],
        'author' : data['author'],
        'label' : data['label'],
        'uuid': data['uuid'],
        'sha' : data['sha'],
        'operatingSystem': data['operatingSystem'],
        'imageId' : data['imageId'],
        'lastScanned' : data['lastScanned'],
        'totalVulCount' : data['totalVulCount'],
        'scanStatus' : data['scanStatus'],
        'lastFound' : vuln['lastFound'],
        'firstFound' : vuln['firstFound'],
        'severity' : vuln['severity'],
        'customerSeverity' : vuln['customerSeverity'],
        'typeDetected' : vuln['typeDetected'],
        'status' : vuln['status'],
        'risk': vuln['risk'],
        'category' : vuln['category'],
        'discoveryType' : vuln['discoveryType'],
        'qid' : vuln['qid'],
        'cvssInfo.baseScore' : vuln['cvssInfo']['baseScore'],
        'cvss3Info.baseScore' : vuln['cvss3Info']['baseScore']
      }
      rows.append(row)

MyImagedata = pd.DataFrame(rows,columns=IMAGE_VULN_Header)
MyImagedata.to_csv(Conf.CSV_IMG_QID,index=False)

MyTagData = pd.DataFrame(tagRows,columns=TAG_HEADER)
MyTagData.to_csv(Conf.CSV_IMG_TAG,index=False)








########################
payload = "\r\n"
ACTION = "containers/list?limit=250"
REQUEST_URL = GATEWAY + URL + ACTION

response = Func.getRequest(REQUEST_URL,payload,header)

if (response.ok != True):
  print("Failed to get response from API")
  exit()



ContainersListDataArray = []
def processContainersResponse(response,ContainersListDataArray):
  ContainersListDataArray.append(json.loads(response.text))
  responseHeaders = response.headers
  if (len(responseHeaders)> 18):
    nextString = responseHeaders["link"]
    nextArray = nextString.split(";")
    NEXT_URL = nextArray[0].strip("'<>")
    response = Func.getRequest(NEXT_URL,payload,header)
    if (response.ok != True):
      print("Failed to get response from API")
      exit()
    processContainersResponse(response,ContainersListDataArray)
  else:
    return response


response = processContainersResponse(response,ContainersListDataArray)
###############################################################
if (response == True):
  ContainersListDataArray.append(json.loads(response.text))



with open(Conf.RESPONSE_CNT_LIST, "w") as f:
  f.write(response.text.encode("utf8").decode("ascii", "ignore"))
  f.close()

ContainerIds = []
for ContainerListData in ContainersListDataArray:
  for container in ContainerListData['data']:
        ContainerIds.append(container['sha'])

############################################################### Up to here
df = pd.DataFrame(ContainerIds)
df = df.replace(to_replace='None', value=np.nan).dropna()
containerIdsList = df[0].unique()

rows = []
CONTAINER_VULN_Header = ['created','updated','name','imageId','operatingSystem','sha','privileged','isDrift','isRoot'\
  'sensorUuid','hostname','ipAddress','uuid','lastUpdated','containerId','state','imageUuid','lastFound','firstFound','severity','customerSeverity'\
    ,'typeDetected','status','risk','category','discoveryType','qid','cvssInfo.baseScore','cvss3Info.baseScore']

totalListLength = str(len(containerIdsList))
index = 0 

for container in containerIdsList:
  print("containerId :" + container)
  ACTION = "containers/"+container
  REQUEST_URL = GATEWAY + URL + ACTION
  time.sleep(2)
  response = Func.getRequest(REQUEST_URL,payload,header)
  if (response == {'Error'}):
    print("Failed to get response from API or no data for image")
  else:
    print(container + " - OK - " + str(index) + " out of "+ totalListLength)
    index+=1
    data = json.loads(response.text)
    host = data['host']
    vulns = data['vulnerabilities']
    for vuln in vulns:
      row = {
        'created' : data['created'],
        'updated' : data['updated'],
        'name' : data['name'],
        'imageId' : data['imageId'],
        'operatingSystem' : data['operatingSystem'],
        'sha' : data['sha'],
        'privileged' : data['privileged'],
        'isDrift' : data['isDrift'],
        'isRoot' : data['isRoot'],
        'sensorUuid' : host['sensorUuid'],
        'hostname' : host['hostname'],
        'ipAddress' : host['ipAddress'],
        'uuid' : host['uuid'],
        'lastUpdated' : host['lastUpdated'],
        'containerId' : data['containerId'],
        'state' : data['state'],
        'imageUuid' : data['imageUuid'],
        'lastFound' : vuln['lastFound'],
        'firstFound' : vuln['firstFound'],
        'severity' : vuln['severity'],
        'customerSeverity' : vuln['customerSeverity'],
        'typeDetected' : vuln['typeDetected'],
        'status' : vuln['status'],
        'risk': vuln['risk'],
        'category' : vuln['category'],
        'discoveryType' : vuln['discoveryType'],
        'qid' : vuln['qid'],
        'cvssInfo.baseScore' : vuln['cvssInfo']['baseScore'],
        'cvss3Info.baseScore' : vuln['cvss3Info']['baseScore']
      }
      rows.append(row)
      

MyContainerData = pd.DataFrame(rows,columns=CONTAINER_VULN_Header)
MyContainerData.to_csv(Conf.CSV_CONTAINERS,index=False)

