import Config as Conf
import Lib.Functions as Func
import json
import pandas as pd 
import time 
import numpy as np


BASE = Conf.base
RESPONSE_IMG = Conf.RESPONSE_IMG
RESPONSE_CNT = Conf.RESPONSE_CNT
URL = "/csapi/v1.1/"
ACTION = "images/list?"
tag = Conf.TAG
payload = {}
header = Func.getHeader(Conf.USERNAME,Conf.PASSWORD) 
REQUEST_URL = BASE + URL + ACTION

#getting a list of all images
response = Func.getRequest(REQUEST_URL,payload,header)

if (response.ok != True):
  print("Failed to get response from API")
  exit()
#getting a list of alll images
ImageListData = json.loads(response.text)
imageIds = []
for image in ImageListData['data']:
      imageIds.append(image['imageId'])


df = pd.DataFrame(imageIds)
df = df.replace(to_replace='None', value=np.nan).dropna()
imageIdsList = df[0].unique()


rows = []
tagRows = []
TAG_HEADER = {'imageId','tag'}
IMAGE_VULN_Header = ['created','updated','author','imageId','lastScanned','totalVulCount',\
  'scanStatus','lastFound','firstFound','severity','customerSeverity','typeDetected',\
   'risk','category','discoveryType','qid','cvssInfo.baseScore','cvss3Info.baseScore',\
    'ageInDays','fixed','os','nonRunningKernel','nonExploitableConfig','runningService']
for image in imageIdsList:
  print("ImageId :" + image)
  ACTION = "images/"+image
  REQUEST_URL = BASE + URL + ACTION
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
        'cvss3Info.baseScore' : vuln['cvss3Info']['baseScore'],
        'ageInDays' : vuln['ageInDays'],
        'fixed' : vuln['fixed'],
        'os' : vuln['os'],
        'nonRunningKernel' : vuln['nonRunningKernel'],
        'nonExploitableConfig' : vuln['nonExploitableConfig'],
        'runningService' : vuln['runningService']
      }
      rows.append(row)

MyImagedata = pd.DataFrame(rows,columns=IMAGE_VULN_Header)
MyImagedata.to_csv(Conf.CSV_IMG_QID,index=False)

MyTagData = pd.DataFrame(tagRows,columns=TAG_HEADER)
MyTagData.to_csv(Conf.CSV_IMG_TAG,index=False)








########################
ACTION = "containers/"
REQUEST_URL = BASE + URL + ACTION

response = Func.getRequest(REQUEST_URL,payload,header)

if (response.ok != True):
  print("Failed to get response from API")
  exit()


ContainerListData = json.loads(response.text)
ContainerIds = []
for container in ContainerListData['data']:
      ContainerIds.append(container['containerId'])


df = pd.DataFrame(ContainerIds)
df = df.replace(to_replace='None', value=np.nan).dropna()
containerIdsList = df[0].unique()

rows = []
CONTAINER_VULN_Header = ['created','updated','name','imageId','operatingSystem',\
  'lastScanned','state','containerId','lastFound','firstFound','severity','customerSeverity','typeDetected',\
   'risk','category','discoveryType','qid','cvssInfo.baseScore','cvss3Info.baseScore',\
    'ageInDays','fixed','os','nonRunningKernel','nonExploitableConfig','runningService']

for container in containerIdsList:
  print("containerId :" + container)
  ACTION = "containers/"+container
  REQUEST_URL = BASE + URL + ACTION
  time.sleep(2)
  response = Func.getRequest(REQUEST_URL,payload,header)
  if (response == {'Error'}):
    print("Failed to get response from API or no data for image")
  else:
    print(container + " - OK")
    data = json.loads(response.text)
    vulns = data['vulnerabilities']
    for vuln in vulns:
      row = {
        'created' : data['created'],
        'updated' : data['updated'],
        'name' : data['name'],
        'imageId' : data['imageId'],
        'operatingSystem' : data['operatingSystem'],
        'containerId' : data['containerId'],
        'state' : data['state'],
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
        'cvss3Info.baseScore' : vuln['cvss3Info']['baseScore'],
        'ageInDays' : vuln['ageInDays'],
        'fixed' : vuln['fixed'],
        'os' : vuln['os'],
        'nonRunningKernel' : vuln['nonRunningKernel'],
        'nonExploitableConfig' : vuln['nonExploitableConfig'],
        'runningService' : vuln['runningService']
      }
      rows.append(row)

MyContainerData = pd.DataFrame(rows,columns=CONTAINER_VULN_Header)
MyContainerData.to_csv(Conf.CSV_CONTAINERS,index=False)

