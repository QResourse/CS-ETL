
import pandas as pd 
import Lib.Functions as Func
import os

df = pd.read_xml('config.xml')
configList = df.iloc[0].to_list()

USERNAME = configList[1]
PASSWORD = configList[2]
TAG = configList[3]
##Start Detection
base = configList[0]
###Change the environment POD

RESPONSE_IMG = os.path.join("Requests","Image_Response.json")
CSV_IMG = os.path.join("Requests","_images.csv")
RESPONSE_CNT = os.path.join("Requests","Container_Response.json")
CSV_CONTAINERS = os.path.join("Requests","_containers.csv")