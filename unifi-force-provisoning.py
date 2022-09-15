#!/usr/bin/python3
# Developer: Massoud Ahmed

import requests
import json
import urllib3

print("Starting forced provisioning")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

json_data = {
    'password': '<YourPassword>',
    'username': '<unifiapiUser>',
}

response = requests.post('https://<ControllerIP>:8443/api/login', json=json_data, verify=False)
print(response)
print(response.headers)


cookies = response.headers['Set-Cookie'].split(";")
unifises = str((cookies[0].split("="))[1])


csrf_token = str((cookies[3].split('='))[1])

print(unifises)
print(csrf_token)


cookies = {
    'unifises': str(unifises),
    'csrf_token': str(csrf_token),
}




response = requests.get('https://<ControllerIP>:8443/api/s/default/stat/device', cookies=cookies,verify=False)

responseAPs = response.json()

for devices in responseAPs['data']:
  mac = devices['mac']
  try:
   print(devices['name'], " provisioned")
  except:
    continue
  json_data = {
    'cmd': 'force-provision',
    'mac': mac,
  }
  response = requests.post('https://<ControllerIP>:8443/api/s/default/cmd/devmgr', cookies=cookies, json=json_data, verify=False)
  
print("Finished")
