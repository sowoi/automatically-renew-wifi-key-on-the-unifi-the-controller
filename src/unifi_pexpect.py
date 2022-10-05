#!../bin/python3
# Developer: Massoud Ahmed
# This is a Python Expect script with which you can force automated changes of the WLAN key e.g. via Cron or Systemd Timer.
# This script works both on the controller and remotely via SSH and https. 
# You need a controller user for manual provisioning. Optionally, an SSH user is required (if the script is initialized via a remote connection).
# The SSH user only needs the following sudo permissions:
# Visudo
# Cmnd_Alias UNIFI=/usr/bin/systemctl restart unifi.service,/usr/bin/systemctl --no-pager status unifi.service
# <USER>  ALL=NOPASSWD:UNIFI
# if you want to use the mailfunction you need to setup MTA, i.e. via Postfix.
# this script uses mailutils as sendagent

import pexpect
import sys
import time
import secrets
import string
from optparse import OptionParser, OptionGroup
import os.path
from pathlib import Path
from subprocess import call, run
import subprocess
import json
import urllib3
import requests

# Create new random wifi key
def createPassword():
 alphabet = string.ascii_letters + string.digits
 wifikey = ''.join(secrets.choice(alphabet) for i in range(12))
 return wifikey

# Change wifi key
def changePassword(wifikey,host_name,ssid_name,user_name,password,debug):
 if user_name != None:
  sshcommand = "ssh "+user_name+"@"+host_name
  child = pexpect.spawn(sshcommand, encoding='utf-8')
  key = child.expect([".*assword:",".*Last*."])
  if key == 0:
   child.sendline(password)
   child.expect(".*Welcome*.")

  elif key == 1:
   child.sendline('mongo 127.0.0.1:27117')
 else:
   child = pexpect.spawn('mongo 127.0.0.1:27117',encoding='utf-8')
 child.logfile = debug

 child.expect(".*MongoDB.*")
 child.sendline('use ace;')
 child.expect(".*ace.*")
 time.sleep(1)
 child.sendline('db.wlanconf.find({"name" : "'+ssid_name+'"},{"x_passphrase":1});')
 time.sleep(4)
 child.expect('.* }*.')
 oldKeyTemp = child.after
 for keys in oldKeyTemp.splitlines():
  if "_id" in keys:
   keys = keys.replace('ObjectId(','').replace('")','"')
   keys = json.loads(json.loads(json.dumps(keys)))
   oldKey = keys["x_passphrase"]
 if debug == True:
  print("Old Wifi key: "+oldKey)
 time.sleep(4)

 
 child.sendline('db.wlanconf.update({"name" : "'+ssid_name+'"},{$set: {"x_passphrase" : "'+wifikey+'"}})')
 
 time.sleep(4)
 child.sendcontrol('d')
 child.sendline('sudo /usr/bin/systemctl restart unifi.service')
 time.sleep(50)
 child.sendline('sudo /usr/bin/systemctl --no-pager status unifi.service')
 time.sleep(15)
 child.expect(".*running*.", timeout=120)
 child.close()
 return(oldKey)




# trigger provisioning on all unifi APs
def forceProvision(host,unifi_user_name,unifi_user_password,debug):
 if debug:
  print("Starting forced provisioning")
 urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

 json_data = {
    'password': unifi_user_password,
    'username': unifi_user_name,
 }

 response = requests.post("https://"+host+':8443/api/login', json=json_data, verify=False)
 if debug:
  print("Response Headers: "+str(response.headers))


 cookies = response.headers['Set-Cookie'].split(";")
 unifises = str((cookies[0].split("="))[1])


 csrf_token = str((cookies[3].split('='))[1])
 if debug:
  print("CSRF Token: "+csrf_token)


 cookies = {
    'unifises': str(unifises),
    'csrf_token': str(csrf_token),
 }




 response = requests.get("https://"+host+':8443/api/s/default/stat/device', cookies=cookies,verify=False)

 responseAPs = response.json()

 for devices in responseAPs['data']:
  mac = devices['mac']
  try:
   if debug:
    print(devices['name'], " provisioned")
  except:
    continue
  json_data = {
    'cmd': 'force-provision',
    'mac': mac,
  }
  response = requests.post("https://"+host+':8443/api/s/default/cmd/devmgr', cookies=cookies, json=json_data, verify=False)
 if debug:
  print("Finished provisioning APs")




# send mail with changes 
def sendMailwithChanges(oldkey,wifikey,ssid, mailRecipient, mailSender,debug):

 mailSubject = 'Changed' + ssid +'"'
 mailBody = "Wifikey of SSID " + ssid + " changed from " + oldkey +" to "+ wifikey
 if debug == True:
  print("MailSubject: "+ mailSubject)
  print("MailBody: " + mailBody)
  print("MailRecipient: " + mailRecipient)
  print("MailSender: " + mailSender)
 mailCommand = "echo \""+ mailBody + "\" | mail -s \"" + mailSubject +" " +mailRecipient + " --content-type 'text/plain; charset=utf-8'" + " -aFrom:"+mailSender

 os.system(mailCommand)
 if debug == True:
  print("E-mail has been sent")
  
 sys.exit(0)

 


 
if __name__ == "__main__":

        desc='''%prog changes Unifi Wifi Password via PExpect, MongoDB and Unifi API '''
        parser = OptionParser(description=desc)
        gen_opts = OptionGroup(parser, "Generic options")
        host_opts = OptionGroup(parser, "Host options")
        ssid_opts = OptionGroup(parser, "SSID options")
        user_opts = OptionGroup(parser, "User options")
        password_opts = OptionGroup(parser, "Password options")
        remote_opts = OptionGroup(parser, "Remote options")
        mail_opts = OptionGroup(parser, "Mail options")
        parser.add_option_group(gen_opts)
        parser.add_option_group(host_opts)
        parser.add_option_group(ssid_opts)
        parser.add_option_group(user_opts)
        parser.add_option_group(password_opts)
        parser.add_option_group(remote_opts)
        parser.add_option_group(mail_opts)

        #-d / --debug
        gen_opts.add_option("-d", "--debug", dest="debug", default=False, action="store_true", help="enable debugging outputs (default: no)")

        #-H / --host
        remote_opts.add_option("-H", "--host", dest="host", default="127.0.0.1", action="store", metavar="HOST", help="defines the controller hostname or IP (default: localhost, only mandatory if script is not running locally)")

        #-s / --ssid
        
        ssid_opts.add_option("-S", "--ssid", dest="ssid_name", default=None, action="store", metavar="SSID", help="defines the SSID name (mandatory)")

        #-u / --user
        remote_opts.add_option("-u", "--user", dest="user_name", default=None, action="store", metavar="USER", help="defines SSH user (only mandatory if script is not running locally)")

        #-p / --password
        remote_opts.add_option("-p", "--password", dest="password", default=None, action="store", metavar="PASSWORD", help="defines SSH password. leave blank if ssh key is available (only mandatory if script is not running locally)")

        #--accountuser
        password_opts.add_option("-U", "--accountuser", dest="unifi_user_name", default=None, action="store", metavar="UNIFIUSER", help="defines your Unifi Controller user (mandatory)")

        #--accountpassword
        password_opts.add_option("-P", "--accountpassword", dest="unifi_user_password", default=None, action="store", metavar="UNIFIPASSWORD", help="defines your Unifi Controller user (mandatory")

        #--mailrecipient
        mail_opts.add_option("-m", "--mailrecipient", dest="mailrecipient", default=None, action="store", metavar="MAILRECIPIENT", help="provide an e-mail address to which the change of the key will be sent.")

        #--mailsender
        mail_opts.add_option("-r", "--mailsender", dest="mailsender", default=None, action="store", metavar="MAILSENDER", help="provide an e-mail address from  which the change of the key will be sent (mandatory if mailrecipient is set).")
        

        #parse arguments   
        (options, args) = parser.parse_args()
        host = options.host
        user = options.user_name
        ssid = options.ssid_name
        password = options.password
        unifi_user_name = options.unifi_user_name
        unifi_user_password = options.unifi_user_password
        debug = options.debug
        mailrecipient = options.mailrecipient
        mailsender = options.mailsender

        #set logging
        if options.debug:
          logging = sys.stdout
          print("Got: host "+ host + " SSID " + ssid + " Unifi Username " + unifi_user_name)

        else:
          logging = None

        if (options.unifi_user_name) == None:
                print("Please define controller username. Use -h to show help.")
                exit(3)
        if (options.unifi_user_password) == None:
                print("Please define controller password. Use -h to show help.")
                exit(3)

        if (options.ssid_name) == None:
                print("Please enter SSID. Type -h or --help for options")
                exit(3)

        if (options.user_name) == None and (options.host) != "127.0.0.1":
                print("Please specify a username for oyur host. Type -h or --help for options")
                exit(3)
                
        elif (options.password) == None and (options.host) != "127.0.0.1":
                home = str(Path.home())
                sshkeyFile = home+"/.ssh/id_rsa"

                if os.path.isfile(sshkeyFile):
                    if options.debug:
                     print ("Using SSH key")
                    password = sshkeyFile

                else:
                   print ("SSH key does not exist. Please specify a password. Use -h to show help.")
                   exit(3)


        if (options.mailrecipient != None and options.mailsender == None):
                print("You need to provide a valid mailsender otherwise your mail will like considered spam. Use -h to show help.")
                exit(3)


        # create a random Wifi key
        wifikey = createPassword()
        if options.debug:
         print("Randomly generated Wifikey: ",wifikey)
        # change wifi key and save your old key
        oldkey = changePassword(wifikey,host,ssid,user,password,logging)
        # provision all Unifi access points via API request through the controller
        forceProvision(host,unifi_user_name,unifi_user_password,logging)
        # E-mail notification if set
        if options.mailrecipient != None:
           sendMailwithChanges(oldkey,wifikey,ssid,mailrecipient,mailsender,logging)
