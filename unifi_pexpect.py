#!/usr/bin/python3
# Developer: Massoud Ahmed
# Visudo
# Cmnd_Alias UNIFI=/usr/bin/systemctl restart unifi.service,/usr/bin/systemcytl restart unifi.service;echo $!,/usr/bin/systemctl --no-pager status unifi.service
# <USER>  ALL=NOPASSWD:UNIFI


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



# Create new password
def createPassword():
 alphabet = string.ascii_letters + string.digits
 wifikey = ''.join(secrets.choice(alphabet) for i in range(12))
 return wifikey


def changePassword(wifikey,host_name,ssid_name,user_name,password,debug):
 sshcommand = "ssh "+user_name+"@"+host_name
 child = pexpect.spawn(sshcommand, encoding='utf-8')
 child.logfile = debug
 key = child.expect([".*assword:",".*Last*."])
 if key == 0:
  child.sendline(password)
  child.expect(".*Welcome*.")

 elif key == 1:
  pass

 child.sendline('mongo 127.0.0.1:27117')
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

 print(oldKey)
 time.sleep(4)

 
 child.sendline('db.wlanconf.update({"name" : "'+ssid_name+'"},{$set: {"x_passphrase" : "'+wifikey+'"}})')
 
 # add fake Wifi SSID
 child.sendline("""db.wlanconf.insert({
        "_id" : ObjectId("6214b3cf8eaf1b01ef8c7e03"),
        "ap_group_ids" : [
                "5fac19fe7a715944f8f8f883"
        ],
        "enabled" : true,
        "fast_roaming_enabled" : false,
        "hide_ssid" : false,
        "name" : "TRIGGERPROVISION",
        "networkconf_id" : "5f061de97a715968dddc25f3",
        "pmf_mode" : "disabled",
        "usergroup_id" : "5f061de97a715968dddc25f4",
        "wlan_bands" : [
                "5g",
                "2g"
        ],
        "wpa_enc" : "ccmp",
        "x_passphrase" : "wechangedwifipassword",
        "wpa3_support" : false,
        "wpa3_transition" : false,
        "wpa3_fast_roaming" : false,
        "wpa3_enhanced_192" : false,
        "group_rekey" : 0,
        "uapsd_enabled" : false,
        "mcastenhance_enabled" : false,
        "no2ghz_oui" : true,
        "bss_transition" : true,
        "proxy_arp" : false,
        "l2_isolation" : false,
        "b_supported" : false,
        "optimize_iot_wifi_connectivity" : true,
        "dtim_mode" : "default",
        "minrate_ng_enabled" : false,
        "minrate_ng_data_rate_kbps" : 1000,
        "minrate_ng_advertising_rates" : false,
        "minrate_na_enabled" : false,
        "minrate_na_data_rate_kbps" : 6000,
        "minrate_na_advertising_rates" : false,
        "mac_filter_enabled" : false,
        "mac_filter_policy" : "allow",
        "mac_filter_list" : [ ],
        "radius_mac_auth_enabled" : false,
        "radius_macacl_format" : "none_lower",
        "security" : "wpapsk",
        "wpa_mode" : "wpa2",
        "schedule_enabled" : false,
        "radius_das_enabled" : false,
        "site_id" : "5f061ddb7a715968dddc25e3",
        "iapp_enabled" : true,
        "x_iapp_key" : "2c3020a669b73e87b96bd836e6d0f94d",
        "dtim_ng" : 1,
        "dtim_na" : 3,
        "dtim_6e" : 3,
        "wlan_band" : "both"
 });
 """)

 time.sleep(5)
 child.sendcontrol('d')
 child.sendline('sudo /usr/bin/systemctl restart unifi.service;echo $?')
 child.expect(".*0*.", timeout=120)
 child.sendline('sudo /usr/bin/systemctl --no-pager status unifi.service')
 time.sleep(45)
 child.expect(".*running*.", timeout=120)
 time.sleep(180)
 child.sendline('mongo 127.0.0.1:27117')
 child.expect(".*MongoDB.*")
 child.sendline('use ace;')
 child.expect(".*ace.*")

# remove Fake Wifi SSID
 child.sendline("""db.wlanconf.remove({
        "_id" : ObjectId("6214b3cf8eaf1b01ef8c7e03"),
        "ap_group_ids" : [
                "5fac19fe7a715944f8f8f883"
        ],
        "enabled" : true,
        "fast_roaming_enabled" : false,
        "hide_ssid" : false,
        "name" : "TRIGGERPROVISION",
        "networkconf_id" : "5f061de97a715968dddc25f3",
        "pmf_mode" : "disabled",
        "usergroup_id" : "5f061de97a715968dddc25f4",
        "wlan_bands" : [
                "5g",
                "2g"
        ],
        "wpa_enc" : "ccmp",
        "x_passphrase" : "wechangedwifipassword",
        "wpa3_support" : false,
        "wpa3_transition" : false,
        "wpa3_fast_roaming" : false,
        "wpa3_enhanced_192" : false,
        "group_rekey" : 0,
        "uapsd_enabled" : false,
        "mcastenhance_enabled" : false,
        "no2ghz_oui" : true,
        "bss_transition" : true,
        "proxy_arp" : false,
        "l2_isolation" : false,
        "b_supported" : false,
        "optimize_iot_wifi_connectivity" : true,
        "dtim_mode" : "default",
        "minrate_ng_enabled" : false,
        "minrate_ng_data_rate_kbps" : 1000,
        "minrate_ng_advertising_rates" : false,
        "minrate_na_enabled" : false,
        "minrate_na_data_rate_kbps" : 6000,
        "minrate_na_advertising_rates" : false,
        "mac_filter_enabled" : false,
        "mac_filter_policy" : "allow",
        "mac_filter_list" : [ ],
        "radius_mac_auth_enabled" : false,
        "radius_macacl_format" : "none_lower",
        "security" : "wpapsk",
        "wpa_mode" : "wpa2",
        "schedule_enabled" : false,
        "radius_das_enabled" : false,
        "site_id" : "5f061ddb7a715968dddc25e3",
        "iapp_enabled" : true,
        "x_iapp_key" : "2c3020a669b73e87b96bd836e6d0f94d",
        "dtim_ng" : 1,
        "dtim_na" : 3,
        "dtim_6e" : 3,
        "wlan_band" : "both"
 });
 """)


 child.expect('.*WriteResult({ "nRemoved" : 1 })*.')
 time.sleep(4)
 child.sendcontrol('d')
 child.sendline('sudo /usr/bin/systemctl restart unifi.service;echo $?')
 child.expect(".*0*.", timeout=120)
 child.sendline('sudo /usr/bin/systemctl --no-pager status unifi.service')
 time.sleep(45)
 child.expect(".*running*.", timeout=120)
 child.close()
 return(oldKey)




def copyWifiKey(oldkey, wifikey, debug):
 login = "python3 /srv/script/core/pwb.py /srv/script/core/scripts/login.py"
 botCommand = "python3 /srv/script/core/pwb.py /srv/script/core/scripts/replace.py -page:WLAN-Zugang "+oldkey+ " "+wifikey
 logout = login+" -logout"
 child = pexpect.spawn(login, encoding='utf-8')
 child.logfile = debug
 time.sleep(5)
 child.expect('.*Logged in*.')
 print("Logged in")
 child.close()
 time.sleep(3)
 child = pexpect.spawn(botCommand, encoding='utf-8')
 child.logfile = debug

 time.sleep(10)
 child.expect('.*make:*.')
 time.sleep(2)
 child.sendline('changed key')
 time.sleep(2)
 child.expect('.*changes*.')
 time.sleep(2)
 child.sendline('y')
 time.sleep(60)
 child.expect('.*successfully*.')
 time.sleep(5)
 child.close()
 child = pexpect.spawn(logout, encoding='utf-8')
 child.logfile = debug
 time.sleep(5)
 child.expect('.*out*.')
 time.sleep(5)
 child.close()


def forceProvision(host,user,password,debug):
 sshcommand = "ssh "+user+"@"+host
 child = pexpect.spawn(sshcommand, encoding='utf-8')
 child.logfile = debug
 key = child.expect([".*assword:",".*Last*."])
 print(key)
 if key == 0:
  child.sendline(password)
  child.expect(".*Welcome*.")

 elif key == 1:
  pass

 child.sendline('/usr/bin/python3 /srv/unifi-force-provisoning.py')
 child.expect('.*Finished*.')
 child.close()
 

 
def sendMailwithChanges(oldkey,wifikey,ssid):

 mailSubject = 'Changed' + ssid +'"'
 mailCommand = "echo \""+ mailBody + "\" | mail -s \"" + mailSubject
 os.system(mailCommand)
 os.system(mailCommandEmployees)
 print("Sending mail to employees")
 

  
 sys.exit(0)

 


 
if __name__ == "__main__":

        desc='''%prog changes Unifi Wifi Password via PExpect and MongoDB '''
        parser = OptionParser(description=desc)
        gen_opts = OptionGroup(parser, "Generic options")
        host_opts = OptionGroup(parser, "Host options")
        ssid_opts = OptionGroup(parser, "SSID options")
        user_opts = OptionGroup(parser, "User options")
        password_opts = OptionGroup(parser, "Password options")
        parser.add_option_group(gen_opts)
        parser.add_option_group(host_opts)
        parser.add_option_group(ssid_opts)
        parser.add_option_group(user_opts)
        parser.add_option_group(password_opts)

        #-d / --debug                                                                                                                                                                                                                                         
        gen_opts.add_option("-d", "--debug", dest="debug", default=False, action="store_true", help="enable debugging outputs (default: no)")

        #-H / --host                                                                                                                                                                                                                                          
        host_opts.add_option("-H", "--host", dest="host", default=None, action="store", metavar="HOST", help="defines the controller hostname or IP")

        #-c / --ssid
        
        ssid_opts.add_option("-S", "--ssid", dest="ssid_name", default=None, action="store", metavar="SSID", help="defines the SSID name (default: none)")

        #-u / --user                                                                                                                                                                                                                                  
        user_opts.add_option("-u", "--user", dest="user_name", default=None, action="store", metavar="USER", help="defines SSH user")

        #-p / --password                                                                                                                                                                                                                                          
        password_opts.add_option("-p", "--password", dest="password", default=None, action="store", metavar="PASSWORD", help="defines SSH password. leave blank if ssh key is available")


        #parse arguments                                                                                                                                                                                                                                     
   
        (options, args) = parser.parse_args()
        host = options.host
        user = options.user_name
        ssid = options.ssid_name
        password = options.password

         #set loggin                                                                                                          
        if options.debug:
          logging = sys.stdout

        else:
          logging = None


        if (options.host) == None:
                print("Please define host IP or hostname")
                exit(3)

        elif (options.ssid_name) == None   and  (options.user_name) == None:
                print("Type -h or --help for options")

        elif (options.password) == None:
                home = str(Path.home())
                sshkeyFile = home+"/.ssh/id_rsa"

                if os.path.isfile(sshkeyFile):
                    print ("Using SSH key")
                    password = sshkeyFile

                else:
                   print ("SSH key does not exist. Please specify a password")
        wifikey = createPassword()
        if options.debug:
         print("Randomly generated Wifikey: ",wifikey)
        oldkey = changePassword(wifikey,host,ssid,user,password,logging)
        copyWifiKey(oldkey, wifikey, logging)
        forceProvision(host,user,password,logging)
        sendMailwithChanges(oldkey,wifikey,ssid)



