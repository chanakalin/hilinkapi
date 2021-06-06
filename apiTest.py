from HiLinkAPI import webui
import logging
from time import sleep
from datetime import datetime

logging.basicConfig(filename="hilinkapitest.log", format='%(asctime)s --  %(name)s::%(levelname)s -- {%(pathname)s:%(lineno)d} -- %(message)s', level=logging.DEBUG, datefmt="%Y-%m-%d %I:%M:%S %p:%Z")

try:
    webUIArray = [
        webui("E3372h-153", "192.168.18.1", "admin", "admin"),
        webui("E3372h-320", "192.168.19.1"),
        webui("E8372h-320","192.168.10.1","admin","admin"),
        webui("E8372h-155","192.168.11.1","admin","password"),
    ]
    
    for webUI in webUIArray:
        print(f"devicename = {webUI.getDeviceName()}")
        print(f"webui version = {webUI.getWebUIVersion()}")
        print(f"login required = {webUI.getLoginRequired()}")
        print(f"authenticated = {webUI.authenticate()}")
        # Device info
        print("########################################")
        webUI.queryDeviceInfo()
        deviceInfo = webUI.getDeviceInfo()
        for key in deviceInfo.keys():
            if len(key) >= 8:
                print(f"{key}\t:{deviceInfo[key]}")
            else:
                print(f"{key}\t\t:{deviceInfo[key]}")
            
        if webUI.authenticate():
            #############################################
            print("########################################\n")
            webUI.queryNetwork()
            print(f"Network = {webUI.getNetwork()}\n")
            #############################################
            #############################################
            # IP rotation test
            print("############# IP rotation method test ###########")
            #############################################
            # connection on off
            sleep(5)
            print("\n****** Connection on/off ******")
            now = datetime.now()
            dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
            print("\tdate and time = ", dt_string)
            webUI.queryWANIP()
            print(f"\tWAN IP = {webUI.getWANIP()}")
            print(f"\tSwitch connection off = {webUI.switchConnection(False)}")
            sleep(5)
            print(f"\tSwitch connection on = {webUI.switchConnection(True)}")
            webUI.queryWANIP()
            while webUI.getWANIP() is None:
                webUI.queryWANIP()
                sleep(1)
            print(f"\tWAN IP = {webUI.getWANIP()}")
            now = datetime.now()
            dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
            print("\tdate and time = ", dt_string)
            sleep(10)
            #############################################
            # switch LTE/WCDMA
            print("\n****** switch LTE/WCDMA ******")
            now = datetime.now()
            dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
            print("\tdate and time = ", dt_string)
            webUI.queryWANIP()
            print(f"\tWAN IP = {webUI.getWANIP()}")
            print(f"\tSwitch to WCDMA = {webUI.switchLTE(False)}")
            sleep(5)
            print(f"\tSwitch to LTE = {webUI.switchLTE(True)}")
            sleep(1)
            webUI.queryWANIP()
            while webUI.getWANIP() is None:
                webUI.queryWANIP()
            print(f"\tWAN IP = {webUI.getWANIP()}")
            now = datetime.now()
            dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
            print("\tdate and time = ", dt_string)
            sleep(10)
            # reboot
            print("\n****** Rebooting ******")
            webUI.reboot()
            #############################################
            # End
            print("*************************")
        else:
            print("\n\nProvide login credentials")
except Exception as e:
    print(e)
#End of the test
print("\n")
