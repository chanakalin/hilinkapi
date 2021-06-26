from HiLinkAPI import webui
import logging
from time import sleep, time
from datetime import datetime

logging.basicConfig(filename="hilinkapitest.log", format='%(asctime)s --  %(name)s::%(levelname)s -- {%(pathname)s:%(lineno)d} -- %(message)s', level=logging.DEBUG, datefmt="%Y-%m-%d %I:%M:%S %p:%Z")

try:
    webUIArray = [
         webui("E3372h-153", "192.168.18.1", "admin", "admin", logger=logging),
        # webui("E3372h-320", "192.168.8.1", "admin", "abcd@1234", logger=logging),
        # webui("E8372h-320", "192.168.10.1", "admin", "abcd@1234",logger=logging),
    ]
    
    for webUI in webUIArray:
        try:
            # start
            webUI.start()
            # wait until validate the session
            while not webUI.getValidSession():
                # check for active errors
                if webUI.getActiveError() is not None:
                    error = webUI.getActiveError()
                    print(error)
                    sleep(5)
                # check for login wait time
                if webUI.getLoginWaitTime() > 0:
                    print(f"Login wait time available = {webUI.getLoginWaitTime()} minutes")
                    sleep(5)
            ########
            # Enable data roaming and set max idle time out into 2 hours (7200 seconds)
            webUI.configureDataConnection(True, 7200)
            ########
            # query data  connection
            webUI.queryDataConnection()
            # query device info
            webUI.queryDeviceInfo()
            # query WAN IP
            webUI.queryWANIP()
            # query network name
            webUI.queryNetwork()
            ###################
            #######Call gets###
            print(f"devicename = {webUI.getDeviceName()}")
            print(f"webui version = {webUI.getWebUIVersion()}")
            print(f"login required = {webUI.getLoginRequired()}")
            print(f"valid session = {webUI.validateSession()}")
            print("########################################")
            # session refresh interval
            # webUI.setSessionRefreshInteval(10)
            print(f"Session refresh interval = {webUI.getSessionRefreshInteval()}")
            print("########################################")
            # data connection info
            print("########################################")
            print(f"Data roaming = {webUI.getDataRoaming()}")
            print(f"Max idle time = {webUI.getMaxIdleTime()}")
            print("########################################")
            # set primary and secondary network modes
            netMode = webUI.setNetwokModes("LTE", "WCDMA")
            print(f"Network mode setting = {netMode}")
            print(webUI.getNetwokModes())
            # Device info
            print("########################################")
            deviceInfo = webUI.getDeviceInfo()
            for key in deviceInfo.keys():
                if len(key) >= 8:
                    print(f"{key}\t:{deviceInfo[key]}")
                else:
                    print(f"{key}\t\t:{deviceInfo[key]}")
            #
            print("########################################")
            print(f"Network = {webUI.getNetwork()}")
            print("########################################\n")
            # Connection on off
            print(f"\t{datetime.now()}")
            webUI.queryWANIP()
            print(f"\tWAPN IP = {webUI.getWANIP()}")
            print(f"\tSwitching - Connection off = {webUI.switchConnection(False)}")
            sleep(1)
            print(f"\tSwitching - Connection on = {webUI.switchConnection(True)}")
            webUI.queryWANIP()
            while webUI.getWANIP() is None:
                webUI.queryWANIP()
            print(f"\tWAPN IP = {webUI.getWANIP()}")
            print("")
            # switching LTE / WCDMA
            times = 1
            while times > 0:
                times -= 1
                rotation = open("rotation", 'a')
                print(f"\t{datetime.now()}")
                rotation.write(f"{datetime.now()}\n")
                webUI.queryWANIP()
                print(f"\tWAPN IP = {webUI.getWANIP()}")
                rotation.write(f"WAPN IP = {webUI.getWANIP()}\n")
                status = webUI.switchNetworMode(False)
                print(f"\tSwitching - WCDMA = \t{status}")
                rotation.write(f"Switching - WCDMA = \t{status}\n")
                sleep(1)
                status = webUI.switchNetworMode(True)
                print(f"\tSwitching - LTE = \t{status}")
                rotation.write(f"Switching - LTE = \t{status}\n")
                webUI.queryWANIP()
                while webUI.getWANIP() is None:
                    webUI.queryWANIP()
                print(f"\tWAPN IP = {webUI.getWANIP()}")
                rotation.write(f"WAPN IP = {webUI.getWANIP()}\n")
                print(f"\t{datetime.now()}")
                rotation.write(f"{datetime.now()}\n\n")
                print("\n")
                rotation.close()
                sleep(60)
            # webUI.switchDHCPIPBlock("192.168.8.1")
            
            print("****************************************\n\n")
            ###################
            # stop
            webUI.stop()
            while(not webUI.isStopped()):
                webUI.stop()
                print(f"Waiting for stop")
                sleep(1)
        except Exception as e:
            print(e)
        
except Exception as e:
    print(e)
# End of the test
print("\n")
