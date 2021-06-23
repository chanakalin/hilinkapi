import logging
from threading import Thread
import requests
import xmltodict
import uuid
import base64
import hashlib
import binascii
import hmac
import time
from binascii import hexlify
from collections import OrderedDict
from bs4 import BeautifulSoup
from datetime import datetime


class hilinkException(Exception):
    """
    HiLink API exception
    
    :param    modemname:    Unique name of the modem will be used in raising an exceptions to identify the
                            respective modem
    :param    message:    Error message body for the raising exception
    :type    modemname:    string
    :type    message:    string
    """
    
    def __init__(self, modemname, message):
        self.message = message
        self.modemname = modemname

    def __str__(self):
        return "Huawei HLink API Error ({}) : {}".format(self.modemname, self.message)


class webui(Thread):
    """
    This class facilitate to open, authenticate and operate functions of supported Huawei HiLink modems. 
    
            
    :param    modemname:    A uniquely identifiable name for the modem will useful when debugging or tracing with logs 
    :param    host:    IP address of the modem
    :param    username:     Username if authentication required
    :param    password:     Password if authentication required
    :param    logger:    Logger object if using already configured :class:`logging.Logger`
    :type    url:    string
    :type    host:    string
    :type    username:    string, defaults to None
    :type    password:    string, defaults to None
    :type    logger:    :class:`logging.Logger`, defaults to None
    """
    
    errorCodes = {
        108001: "Wrong username",
        108002: "Wrong password",
        108003: "Already logged in",
        108005: "Too many logins / login attempts",
        108006: "Wrong username or password",
        108007: "Login attempts over run",
        108009: "Login in different devices",
        108010: "Frequency login",
        100002: "System not supported",
        100003: "System has no rights",
        100004: "System busy",
        125001: "Wrong token",
        125002: "Wrong session",
        125003: "Wrong session token",
        }

    def __init__(self, modemname, host, username=None, password=None, logger=None):
        """
        Initialize webui
        """
        self._modemname = modemname
        self._host = host
        # assign empty strings if none
        self._username = username if username is not None else ""
        self._password = password if password is not None else ""
        # initialize logger if not provided
        if logger is None:
            self.logger = logging.getLogger()
        else:
            self.logger = logger
        # build http host URL
        self._httpHost = f"http://{self._host}"
        # timeout for a HTTP call (seconds)
        self._HTTPcallTimeOut = 10
        # variables required for webui session
        self._sessionId = None
        self._RequestVerificationToken = None
        # Authenticaion required or not
        self._loginRequired = False
        #### WebUI variables####
        self._sessionId = None
        self._RequestVerificationToken = None
        self._deviceClassify = None
        self._deviceName = None
        self._loginState = False  # Logged in to the session or not
        self._webuiversion = None  # Has to be 10 or 17/21
        # in an operation or not
        self._inOperation = False
        #session refresh interval in seconds
        self._sessionRefreshInterval = 10
        # session refreshed after an operation
        self._sessionRefreshed = False
        # Last operation ended time
        self._lastOperationEndedTime = None
        # valid session or not (not logged in)
        self._validSession = False
        # login wait time
        self._loginWaitTime = 0
        # active error code
        self._activeErrorCode = 0
        # initialize thread stop
        self._stopped = True
        # thread stopped
        self._isStopped = True
        # network modes
        #LTE=3, WCDMA=2, GSM=1 network modes
        self._netModePrimary = 3
        self._netModeSecondary = 2
        ###############################
        # device info
        self._deviceName = None
        self._imei = None
        self._serial = None
        self._imsi = None
        self._iccid = None
        self._supportedModes = None
        self._hwversion = None
        self._swversion = None
        self._webui = None
        # connection info
        self._workmode = None
        self._wanIP = None
        self._networkName = None
        ######### Initialize ###########
        
    def start(self):
        """
        This method will start the thread. 
        """
        # initialize variables and webui
        self._stopped = False
        self._isStopped = False
        self.initialize()
        # Thread start
        Thread.start(self)
        
    def stop(self):
        """
        This method will initialize thread stop. 
        """
        self._stopped = True
    
    def isStopped(self):
        """
        This method will return successfully stopped or not. 
        
        :return:    Return deinited or not
        :rtype:    boolean
        """
        return self._isStopped
        
    def setCredentials(self, username, password):
        """
        This method will set/update username and password for authentication after initializing. 
        
        :param    username:     Username if authentication required
        :param    password:     Password if authentication required
        :type    username:    string, defaults to None
        :type    password:    string, defaults to None
        """
        self._username = username
        self._password = password
        
    def processHTTPHeaders(self, response):
        """
        This method will retrieve *SessionID* from cookies and *__RequestVerificationToken* from HTTP headers.
        This method has to be called after each :class:`requests.get` or :class:`requests.post` as mismatch with *SessionID*
        or *__RequestVerificationToken* between API(webui) and HTTP request call leading to return errors in API calls.
        
        :param    response:    Response object from :class:`requests.get` or :class:`requests.post`
        :type    response:    :class:`requests.Response`
        """
        if 'SessionID' in response.cookies:
            self._sessionId = response.cookies['SessionID']
            self.logger.debug(f"Updating SessionID = {self._sessionId}")
            
        headers = OrderedDict(response.headers)
        if '__RequestVerificationToken' in headers:
            self.logger.debug("Updating RequestVerificationToken = {}".format(self._RequestVerificationToken))
            self._RequestVerificationToken = None
            self._RequestVerificationToken = headers['__RequestVerificationToken'].split("#")[0]
            self.logger.debug("Updated RequestVerificationToken to = {}".format(self._RequestVerificationToken))
    
    def buildCookies(self):
        """
        This method will build a dictionary object containing *SessionID* which is provided as cookies to HTTP requests.
        Each call of :meth:`~httpGet` and :meth:`~httpPost` will generate default cookies set if cookies not provided in parameters.
        
        :return:    Return a dictionary containing cookies 
        :rtype:    dictionary
        """
        cookies = None
        if self._sessionId:
            cookies = {
                'SessionID': self._sessionId
            }
        # return
        return cookies
    
    def httpGet(self, endpoint, cookies=None, headers=None):
        """
        Call an API end point using a HTTP GET request. If :attr:`cookies` are not provided (when defaulted to None) will build cookies
        by calling :meth:`~buildCookies`.
        At the end of each call :meth:`~processHTTPHeaders` will call to retrieve *SessionID* and *__RequestVerificationToken*.

        :param    endpoint:    API end point (eg:- /api/device/information)
        :param    cookies:     cookies, defaults to None
        :param    headers:     HTTP headers, defaults to None
        :type    endpoint:    string
        :type    postBody:    string
        :type    cookies:    dictionary
        :type    headers:    dictionary
        :return:    Return the HTTP response as a requests.Response
        :rtype:    :class:`requests.Response`
        """
        if(cookies == None):
            cookies = self.buildCookies()
        # request
        try:
            _response = requests.get(f"{self._httpHost}{endpoint}", cookies=cookies, timeout=self._HTTPcallTimeOut)
            self.processHTTPHeaders(_response)
            return _response
        except Exception as e:
            self.logger.error(e)
            raise hilinkException(self._modemname, f"Calling {self._httpHost}{endpoint} failed")
    
    def httpPost(self, endpoint, postBody, cookies=None, headers=None):
        """
        Call an API end point using a HTTP POST request. If :attr:`cookies` are not provided (when defaulted to None) will build cookies
        by calling :meth:`~buildCookies`.
        At the end of each call :meth:`~processHTTPHeaders` will call to retrieve *SessionID* and *__RequestVerificationToken*.

        :param    endpoint:    API end point (eg:- /api/user/authentication_login)
        :param    postBody:    HTTP body
        :param    cookies:     cookies
        :param    headers:     HTTP headers
        :type    endpoint:    string
        :type    postBody:    string
        :type    cookies:    dictionary
        :type    headers:    dictionary
        :return:    Return the HTTP response as a requests.Response
        :rtype:    :class:`requests.Response`
        """
        if(cookies == None):
            cookies = self.buildCookies()
        # request
        try:
            _response = requests.post(f"{self._httpHost}{endpoint}", data=postBody, cookies=cookies, headers=headers, timeout=self._HTTPcallTimeOut)
            self.processHTTPHeaders(_response)
            return  _response
        except Exception as e:
            self.logger.error(e)
            raise hilinkException(self._modemname, f"Calling {self._httpHost}{endpoint} failed")
        
    def initialize(self):
        """      
        Calling this method will initialize API calls by
        
        * Initialize session and fetch *SessionID*
        * Request initial *__RequestVerificationToken*
        * Query authentication required or not
        * Identify webUI version
        
        """
        self._sessionId = None
        self._RequestVerificationToken = None
        self._webuiversion = None
        self._deviceClassify = None
        self._deviceName = None
        # Initialize session
        self.httpGet(endpoint="/")
        # get request verification token
        # first webUI 10 or 21
        try:
            self.logger.debug(f"Trying for webUI version 10")
            response = self.httpGet("/api/webserver/token")
            tokenJson = xmltodict.parse(response.text)
            if "response" in tokenJson:
                loginToken = tokenJson['response']['token']
                self.logger.debug(f"Got new loginToken = {tokenJson}")
                size = len(loginToken)
                self._RequestVerificationToken = loginToken[(size - 32):(size)]
                self.logger.debug(f"Got new RequestVerificationToken = {self._RequestVerificationToken}")
                # set supporting webUI version is 10 as default
                self._webuiversion = 10
                # check if it's 21
                response = self.httpGet("/api/device/basic_information")
                tokenJson21Check = xmltodict.parse(response.text)
                if "response" in tokenJson21Check:  # valid response
                    if "WebUIVersion" in tokenJson21Check["response"]:
                        if "21." in tokenJson21Check["response"]["WebUIVersion"]:
                            self._webuiversion = 21
        except:
            self._RequestVerificationToken = None
            self._webuiversion = None
        # If haven't fetched try for webUI version 17
        if self._RequestVerificationToken is None:
            self.logger.debug(f"Trying for webUI version 17")
            response = self.httpGet("/html/home.html")
            soup = BeautifulSoup(response.text, "html.parser")
            meta = soup.head.meta
            if meta is not None:
                self._RequestVerificationToken = meta.get("content", None)
                self.logger.debug(f"Got new RequestVerificationToken = {self._RequestVerificationToken}")
            if self._RequestVerificationToken is None:
                raise hilinkException(self._modemname, "Failed to get a request verification token")
            else:
                self._webuiversion = 17
        # End of request verification token fetching and webUI version
        self.logger.info(f"Huawei webUI version = {self._webuiversion}")
        ###############################################################
        # Get basic device info
        try:
            headers = {'X-Requested-With':'XMLHttpRequest'}
            response = self.httpGet("/api/device/basic_information", headers=headers)
            deviceInfo = xmltodict.parse(response.text)
            if "response" in deviceInfo:
                self._deviceClassify = deviceInfo['response']['classify']
                self._deviceName = deviceInfo['response']['devicename']
            else:
                self.sessionErrorCheck(deviceInfo)
                raise hilinkException(self._modemname, "Failed to get device info")
        except Exception as e:
            self.logger.error(e)
            raise hilinkException(self._modemname, "Failed to get device info")
        ###############################################################
        ################## Authentication required check ##############
        # common API endpoint for webui version 10,17 & 21
        try:
            response = self.httpGet("/api/user/hilink_login")
            hilinkLogin = xmltodict.parse(response.text)
            if "response" in hilinkLogin:
                if int(hilinkLogin['response']['hilink_login']) == 0:
                    # wingles always comes with authentication even hilink_login==0
                    if str(self._deviceClassify).upper() == "WINGLE":
                        self._loginRequired = True
                    else:
                        self._loginRequired = False
                elif int(hilinkLogin['response']['hilink_login']) == 1:
                    self._loginRequired = True
            else:
                self.sessionErrorCheck(hilinkLogin)
                raise hilinkException(self._modemname, "Invalid response while getting user hilink state")
        except Exception as e:
            self.logger.error(e)
            raise hilinkException(self._modemname, "Failed to get user login state")   
        #############Authentication required check end#################
        # Initialize the thread
        Thread.__init__(self)
        
    def sessionErrorCheck(self, responseDict):
        """
        This method will use to validate error responses
        """
        self.logger.error(responseDict)
        # check for errors & if exist set as active error code
        if "error" in responseDict:
            try:
                self._activeErrorCode = int(responseDict["error"]["code"])
                if self._activeErrorCode in self.errorCodes:
                    self.logger.error(f"{self._activeErrorCode} -- {self.errorCodes[self._activeErrorCode]}")
                else:
                    self.logger.error(f"Unidentified error code - {self._activeErrorCode}")
            except Exception as e:
                self.logger.error("Error code extraction failed")
                self.logger.error(e)
                
    def resetActiveErrorCode(self):
        """
        This method will reset active error code
        """
        self._activeErrorCode = 0
        
    def login_b64_sha256(self, data):
        """
        This method will used to SHA256 hashing and base64 encoding for WebUI version 10.x.x authentication in :meth:`~login_WebUI10`.
        
        :param    data:    Data to hash and encode
        :type    data:    string
        :return:    Return hashed and encoded data string
        :rtype:    string
        """
        s256 = hashlib.sha256()
        s256.update(data.encode('utf-8'))
        dg = s256.digest()
        hs256 = binascii.hexlify(dg)
        return base64.urlsafe_b64encode(hs256).decode('utf-8', 'ignore')
    
    def validateSession(self):
        """
        This method will validate session
        
        * Check if a valid authenticated session
        * If authentication required will login
        
        :return:    Return valid session or not
        :rtype:    boolean
        """
        # wait if in an operation
        while self._inOperation:
            time.sleep(0.5)
            #******fine tune the wait******
        # update in an operation
        self._inOperation = True
        #####################################
        ######### Login state check #########
        response = self.httpGet("/api/user/state-login")
        stateLogin = xmltodict.parse(response.text)
        if "response" in stateLogin:
            self._loginState = True if int(stateLogin['response']['State']) == 0 else False
            self._passwordType = stateLogin['response']['password_type']
            self._loginWaitTime = int(stateLogin['response']['remainwaittime']) if 'remainwaittime' in stateLogin['response'] else 0
            # in response lockstatus=1 if locked
            # update active error code if has a login wait time
            if self._loginWaitTime > 0:
                self._activeErrorCode = 108007
        else:
            self.logger.error("Invalid response while getting user login state")
        ###### Login state check end ########
        #####################################
        ###### Login if required ############
        # In webui 10 self._loginState is -1 even login not enabled so hilink_state check is also required
        # print(f"Login required = {self._loginRequired} \t LoginState = {self._loginState} \t time = {datetime.now()}")
        if not self._loginState and self._loginRequired:
            # check for login wait time
            if self._loginWaitTime <= 0:
                # invalidate session
                self._validSession = False
                # check username and password have provided
                if self._username is not None and self._password is not None:
                    # login for webui 17 & 21
                    if self._webuiversion in (17, 21):
                        self.logger.debug(f"Login initiated fot WebUI version 17 & 21")
                        self.logger.debug(f"Having session ID = {self._sessionId}")
                        self.logger.debug(f"Having request verification token = {self._RequestVerificationToken}")
                        # generate password value
                        # base64encode(SHA256(name + base64encode(SHA256($('#password').val())) + g_requestVerificationToken[0]));
                        passwd_string = f"{self._password}"
                        s256 = hashlib.sha256()
                        s256.update(passwd_string.encode('utf-8'))
                        dg = s256.digest()
                        hs256 = binascii.hexlify(dg)
                        hassed_password = base64.urlsafe_b64encode(hs256).decode('utf-8', 'ignore')
                        s2562 = hashlib.sha256()
                        s2562.update(f"{self._username}{hassed_password}{self._RequestVerificationToken}".encode('utf-8'))
                        dg2 = s2562.digest()
                        hs2562 = binascii.hexlify(dg2)
                        hashed_username_password = base64.urlsafe_b64encode(hs2562).decode('utf-8', 'ignore')
                        xml_body = f"""
                        <?xml version="1.0" encoding="UTF-8"?>
                        <request>
                        <Username>{self._username}</Username>
                        <Password>{hashed_username_password}</Password>
                        <password_type>{self._passwordType}</password_type>
                        </request>
                        """.replace("b\'", "").replace("\'", "")
                        # challenge headers
                        headers = {
                            'X-Requested-With':'XMLHttpRequest',
                            '__RequestVerificationToken': self._RequestVerificationToken
                            }
                        # challenge_login
                        response = self.httpPost("/api/user/login", xml_body, cookies=None, headers=headers)
                        loginResponse = xmltodict.parse(response.text)
                        # validate login & session
                        if "response" in loginResponse:
                            if loginResponse['response'] == "OK":
                                self._validSession = True
                                # reset if theres any active error
                                self.resetActiveErrorCode()
                            else:
                                self.sessionErrorCheck(loginResponse)
                                self.logger.error(f"Login failed -- {response.text}")
                        else:
                            self.logger.error(f"Login failed -- {response.text}")
                        # validate login & session end
                    # else webui 10 login as default
                    else:
                        # login to webui 10
                        self.logger.debug(f"Login initiated fot WebUI version 10")
                        # grab the verification token
                        self.logger.debug("Querying for token")
                        response = self.httpGet("/api/webserver/token")
                        tokenJson = xmltodict.parse(response.text)
                        self.logger.debug(response.text)
                        if "response" in tokenJson:
                            _tmpToken = tokenJson['response']['token']
                            self._RequestVerificationToken = _tmpToken[len(_tmpToken) - 32:len(_tmpToken)] 
                        # log
                        self.logger.debug(f"Having session ID = {self._sessionId}")
                        self.logger.debug(f"Having request verification token = {self._RequestVerificationToken}")
                        # generate password value
                        password_value = self.login_b64_sha256(self._username + self.login_b64_sha256(self._password) + self._RequestVerificationToken)
                        # challenge login
                        client_nonce = uuid.uuid4().hex + uuid.uuid4().hex
                        # generate request XML body
                        xml_body = """
                        <?xml version="1.0" encoding="UTF-8"?>
                        <request>
                        <username>{}</username>
                        <firstnonce>{}</firstnonce>
                        <mode>1</mode>
                        </request>
                        """.format(self._username, client_nonce)
                        # challenge headers
                        headers = {
                            'X-Requested-With':'XMLHttpRequest',
                            '__RequestVerificationToken': self._RequestVerificationToken
                            }
                        # challenge_login
                        response = self.httpPost("/api/user/challenge_login", xml_body, cookies=None, headers=headers)
                        challangeDict = xmltodict.parse(response.text)
                        self.logger.debug("Login challangeDict")
                        # check for response
                        if 'response' in challangeDict:
                            salt = challangeDict['response']['salt']
                            server_nonce = challangeDict['response']['servernonce']
                            iterations = int(challangeDict['response']['iterations'])
                            # authenticate login
                            msg = "%s,%s,%s" % (client_nonce, server_nonce, server_nonce)
                            salted_pass = hashlib.pbkdf2_hmac('sha256', bytearray(self._password.encode('utf-8')), bytearray.fromhex(salt), iterations)
                            client_key = hmac.new(b'Client Key', msg=salted_pass, digestmod=hashlib.sha256)
                            stored_key = hashlib.sha256()
                            stored_key.update(client_key.digest())
                            signature = hmac.new(msg.encode('utf_8'), msg=stored_key.digest(), digestmod=hashlib.sha256)
                            client_key_digest = client_key.digest()
                            signature_digest = signature.digest()
                            client_proof = bytearray()
                            i = 0
                            while i < client_key.digest_size:
                                val = ord(client_key_digest[i:i + 1]) ^ ord(signature_digest[i:i + 1])
                                client_proof.append(val)
                                i = i + 1
                            HexClientProof = hexlify(client_proof)
                            xml_body = """
                            <?xml version="1.0" encoding="UTF-8"?>
                            <request>
                            <clientproof>{}</clientproof>
                            <finalnonce>{}</finalnonce>
                            </request>
                            """.format(HexClientProof, server_nonce).replace("b\'", "").replace("\'", "")
                            # login headers
                            headers = {
                                'X-Requested-With':'XMLHttpRequest',
                                '__RequestVerificationToken': self._RequestVerificationToken
                                }
                            response = self.httpPost("/api/user/authentication_login", xml_body, cookies=None, headers=headers)
                            loginResponse = xmltodict.parse(response.text)
                            # validate login & session
                            if "response" in loginResponse:
                                self._validSession = True
                                # reset if theres any active error
                                self.resetActiveErrorCode()
                            else:
                                self.sessionErrorCheck(loginResponse)
                                self.logger.error(f"Login failed -- {response.text}")
                        else:
                            self.sessionErrorCheck(challangeDict)
                            self.logger.error("Invalid response for Login challageDict")
                else:
                    self.logger.error("Username & password are mandatory")
            # login waittime is available have to wait
            else:
                self.logger.error(f"Login wait time is available {self._loginWaitTime} minutes")
        # login not required
        else:
            # validate session
            self._validSession = True
        ##############################
        # update in an operation
        self._inOperation = False
        # update session refreshed
        self._sessionRefreshed = True
        # return session validation
        return self._validSession
    
    def run(self):
        """      
        This is the overriding method for :class:threading.Thread.run()
        
        * Check login state of the session
        * Perform login when required
        
        """
        #init session refreshed
        self._lastSessionRefreshed = 0
        #set default stopped into false
        self._isStopped = False
        # if not stop initialized
        while not self._stopped:
            if time.time() >= (self._lastSessionRefreshed + self.getSessionRefreshInteval())
                #validate session
                self.validateSession()
                #reset last session refreshed
                self._lastSessionRefreshed = time.time()
            #0.5 second delay in loop
            time.sleep(0.5)
            ####### Loop delay ###########
        # stopping completed
        self._isStopped = True
        
    ####################################################
    ###################### Query methods ###############
    ####################################################
        
    def queryDeviceInfo(self):
        """
        This method will query device information and update existing.
        
        If session need a refresh :meth:`~validateSession` before calling device information API end point.
        
        :return:   Return querying device info succeed or not
        :rtype:    boolean
        """
        # if session is not refreshed validate and refresh session again
        if not self._sessionRefreshed:
            self.validateSession()
        # wait if in an operation
        while self._inOperation:
            time.sleep(0.5)            
        # if session is valid query device info
        if self._validSession:
            try:
                ######### query device info ##########
                headers = {'X-Requested-With':'XMLHttpRequest'}
                response = self.httpGet("/api/device/information", headers=headers)
                deviceInfo = xmltodict.parse(response.text)
                if "response" in deviceInfo:
                    self._deviceClassify = deviceInfo['response']['Classify']
                    self._deviceName = deviceInfo['response']['DeviceName']
                    self._workmode = deviceInfo['response']['workmode']
                    if "Imei" in deviceInfo['response']:
                        self._imei = deviceInfo['response']['Imei']
                    if "SerialNumber" in deviceInfo['response']:
                        self._serial = deviceInfo['response']['SerialNumber']
                    if "Imsi" in deviceInfo['response']:
                        self._imsi = deviceInfo['response']['Imsi']
                    if "Iccid" in deviceInfo['response']:
                        self._iccid = deviceInfo['response']['Iccid']
                    if "supportmode" in deviceInfo['response']:
                        try:
                            self._supportedModes = deviceInfo['response']['supportmode'].split("|")
                        except:
                            self._supportedModes = []
                    if "HardwareVersion" in deviceInfo['response']:
                        self._hwversion = deviceInfo['response']['HardwareVersion']
                    if "SoftwareVersion" in deviceInfo['response']:
                        self._swversion = deviceInfo['response']['SoftwareVersion']
                    if "WebUIVersion" in deviceInfo['response']:
                        self._webui = deviceInfo['response']['WebUIVersion']
                    # invalidate refresh
                    self._sessionRefreshed = False
                    # reset if theres any active error
                    self.resetActiveErrorCode()
                    # return success
                    return True
                else:
                    self.sessionErrorCheck(deviceInfo)
                    self._sessionRefreshed = False
                    return False
                ####### query device info end ########
            except Exception as e:
                # invalidate refresh
                self._sessionRefreshed = False
                self.logger.error(e)
                self.logger.error(f"{self._modemname} Failed to get device info")
                return False
        else:
            # invalidate refresh
            self._sessionRefreshed = False
            self.logger.error(f"{self._modemname} Failed to get device info")
            return False
        
    def querySupportedNetworkMethods(self):
        """
        This method will query supported network modes
        
        If session need a refresh :meth:`~validateSession` before calling device information API end point.
        
        :return:   Return querying supported network modes succeeded or not
        :rtype:    boolean
        """
        # if session is not refreshed validate and refresh session again
        if not self._sessionRefreshed:
            self.validateSession()
        # wait if in an operation
        while self._inOperation:
            time.sleep(0.5)            
        # if session is valid query wan ip info
        if self._validSession:
            #### Query supported network modes ####
            headers = {'X-Requested-With':'XMLHttpRequest'}
            response = self.httpGet("/config/network/networkmode.xml", headers=headers)
            supportedNetModes = xmltodict.parse(response.text)
            print(response.text)
            #print(supportedNetModes)
        else:
            # invalidate refresh
            self._sessionRefreshed = False
            self.logger.error(f"{self._modemname} Failed to get supported network modes")
            return False
        

    def queryWANIP(self):
        """
        This method will query WAN IP from the carrier network and update existing.
        
        If session need a refresh :meth:`~validateSession`  before calling device information API end point.
        
        Separate API end points will be called as per the WebUI version.
        
        :return:   Return querying WAN IP succeed or not
        :rtype:    boolean
        """
        # if session is not refreshed validate and refresh session again
        if not self._sessionRefreshed:
            self.validateSession()
        # wait if in an operation
        while self._inOperation:
            time.sleep(0.5)            
        # if session is valid query wan ip info
        if self._validSession:
            # Make WAN IP None
            self._wanIP = None
            try:
                ######### query WAN IP info ##########
                headers = {'X-Requested-With':'XMLHttpRequest'}
                # API endpoint is defer relavant to webui version
                if self._webuiversion in (10, 21):
                    wanIPAPIEndPoint = "/api/device/information"
                else:  # webui version 17
                    wanIPAPIEndPoint = "/api/monitoring/status"
                response = self.httpGet(wanIPAPIEndPoint, headers=headers)
                wanIPInfo = xmltodict.parse(response.text)
                if "response" in wanIPInfo:
                    if "WanIPAddress" in wanIPInfo['response']:
                        self._wanIP = wanIPInfo['response']['WanIPAddress']
                    # invalidate refresh
                    self._sessionRefreshed = False
                    # reset if theres any active error
                    self.resetActiveErrorCode()
                    # return success
                    return True
                else:
                    self.sessionErrorCheck(wanIPInfo)
                    self._sessionRefreshed = False
                    return False
                ####### query WAN IP info end ########
            except Exception as e:
                # invalidate refresh
                self._sessionRefreshed = False
                self.logger.error(e)
                self.logger.error(f"{self._modemname} Failed to get WAN IP info")
                return False
        else:
            # invalidate refresh
            self._sessionRefreshed = False
            self.logger.error(f"{self._modemname} Failed to get WAN IP info")
            return False
        
    def queryNetwork(self):
        """
        This method will query network name of the carrier network and update existing.
        
        If session need a refresh :meth:`~validateSession` before calling device information API end point.
        
        :return:   Return querying network succeed or not
        :rtype:    boolean
        """
        # if session is not refreshed validate and refresh session again
        if not self._sessionRefreshed:
            self.validateSession()
        # wait if in an operation
        while self._inOperation:
            time.sleep(0.5)            
        # if session is valid query network info
        if self._validSession:
            try:
                headers = {'X-Requested-With':'XMLHttpRequest'}
                response = self.httpGet("/api/net/current-plmn", headers=headers)
                connectionInfo = xmltodict.parse(response.text)
                if "response" in connectionInfo:
                    self._networkName = connectionInfo["response"]["FullName"]
                else:
                    self.sessionErrorCheck(connectionInfo)
                    self._sessionRefreshed = False
                # invalidate refresh
                self._sessionRefreshed = False
                # reset if theres any active error
                self.resetActiveErrorCode()
                # return success
                return True
                ####### query network info end ########
            except Exception as e:
                # invalidate refresh
                self._sessionRefreshed = False
                self.logger.error(e)
                self.logger.error(f"{self._modemname} Failed to get Network info")
                return False
        else:
            # invalidate refresh
            self._sessionRefreshed = False
            self.logger.error(f"{self._modemname} Failed to get Network info")
            return False
        
    ###################################################
    ################# Set methods #####################
    def setNetwokModes(self,primary="LTE",secondary="WCDMA"):
        """
        Set primary and secondary network modes respectively with :attr:`primary` and  :attr:`secondary`.
        
        :param    primary:    Either "LTE","WCDMA" or "GSM" as primary network mode        
        :param    secondary:    Either "LTE","WCDMA" or "GSM" as secondary network mode
        :type    primary:    String
        :type    secondary:    String
                        
        :return:   Return network mode configuration success or not
        :rtype:    bool
        """
        modes = {"LTE":3,"WCDMA":2,"GSM":1,"AUTO":0}
        #primary
        if primary in modes:
            self._netModePrimary = modes[primary]
        else:
            return False
        #secondary
        if secondary in modes:
            self._netModeSecondary = modes[secondary]
        else:
            return False
        #if both went fine return True as success
        return True
    
    def setSessionRefreshInteval(self,interval):
        """
        This method will set the session refresh interval while in idle without any operation.  
        
        :param    interval:    Session refresh interval in seconds     
        :type    interval:    int
        """
        self._sessionRefreshInterval = interval
        
    ###################################################
    ################# Get methods #####################
    ###################################################
    def getLoginRequired(self):
        """
        This method will return either login/authentication required or not which will be updated after calling
        :meth:`~initialize`.
        
        :return:   Return login required or not
        :rtype:    bool
        """
        return self._loginRequired
    
    def getWebUIVersion(self):
        """
        This method will return WebUI version either *10*, *17* or *21*.
        
        :return:   Return WebUI version
        :rtype:    int    
        """
        return self._webuiversion
    
    def getValidSession(self):
        """
        This method will return if the session is valid for querying and operations or not
        
        :return:   Return a valid session or not
        :rtype:    boolean    
        """
        return self._validSession
    
    def getSessionRefreshInteval(self):
        """
        This method will return the session refresh interval while in idle without any operation.
        Use :meth:`~setSessionRefreshInteval`
       
        :return:   Session refresh interval in seconds 
        :rtype:    int
        """
        self._sessionRefreshInterval = interval
    
    def getActiveError(self):
        """
        This method will return if theres any active error code else none
        
        :return:   Return {"errorcode":<code>,"error":"<error message>"}
        :rtype:    dictionary    
        """
        
        error = None
        if self._activeErrorCode > 0:
            if self._activeErrorCode in self.errorCodes:
                error = {
                    "errorcode":self._activeErrorCode,
                    "error":self.errorCodes[self._activeErrorCode]
                }
            else:
                error = {
                    "errorcode":self._activeErrorCode,
                    "error":"Un-identified"
                }
        ###########
        return error

    def getLoginWaitTime(self):
        """
        This method will return waittime for next login attemp 
        
        If session need a refresh :meth:`~validateSession` before calling device information API end point.
        
        :return:   Login wait time
        :rtype:    int
        """
        return self._loginWaitTime

    def getDeviceName(self):
        """
        This method will return the device name *(model)* from API end point */api/device/information*.
        
        :return:   Return device name
        :rtype:    string
        """
        return self._deviceName
    
    def getDeviceInfo(self):
        """
        This method will return following device info as a dictionary.
        
        These information have get update by calling :meth:`~queryDeviceInfo` (Required only one time as these are constants)
        
        #. *devicename* - Device name
        #. *serial* - Modem serial number
        #. *imei* - IMEI number of the modem
        #. *imsi* - IMSI number
        #. *iccid* - ICCID of the SIM
        #. *modes* - Supported network modes (LTE,WCDMA,GSM)
        #. *hwversion* - Hardware version of the modem
        #. *swversion* - Software version of the modem
        #. *webui* - WebUI version of the modem
        
        :return:   Device information as a dictionary
        :rtype:    dictionary
        """
        return {
            "devicename":self._deviceName,
            "serial":self._serial,
            "imei":self._imei,
            "imsi":self._imsi,
            "iccid":self._iccid,
            "modes":self._supportedModes,
            "workmode":self._workmode,
            "hwversion":self._hwversion,
            "swversion":self._swversion,
            "webui":self._webui
        }
    
    def getWANIP(self):
        """
        This method will return the WAN IP.
        
        WAN IP can update by calling :meth:`~queryWANIP` and call this when after a possible WAN IP change like,
        
        #. Connection switch on/off event after calling :meth:`~switchConnection`.
        #. Switching between LTE and WCDMA even after calling :meth:`~switchLTE`. 
        
        :return:   Return WAN IP
        :rtype:    string
        """
        return self._wanIP
    
    def getNetwork(self):
        """
        This method will return the name of Carrier Network.
        
        Carrier Network name can update by calling :meth:`~queryNetwork` and required only to call one time after the first 
        time after a possible WAN IP change like,
        
        #. Connection switch on/off event after calling :meth:`~switchConnection`.
        #. Switching between LTE and WCDMA even after calling :meth:`~switchLTE`. 
        
        :return:   Return network name
        :rtype:    string
        """
        return self._networkName
    
    def getWorkmode(self):
        """
        This method will return the work mode.
        
       Mandatory to update by device work mode by calling :meth:`~queryDeviceInfo` prior to call this method
        
        :return:   Return network name
        :rtype:    string
        """
        return self._networkName
    
    def getNetwokModes(self):
        """
        Get primary and secondary network modes
                        
        :return:   {"primary":<<Primary networn mode>>,"secondary":<<Secondary networn mode>>}
        :rtype:    dictionary 
        """
        modes = {3:"LTE",2:"WCDMA",1:"GSM",0:"AUTO"}
        return {"primary":modes[self._netModePrimary],"secondary":modes[self._netModeSecondary]}
    
    #########################################
    ######## Connection manage ##############
    #########################################
    def switchConnection(self, status=True):
        """
        Switch on or off data connection based on :attr:`status`.
        
        :param    status:    Either set status of the connection On or Off
        :type    status:    bool
                        
        :return:   Return either requested connection switching succeeded or failed
        :rtype:    bool
        """
        # if session is not refreshed validate and refresh session again
        if not self._sessionRefreshed:
            self.validateSession()
        # wait if in an operation
        while self._inOperation:
            time.sleep(0.5)            
        # if session is valid start switching data connection
        if self._validSession:
            try:
                # data switch
                dataSwitch = "1" if status else "0"
                xml_body = f"""
                <?xml version="1.0" encoding="UTF-8"?>
                <request>
                <dataswitch>{dataSwitch}</dataswitch>
                </request>
                """
                headers = {
                'X-Requested-With':'XMLHttpRequest',
                '__RequestVerificationToken': self._RequestVerificationToken
                }
                # call switch
                self.logger.info(f"Switching data connection status = {dataSwitch}")
                response = self.httpPost("/api/dialup/mobile-dataswitch", xml_body, cookies=None, headers=headers)
                dataswitchInfo = xmltodict.parse(response.text)
                if "response" in dataswitchInfo:
                    self.logger.info(f"Switched data connection status = {dataSwitch}")
                    # invalidate refresh
                    self._sessionRefreshed = False
                    # reset if theres any active error
                    self.resetActiveErrorCode()
                    # return success
                    return True
                else:
                    self._sessionRefreshed = False
                    self.sessionErrorCheck(dataswitchInfo)
                    self.logger.error(f"Switching data connection to status = {dataSwitch} failed")
                    # Return failed
                    return False
                ####### switching data connection end ########
            except Exception as e:
                # invalidate refresh
                self._sessionRefreshed = False
                self.logger.error(e)
                self.logger.error(f"{self._modemname} Failed to switch data connection")
                return False
        else:
            # invalidate refresh
            self._sessionRefreshed = False
            self.logger.error(f"{self._modemname} Failed to switch connection")
            return False
        
    def switchNetworMode(self, primary=True):
        """
        Switch network between primary and secondary network modes based on :attr:`primary`.
        If :attr:`primary` is **True** network mode switch to the primary or else to the secondary.
        
        Primary network mode and secondary network mode can be set using :meth:`~setNetwokModes` 
        
        :param    primary:    Primary network mode or secondary network mode
        :type    primary:    bool
                        
        :return:   Return either requested network mode switching succeeded or failed
        :rtype:    bool
        """
        # if session is not refreshed validate and refresh session again
        if not self._sessionRefreshed:
            self.validateSession()
        # wait if in an operation
        while self._inOperation:
            time.sleep(0.5)            
        # if session is valid start switching network mode
        if self._validSession:
            try:
                # decide network mode
                # http://192.168.10.1/config/network/networkmode.xml
                # 0=auto 1=2G 2=3G 3=4G
                NetworkMode = self._netModePrimary if primary else self._netModeSecondary
                NetworkBand = ""
                LTEBand = ""
                # fetch LTE bands
                headers = {'X-Requested-With':'XMLHttpRequest'}
                response = self.httpGet("/api/net/net-mode", headers=headers)
                netModeInfo = xmltodict.parse(response.text)
                if "response" in netModeInfo:
                    NetworkBand = netModeInfo['response']['NetworkBand']
                    LTEBand = netModeInfo['response']['LTEBand']
                    # proceed switching
                    xml_body = f"""
                    <?xml version="1.0" encoding="UTF-8"?>
                    <request>
                    <NetworkMode>0{NetworkMode}</NetworkMode>
                    <NetworkBand>{NetworkBand}</NetworkBand>
                    <LTEBand>{LTEBand}</LTEBand>
                    </request>
                    """
                    headers = {
                    'X-Requested-With':'XMLHttpRequest',
                    '__RequestVerificationToken': self._RequestVerificationToken
                    }
                    self.logger.info(f"Switching network mode = 0{NetworkMode} - NetworkBand={NetworkBand} LTEBand-{LTEBand}")
                    response = self.httpPost("/api/net/net-mode", xml_body, cookies=None, headers=headers)
                    netmodeSwitchInfo = xmltodict.parse(response.text)
                    if "response" in netmodeSwitchInfo:
                        self.logger.info(f"Switched network mode = 0{NetworkMode} - NetworkBand={NetworkBand} LTEBand-{LTEBand}")
                        # invalidate refresh
                        self._sessionRefreshed = False
                        # reset if theres any active error
                        self.resetActiveErrorCode()
                        # return success
                        return True
                    else:
                        self._sessionRefreshed = False
                        self.sessionErrorCheck(netmodeSwitchInfo)
                        self.logger.error(f"Switching network mode = 0{NetworkMode} failed")
                        # Return failed
                        return False
                # band configurations fetching failed
                else:
                    self._sessionRefreshed = False
                    self.logger.error(f"{self._modemname} Failed to fetch network bands from /api/net/net-mode")
                    return False                
                ####### switching network mode end ########
            except Exception as e:
                # invalidate refresh
                self._sessionRefreshed = False
                self.logger.error(e)
                self.logger.error(f"{self._modemname} Failed to switch network mode")
                return False
        else:
            # invalidate refresh
            self._sessionRefreshed = False
            self.logger.error(f"{self._modemname} Failed to switch network mode")
            return False
        
    ################################################
    ########## Modem management ####################
    ################################################
    def switchDHCPIPBlock(self, gateway):
        """
        This methos will change DHCP IP block and gateway(modem) IP based on provided :attr:`gateway`.
        
        All existing connections will drop and probably a soft reboot will performed after calling this method.
        
        Use only gateway in 192.168.X.1 format (eg:- 192.168.2.1, 192.168.20.1).
        So the DHCP offering IP block will be 192.168.x.100-192.168.x.199.
        
        :param    gateway:    Gateway or IP of the modem
        :type    gateway:    string
        
        """
        # if session is not refreshed validate and refresh session again
        if not self._sessionRefreshed:
            self.validateSession()
        # wait if in an operation
        while self._inOperation:
            time.sleep(0.5)            
        # if session is valid start switching DHCP IP block
        if self._validSession:
            try:
                xml_body = f"""
                <?xml version="1.0" encoding="UTF-8"?>
                <request>
                <DhcpIPAddress>{gateway}</DhcpIPAddress>
                <DhcpLanNetmask>255.255.255.0</DhcpLanNetmask>
                <DhcpStatus>1</DhcpStatus>
                <DhcpStartIPAddress>{gateway}00</DhcpStartIPAddress>
                <DhcpEndIPAddress>{gateway}99</DhcpEndIPAddress>
                <DhcpLeaseTime>86400</DhcpLeaseTime>
                <DnsStatus>1</DnsStatus>
                <PrimaryDns>{gateway}</PrimaryDns>
                <SecondaryDns>{gateway}</SecondaryDns>
                </request>
                """
                headers = {
                'X-Requested-With':'XMLHttpRequest',
                '__RequestVerificationToken': self._RequestVerificationToken
                }
                # call switch
                self.logger.info(f"Gateway IP changing into {gateway}")
                self.httpPost("/api/dhcp/settings", xml_body, cookies=None, headers=headers)
                # No response & immediatly modem reboot with new IP block
                # Therefore need to stop
                self.stop()
                self.logger.info(f"Stop the thread due to gateway change")
                ####### switching DHCP IP block end ########
            except Exception as e:
                # invalidate refresh
                self._sessionRefreshed = False
                self.logger.error(e)
                self.logger.error(f"{self._modemname} Failed to switch DHCP IP block")
        else:
            # invalidate refresh
            self._sessionRefreshed = False
            self.logger.error(f"{self._modemname} Failed to switch DHCP IP block")
