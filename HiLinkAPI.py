import logging
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


class webui:
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
            _response = requests.get(f"{self._httpHost}{endpoint}", cookies=cookies, timeout=self._callTimeOut)
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
            _response = requests.post(f"{self._httpHost}{endpoint}", data=postBody, cookies=cookies, headers=headers, timeout=self._callTimeOut)
            self.processHTTPHeaders(_response)
            return  _response
        except Exception as e:
            self.logger.error(e)
            raise hilinkException(self._modemname, f"Calling {self._httpHost}{endpoint} failed")
    
    def initialize(self):
        """      
        Calling this method will initialize API calls by
        
        * Refresh session and retrieving a fresh *SessionID*
        * Regenerate and request a new *__RequestVerificationToken*
        * Query authentication required or not
        * Identify webUI version
        
        """
        self._sessionId = None
        self._RequestVerificationToken = None
        self._webuiversion = None
        self._deviceClassify = None
        self._deviceName = None
        self._loginRequired = None
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
                raise hilinkException(self._modemname, "Failed to get device info")
        except Exception as e:
            self.logger.error(e)
            raise hilinkException(self._modemname, "Failed to get device info")
        ###############################################################
        # Check for authentication required or not
        if self._webuiversion == 17 or self._webuiversion == 21:  # WebUI version 17 or 21
            try:
                response = self.httpGet("/api/user/state-login")
                stateLogin = xmltodict.parse(response.text)
                if "response" in stateLogin:
                    if int(stateLogin['response']['password_type']) == 0:
                        self._loginRequired = False
                    elif int(stateLogin['response']['password_type']) == 4:
                        self._loginRequired = True
                else:
                    raise hilinkException(self._modemname, "Invalid response while getting user login state")
            except Exception as e:
                self.logger.error(e)
                raise hilinkException(self._modemname, "Failed to get user login state")
        elif self._webuiversion == 10:  # WebUI version 10
            try:
                response = self.httpGet("/api/user/hilink_login")
                stateLogin = xmltodict.parse(response.text)
                if "response" in stateLogin:
                    if int(stateLogin['response']['hilink_login']) == 0:
                        # wingles always comes with authentication even hilink_login==0
                        if str(self._deviceClassify).upper() == "WINGLE":
                            self._loginRequired = True
                        else:
                            self._loginRequired = False
                    elif int(stateLogin['response']['hilink_login']) == 1:
                        self._loginRequired = True
                else:
                    raise hilinkException(self._modemname, "Invalid response while getting user login state")
            except Exception as e:
                self.logger.error(e)
                raise hilinkException(self._modemname, "Failed to get user login state")
        ###########################################################
           

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
    
    def login_WebUI10(self):
        """
        This method will call to authenticate webUI WebUI version 10.x.x.
        
        If got *Invalid Session Token (125003)* error re-initialization will execute by calling :meth:`~initialize`.
        
        :raises:    :meth:`~hilinkException`
        :return:    Return login/authentication is succeeded or failed
        :rtype:    bool        
        """
        try:
            self.logger.debug(f"Login for WebUI version 10 - login count = {self._loginTryCount}")
            # grab the verification token
            self.logger.debug("Querying for token")
            response = self.httpGet("/api/webserver/token")
            tokenJson = xmltodict.parse(response.text)
            self.logger.debug(response.text)
            if "response" in tokenJson:
                _tmpToken = tokenJson['response']['token']
                self._RequestVerificationToken = _tmpToken[len(_tmpToken) - 32:len(_tmpToken)] 
            # increase login count
            self._loginTryCount += 1
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
                self.logger.debug("Login authentication response")
                self.logger.debug(loginResponse)
                if 'error' in loginResponse:
                    self.logger.error("Log in failed")
                    return False
                else:
                    self._loginTryCount = 0
                    self.logger.info("Log in successfully")
                    return True
            else:  # response error
                self.logger.error("response error while getting salt")
                self.logger.error(challangeDict)
                if 'error' in challangeDict:
                    if int(challangeDict['error']['code']) == 125003:  # invalid session token
                        self.logger.debug(f"Got {challangeDict['error']['code']} and re-initializing")
                        self.initialize()
                else:
                    return False
        except Exception as e:
            self.logger.error(e)
            raise hilinkException(self._modemname, "Error while login WebUI10")

    def login_WebUI17or21(self):
        """
        This method will call to authenticate webUI WebUI versions 17.x.x and 21.x.x.
        
        :raises:    :meth:`~hilinkException`
        :return:    Return login/authentication is succeeded or failed
        :rtype:    bool 
        """
        try:
            self.logger.debug(f"Login for WebUI version 17 / 21 - login count = {self._loginTryCount}")
            # increase login count
            self._loginTryCount += 1
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
            <password_type>4</password_type>
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
            self.logger.debug("Login execute")
            self.logger.debug(loginResponse)
            # check for response
            if 'response' in loginResponse:
                return True
            else:  # response error
                self.logger.error("response error while login")
                return False
        except Exception as e:
            self.logger.error(e)
            raise hilinkException(self._modemname, "Error while login WebUI17/21")
            
    def authenticate(self):
        """
        This method will check current session either authenticated or not.
        
        This method required to return **True** before calling any other method which manipulate a function on modem 
        or query any API end point except :meth:`~initialize`.
        
        This method will authenticate if required or session expired by calling */api/user/state-login* API end point.
        As per the WebUI version respective login method will be called (either :meth:`~login_WebUI10` or
        :meth:`~login_WebUI17or21`) if authentication required.
        
        Error message returns in API calls will check using :meth:`~sessionErrorCheck`.
        
        :raises:    :meth:`~hilinkException`, Raise an exception if,
        
                        * *error* received from state-login API
                        * Username and password not provided while authentication is required
                        
        :return:    Return current session is authenticated or not
        :rtype:    bool 
        """
        if self._loginRequired == False:  # Login not required
            return True
        else:  # login required
            response = self.httpGet("/api/user/state-login")
            userStateResponse = xmltodict.parse(response.text)
            # default not logged
            userState = -1
            # if has a valid response
            if "response" in userStateResponse:
                # get user state
                if "State" in userStateResponse["response"]:
                    if userStateResponse["response"]["State"] is not None:
                        userState = int(userStateResponse["response"]["State"])
                # Manipulate login
                if userState == 0:  # active login
                    self._loginTryCount = 0
                    self.logger.debug(f"Active login found userState={userState}")
                    # end by returning a true
                    return True
                else:  # no active login
                    # check for max login retry count
                    if(self._loginTryCount >= self._loginTryCountMax):
                        # if max login retry count exceeded initialize and return False 
                        self.logger.debug("Max login retry count exceeded and initializing")
                        self.initialize()
                        return False
                    else:  # try for login
                        if self._username is not None and self._password is not None:
                            self.logger.debug("Try login")
                            # login
                            if self._webuiversion == 10:  # webUI version 10
                                return self.login_WebUI10()
                            elif self._webuiversion == 17 or self._webuiversion == 21:  # webUI version 17 or 21
                                return self.login_WebUI17or21()
                        else:
                            raise hilinkException(self._modemname, "Username and password not provided for authentication")
            else:
                errMsg = f"User status check failed."
                if 'error' in userStateResponse:
                    errorCode = userStateResponse['error']['code']
                    errMsg = f"{errMsg} errorCode={errorCode}"
                    self.sessionErrorCheck(userStateResponse)
                raise hilinkException(self._modemname, errMsg)

    def sessionErrorCheck(self, responseXMLDict):
        """
        This method will be called if *error* message returned as response in API end point calls.
        
        This will re-initialize session using :meth:`~initialize` if **error** is presented in response XML.
        
        :param    responseXMLDict:    Response XML as a dictionary
        :type    responseXMLDict:    dictionary
        
        """
        if "error" in responseXMLDict:
            self.logger.debug("Re initializing")
            self.initialize()
                
    def queryDeviceInfo(self):
        """
        This method will query device information and update existing.
        
        Authentication will check by calling :meth:`~authenticate` before calling device information API end point.
        
        :raises:    :meth:`~hilinkException`, Raise an exception if an error received from API end point calls.
        """
        try:
            # authenticate
            authenticated = False
            while (self.getLoginMaxTryCount() > self.getLoginTriedCount()) and not authenticated:
                authenticated = self.authenticate()
            # require authentication
            if authenticated: 
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
                else:
                    errMsg = f"Failed to get device info."
                    if 'error' in deviceInfo:
                        errorCode = deviceInfo['error']['code']
                        errMsg = f"{errMsg} errorCode={errorCode}"
                        self.sessionErrorCheck(deviceInfo)
                    raise hilinkException(self._modemname, errMsg)
        except Exception as e:
            self.logger.error(e)
            raise hilinkException(self._modemname, "Failed to get device info")

    def queryWANIP(self):
        """
        This method will query WAN IP from the carrier network and update existing.
        
        Authentication will check by calling :meth:`~authenticate` before calling device information API end point.
        
        Separate API end points will be called as per the WebUI version.
        
        :raises:    :meth:`~hilinkException`, Raise an exception if an error received from API end point calls.
        """
        try:
            # Make WAN IP None
            self._wanIP = None
            # authenticate
            authenticated = False
            while (self.getLoginMaxTryCount() > self.getLoginTriedCount()) and not authenticated:
                authenticated = self.authenticate()
            # require authentication
            if authenticated: 
                if self._webuiversion == 17:  # webUI version 17
                    headers = {'X-Requested-With':'XMLHttpRequest'}
                    response = self.httpGet("/api/monitoring/status", headers=headers)
                    wanIPInfo = xmltodict.parse(response.text)
                    if "response" in wanIPInfo:
                        if "WanIPAddress" in wanIPInfo['response']:
                            self._wanIP = wanIPInfo['response']['WanIPAddress']
                    else:
                        errMsg = f"Failed to get WAN IP info."
                        if 'error' in wanIPInfo:
                            errorCode = wanIPInfo['error']['code']
                            errMsg = f"{errMsg}. errorCode={errorCode}"
                            self.sessionErrorCheck(wanIPInfo)
                        raise hilinkException(self._modemname, errMsg)
                if self._webuiversion == 10 or self._webuiversion == 21:  # WebUI 10 or 21
                    headers = {'X-Requested-With':'XMLHttpRequest'}
                    response = self.httpGet("/api/device/information", headers=headers)
                    wanIPInfo = xmltodict.parse(response.text)
                    if "response" in wanIPInfo:
                        if "WanIPAddress" in wanIPInfo['response']:
                            self._wanIP = wanIPInfo['response']['WanIPAddress']
                    else:
                        errMsg = f"Failed to get WAN IP info."
                        if 'error' in wanIPInfo:
                            errorCode = wanIPInfo['error']['code']
                            errMsg = f"{errMsg}. errorCode={errorCode}"
                            self.sessionErrorCheck(wanIPInfo)
                        raise hilinkException(self._modemname, errMsg)
        except Exception as e:
            self.logger.error(e)
            self.logger.error("WAN IP querying failed")            
            
    def queryNetwork(self):
        """
        This method will query network name of the carrier network and update existing.
        
        Authentication will check by calling :meth:`~authenticate` before calling device information API end point.
        
        :raises:    :meth:`~hilinkException`, Raise an exception if an error received from API end point calls.
        """
        try:
            # authenticate
            authenticated = False
            while (self.getLoginMaxTryCount() > self.getLoginTriedCount()) and not authenticated:
                authenticated = self.authenticate()
            # require authentication
            if authenticated: 
                headers = {'X-Requested-With':'XMLHttpRequest'}
                response = self.httpGet("/api/net/current-plmn", headers=headers)
                connectionInfo = xmltodict.parse(response.text)
                if "response" in connectionInfo:
                    self._networkName = connectionInfo["response"]["FullName"]
                else:
                    errMsg = f"Failed to get connection info."
                    if 'error' in connectionInfo:
                        errorCode = connectionInfo['error']['code']
                        errMsg = f"{errMsg} errorCode={errorCode}"
                        self.sessionErrorCheck(connectionInfo)
                    raise hilinkException(self._modemname, errMsg)
        except Exception as e:
            self.logger.error(e)
            raise hilinkException(self._modemname, "Failed to get connection info")
    
    def __init__(self, modemname, host, username=None, password=None, logger=None):
        """
        Initialize webui
        """
        self._modemname = modemname
        self._host = host
        # assign empty strings if none
        self._username = username if username is not None else ""
        self._password = password if password is not None else ""
        # decrypt configurations string, split and assign end
        if logger is None:
            self.logger = logging.getLogger(f"{__name__}--{self._modemname}")
        else:
            self.logger = logger
        self._httpHost = f"http://{self._host}"
        self._sessionId = None
        self._RequestVerificationToken = None
        # Authenticaion required or not
        self._loginRequired = False
        # login re-try count (only valid with authentication required instances)
        self._loginTryCount = 0
        self._loginTryCountMax = 2
        self._callTimeOut = 15
        # HuaweiWebUI version
        # Has to be 10 or 17/21
        self._webuiversion = None
        # Device classify (hilink | wingle)
        self._deviceClassify = None
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
        ###############################
        # initialize
        self.initialize()

    def getLoginTriedCount(self):
        """
        This method will return unsuccessfull login attempts.
        
        :return:   Return unsuccessfull login attempts count
        :rtype:    int    
        """
        return self._loginTryCount
    
    def getLoginMaxTryCount(self):
        """
        This method will return maximum allowed login attempts.
        
        :return:   Return allowed max login attempts
        :rtype:    int    
        """
        return self._loginTryCountMax
        
    def getWebUIVersion(self):
        """
        This method will return WebUI version either *10*, *17* or *21*.
        
        :return:   Return WebUI version
        :rtype:    int    
        """
        return self._webuiversion

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
    
    def getLoginRequired(self):
        """
        This method will return either login/authentication required or not which will be updated after calling
        :meth:`~initialize`.
        
        :return:   Return login required or not
        :rtype:    bool
        """
        return self._loginRequired

    def switchConnection(self, status=True):
        """
        Switch on or off data connection based on :attr:`status`.
        
        :param    status:    Either set status of the connection On or Off
        :type    status:    bool
        
        :raises:    :meth:`~hilinkException`, Raise exception if,
                        
                        * An error occured
                        * Invalid session token error message received in API end point calls
                        
        :return:   Return either requested connection switching succeeded or failed
        :rtype:    bool
        """
        try:
            dataSwitch = "1" if status else "0"
            # authenticate
            authenticated = False
            while (self.getLoginMaxTryCount() > self.getLoginTriedCount()) and not authenticated:
                authenticated = self.authenticate()
            # require authentication
            if authenticated: 
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
                    return True
                else:
                    self.logger.error(f"Switching data connection status = {dataSwitch} failed")
                    # check for know errors
                    if 'error' in dataswitchInfo:
                        if int(dataswitchInfo['error']['code']) == 125003:  # invalid session token
                            self.sessionErrorCheck(dataswitchInfo)
                            return self.switchConnection(status)
                    # check for know errors end
                    # if not a known error return false
                    return False
        except Exception as e:
            self.logger.error(e)
            self.logger.error(f"Switching data connection failed")
            return False
        
    def switchLTE(self, ltestatus=True):
        """
        Switch network mode either *WCDMA* or *LTE* based on :attr:`ltestatus`.
        If :attr:`ltestatus` is **True** network mode switch to *LTE* or else to *WCDMA*.
        
        :param    ltestatus:    Network mode is LTE or not (WCDMA)
        :type    ltestatus:    bool
        
        :raises:    :meth:`~hilinkException`, Raise exception if,
                        
                        * An error occured
                        * Invalid session token error message received in API end point calls
                        
        :return:   Return either requested network mode switching succeeded or failed
        :rtype:    bool
        """
        # decide network mode
        # http://192.168.10.1/config/network/networkmode.xml
        # 0=auto 02=3G 03=4G
        NetworkMode = "03" if ltestatus else "02"
        NetworkBand = ""
        LTEBand = ""
        # Fetch network band and LTE band
        try:
            # authenticate
            authenticated = False
            while (self.getLoginMaxTryCount() > self.getLoginTriedCount()) and not authenticated:
                authenticated = self.authenticate()
            # require authentication
            if authenticated: 
                headers = {'X-Requested-With':'XMLHttpRequest'}
                response = self.httpGet("/api/net/net-mode", headers=headers)
                netModeInfo = xmltodict.parse(response.text)
                if "response" in netModeInfo:
                    NetworkBand = netModeInfo['response']['NetworkBand']
                    LTEBand = netModeInfo['response']['LTEBand']
                else:
                    errMsg = f"Failed to get connection info."
                    if 'error' in netModeInfo:
                        errorCode = netModeInfo['error']['code']
                        errMsg = f"{errMsg} errorCode={errorCode}"
                        self.sessionErrorCheck(netModeInfo)
                    raise hilinkException(self._modemname, errMsg)
        except Exception as e:
            self.logger.error(e)
            raise hilinkException(self._modemname, "Failed to get network mode info")
        # end of mode fetch
        # switch mode
        try:
            # authenticate
            authenticated = False
            while (self.getLoginMaxTryCount() > self.getLoginTriedCount()) and not authenticated:
                authenticated = self.authenticate()
            # require authentication
            if authenticated: 
                xml_body = f"""
                <?xml version="1.0" encoding="UTF-8"?>
                <request>
                <NetworkMode>{NetworkMode}</NetworkMode>
                <NetworkBand>{NetworkBand}</NetworkBand>
                <LTEBand>{LTEBand}</LTEBand>
                </request>
                """
                headers = {
                'X-Requested-With':'XMLHttpRequest',
                '__RequestVerificationToken': self._RequestVerificationToken
                }
                # call switch
                self.logger.info(f"Switching network mode = {NetworkMode} {'LTE' if ltestatus else 'WCDMA'}")
                response = self.httpPost("/api/net/net-mode", xml_body, cookies=None, headers=headers)
                netmodeSwitchInfo = xmltodict.parse(response.text)
                if "response" in netmodeSwitchInfo:
                    self.logger.info(f"Switched network mode = {NetworkMode} {'LTE' if ltestatus else 'WCDMA'}")
                    return True
                else:
                    self.logger.error(f"Switching network mode = {NetworkMode} {'LTE' if ltestatus else 'WCDMA'} failed")
                    # check for know errors
                    if 'error' in netmodeSwitchInfo:
                        if int(netmodeSwitchInfo['error']['code']) == 125003:  # invalid session token
                            self.sessionErrorCheck(netmodeSwitchInfo)
                            return self.switchLTE(ltestatus)
                    # check for know errors end
                    # if not a known error return false
                    return False
        except Exception as e:
            self.logger.error(e)
            self.logger.error(f"Switching network mode failed")
            return False
        
    def reboot(self):
        """
        This method will soft reboot the modem. 
        """
        try:
            # authenticate
            authenticated = False
            while (self.getLoginMaxTryCount() > self.getLoginTriedCount()) and not authenticated:
                authenticated = self.authenticate()
            # require authentication
            if authenticated: 
                xml_body = f"""
                <?xml version="1.0" encoding="UTF-8"?>
                <request>
                <Control>1</Control>
                </request>
                """
                headers = {
                'X-Requested-With':'XMLHttpRequest',
                '__RequestVerificationToken': self._RequestVerificationToken
                }
                # call switch
                self.logger.info(f"Rebooting")
                response = self.httpPost("/api/device/control", xml_body, cookies=None, headers=headers)
                netRebootInfo = xmltodict.parse(response.text)
                # check for know errors
                if 'error' in netRebootInfo:
                    if int(netRebootInfo['error']['code']) == 125003:  # invalid session token
                        self.sessionErrorCheck(netRebootInfo)
                        return self.switchReboot()
                # check for know errors end
                # if not a known error return false               
                self.logger.info(f"Rebooted")
                return True
        except Exception as e:
            self.logger.error(e)
            self.logger.error(f"Rebooting failed")
            return False 
        
    def switchDHCPIPBlock(self, gateway):
        """
        This methos will change DHCP IP block and gateway(modem) IP based on provided :attr:`gateway`.
        
        All existing connections will drop and probably a soft reboot will performed after calling this method.
        
        Use only gateway in 192.168.X.1 format (eg:- 192.168.2.1, 192.168.20.1).
        So the DHCP offering IP block will be 192.168.x.100-192.168.x.199.
        
        :param    gateway:    Gateway or IP of the modem
        :type    gateway:    string
        
        :raises:    :meth:`~hilinkException`
        """
        try:
            # authenticate
            authenticated = False
            while (self.getLoginMaxTryCount() > self.getLoginTriedCount()) and not authenticated:
                authenticated = self.authenticate()
            # require authentication
            if authenticated: 
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
                response = self.httpPost("/api/dhcp/settings", xml_body, cookies=None, headers=headers)
        except Exception as e:
            self.logger.error(e)
            self.logger.error(f"Gateway IP changing failed")
            return False    
