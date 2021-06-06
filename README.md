# Huawei HiLink Python 3 API #

This will provide a Python 3 API to manage HiLink based Huawei USB modems,

* E8372h-320
* E8372h-155
* E3372h-320
* E3372h-153

having WebUI version 10.xx.xx, 17.xxx.xx and 21.xxx.xx variants.

Choose the best rotation method suppport with your mobile carrier.


## Python packages ##
Following python package installations are required apart from defaults
```bash   
pip3 install requests
pip3 install xmltodict
pip3 install beautifulsoup4
pip3 install uuid
```

## API Test ##
Run apiTest.py python script to test functionalities.
Example provided for 4 modem types supporting using both with and without authentication
```bash   
python3 apiTest.py
```

## Native compilation using Cython ##

This is for building native linux libraries build from python sources

Have to add python source files into cythonNativeCompile.py
```python
ext_modules = [
...
Extension("webui",  ["webui.py"]),
...
]
```

### Python packages ###
Cython has to be install prior to native compilation.
```bash   
pip3 install cython
```

### Compile ###
Run following to build native libraries from python source
```bash   
python3 cythonNativeCompile.py build_ext --inplace

```

## Test results ##

| E3372h-153 | E3372h-320 | E8372h-320 |
|------------|----------- |------------|
| <img src="https://github.com/chanakalin/hilinkapi/blob/main/images/E3372h-153.png" width="250"> | <img src="https://github.com/chanakalin/hilinkapi/blob/main/images/E3372h-320.png" width="250"> | <img src="https://github.com/chanakalin/hilinkapi/blob/main/images/E8372h-320.png" width="250"> | 

## License ##
This piece of software API is licensed under GNU GPLv2.<br/><br/>
Huawei and HiLink are registered trademarks/products of [Huawei Technologies Co. Ltd](https://www.huawei.com) and/or its parents organizations.


