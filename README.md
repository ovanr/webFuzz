# webFuzz

A grey-box fuzzer for web applications

## Installation

1. Instrument your web application using [php-ast-instrumentor](https://bitbucket.org/srecgrp/webfuzz_public/src/v1.1.0/instrumentor/).
2. Make sure your instrumented web application now works fine.
4. Install the python dependencies:  ```pip3 install --upgrade -r web_fuzzer/requirements.txt```

## Usage

Run the fuzzer using `webFuzz.py`.
*Tested on Linux environments with Python version 3.8 and 3.9*

Example run: 
```
./webFuzz.py -vv 
             --driver webFuzz/drivers/geckodriver 
             -m ~/MyWebappInstrumented/instr.meta 
             -w 8 
             -b 'wp-login|action|logout|' 
             -b 'settings|||POST 
             -p -s 
             -r simple 
             'http://localhost/wp-admin/index.php'
```

## Trophy Case

* OSCommerce CE-Phoenix - 8 Zero day XSS bugs - [GitHub Issue](https://github.com/gburton/CE-Phoenix/issues/1039)


## Authors

* **Orpheas van Rooij** - *ovan-r01@cs.ucy.ac.cy*
* **Marcos Antonios Charalambous** - *mchara01@cs.ucy.ac.cy*
* **Demetris Kaizer** - *dkaize01@cs.ucy.ac.cy*
* **Michalis Papaevripides** - *mpapae04@cs.ucy.ac.cy*
* **Elias Athanasopoulos** - *eliasathan@cs.ucy.ac.cy*

All authors are members of the University of Cyprus

## License
[GNU GPLv3](https://choosealicense.com/licenses/gpl-3.0/)
