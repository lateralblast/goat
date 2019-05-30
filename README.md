![alt tag](https://raw.githubusercontent.com/lateralblast/goat/master/goat.png)

GOAT
====

General OOB Automation Tool

Introduction
------------

This tools is designed to consolidate several tools into one generic tool.

At the moment it supports get/read only fetches of information from Intels AMT.

Notes
-----

The API is not that well documented and has changed from a SOAP based interface to
a Web Services based interface. There are sever tools, e.g. amttool to manage AMT,
however I found these did not have all the functionality I needed, and some of the
functionality did not work. I found it easier to use Selenium to drive the
management web interface.

SSL support may work, it is still being tested. The --insecure switch connects via http.

Todo:

- Fully test SSL support
- Add ability to set parameters, e.g. power reset/off/on
- Add in support for other platforms from other scripts

Requirements
------------

The following tools are required:

- Python and the following libraries
  - Selenium
  - BeautifulSoap
- geckodriver

The code will try to auto install the Python modules if they are not available.

An example of installing these on Mac OS:

```
pip install selenium
pip install bs4
brew cask install chromedriver
```
License
-------

This software is licensed as CC-BA (Creative Commons By Attrbution)

http://creativecommons.org/licenses/by/4.0/legalcode

Examples
--------

Getting help:

```
$ ./goat.py --help
usage: goat.py [-h] [--ip IP] [--username USERNAME] [--type TYPE] [--get GET]
               [--set SET] [--password PASSWORD] [--version] [--insecure]
               [--verbose] [--debug]

optional arguments:
  -h, --help           show this help message and exit
  --ip IP
  --username USERNAME
  --type TYPE
  --get GET
  --set SET
  --password PASSWORD
  --version
  --insecure
  --verbose
  --debug
```

Get BIOS version:

```
./goat.py --ip 192.168.1.171 --insecure --username admin --password XXXXXXXX --get bios --type amt
Version: DNKBLi5v.86A.0063.2019.0503.1714
```

Get available BIOS version for a specific model:

```
./goat.py --avail bios --model NUC7i5DNKE --type amt
Available version:  0063
BIOS Download link: https://downloadcenter.intel.com//download/28789/BIOS-Update-DNKBLi5v-86A-
```

Get available BIOS versions for a managed device:

```
./goat.py --ip 192.168.1.171 --insecure --username admin --password XXXXXXXX --avail bios --type amt
Computer model: NUC7i5DNKE
Available version:  0063
BIOS Download link: https://downloadcenter.intel.com//download/28789/BIOS-Update-DNKBLi5v-86A-
```

Check current BIOS version against available vendor version:

```
./goat.py --ip 192.168.1.171 --insecure --username admin --password XXXXXXXX --check bios --type amt
Computer model: NUC7i5DNKE
Version: DNKBLi5v.86A.0063.2019.0503.1714
Available version:  0063
BIOS Download link: https://downloadcenter.intel.com//download/28789/BIOS-Update-DNKBLi5v-86A-
Latest version of BIOS installed
```

Get the Memory configuration:

```
./goat.py --ip 192.168.1.171 --insecure --username admin --password XXXXXXXX --get memory --type amt
Memory Information
Module 1
Not installed
Module 2
Not installed
Module 3
Manufacturer: 859B
Serial number: XXXXXX
Size: 16384 MB
Speed: 2400 MHz
Form factor: SODIMM
Type: DDR4
Type detail: Synchronous, Unbuffered (Unregistered)
Asset tag: 9876543210
Part number: CT16G4SFD824A.M16FE
Module 4
Not installed
```

Get System information:

```
./goat.py --ip 192.168.1.171 --insecure --username admin --password XXXXXXXX --get system --type amt
System Information
Platform
Computer model: NUC7i5DNKE
Manufacturer: Intel Corporation
Version: J57826-401
Serial number: XXXXXXXXXXXXXX 
System ID: XXXXXXXXXXX
Baseboard
Manufacturer: Intel Corporation
Product name: NUC7i5DNB
Version: J57626-401
Serial number: XXXXXXXXXX
Asset tag
Replaceable?: Yes
BIOS
Vendor: Intel Corp.
Version: DNKBLi5v.86A.0063.2019.0503.1714
Release date: 05/03/2019
```

Get System Event information:

```
$ ./goat.py --ip 192.168.1.171 --insecure --username admin --password XXXXXXX --get events --type amt
Event Log,Event,Time,Source,Description
1,5/28/2019,9:59 pm,BIOS,Starting operating system boot process.
2,5/28/2019,9:59 pm,Add-in card,Starting ROM initialization.
3,5/28/2019,9:59 pm,BIOS,USB resource configuration.
4,5/28/2019,9:59 pm,Add-in card,Starting ROM initialization.
5,5/28/2019,9:59 pm,BIOS,Performing PCI configuration.
6,5/28/2019,9:59 pm,BIOS,Performing PCI configuration.
7,5/28/2019,9:59 pm,BIOS,Performing PCI configuration.
```