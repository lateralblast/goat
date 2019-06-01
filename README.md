![alt tag](https://raw.githubusercontent.com/lateralblast/goat/master/goat.png)

GOAT
====

General OOB Automation Tool

Introduction
------------

This tools is designed to consolidate several tools into one generic tool.

At the moment it supports get/set for Intel's AMT.

Some features:

- Get system information (e.g. Serial, Model, Logs, etc)
- Check BIOS version
- Remotely reset device
- Start MeshCommander in order to do other manage tasks (e.g. configure certificates)
- Start amtterm for connecting to the AMT SOL (requires non TLS/Digest access to be enabled)

Notes
-----

There are several tools, e.g. amttool to manage AMT, however I found these did not
have all the functionality I needed, and some of the functionality did not work.
I found it easier to use Selenium to drive the management web interface.

If you have not configured a certificate and thus Digest/TLS connectivity for AMT,
you can connect via HTTP using the --insecure switch.

At the moment hostname, username and password can be stored in a file ~/.goatpass
to help with automation. Obviously this is not totally secure even if the file is
only readable by you, so I am working on a secure store method.

If you use the --allhosts switch it will step through the hosts in ~/.goatpass.
The format of ~/.goatpass is hostname:username:password. If no password is present
it will prompt for one.

The script will try to install various components on Mac OS, eg Python Modules,
and MeshCommander.

MeshCommander is available from here:

https://www.meshcommander.com/meshcommander

Todo:

- Add a local password store so password can be stored securely
- Add in support for other platforms from other scripts

Requirements
------------

The following tools are required:

- Python and the following libraries
  - Seleniue
  - BeautifulSoap
- geckodriver

The code will try to auto install the Python modules and other tools if they are not available.

An example of installing these on Mac OS:

```
pip install selenium
pip install bs4
brew install geckodriver
brew install amtterm
brew install npm
mkdir meshcommander
cd meshcommander
npm install meshcommander
```
License
-------

This software is licensed as CC-BA (Creative Commons By Attrbution)

http://creativecommons.org/licenses/by/4.0/legalcode


Serial-Over-LAN
---------------

Here is a brief guide for enabling serial on devices running Linux.

To be able to use SOL (Serial Over LAN) management, you need to enable agetty via init,
and enable the serial console in grub on the device that you want to remote manage.
Once this is done the machine will need to be rebooted for the serial console to be enabled.

To enable agetty via init you need determine the serial TTY by running the following command:

```
dmesg | grep ttyS | grep irq | grep 0000 | tr -s " " | cut -d" " -f4
```

Once the serial TTY has been determined you can then enable agetty via init:

```
echo "S1:2345:respawn:/sbin/agetty ttySX 115200 vt100-nav" >> /etc/inittab
init q
```

To enable the serial console via grub you’ll need the serial TTY number and
the IO port which can be determined with the following command:

```
dmesg | grep ttySX | grep irq | tr -s " " | cut -d" " -f7
```

Once you have the serial TTY number and the IO port you can configure grub:

```
echo 'GRUB_CMDLINE_LINUX="console=ttySX,115200"' >> /etc/default/grub
echo 'GRUB_TERMINAL="serial console"' >> /etc/default/grub
echo 'GRUB_SERIAL_COMMAND="serial --speed=115200 --port=0xXXXX"' >> /etc/default/grub
update-grub
```


Examples
--------

Getting help:

```
$ ./goat.py --help
usage: goat.py [-h] [--ip IP] [--username USERNAME] [--type TYPE] [--get GET]
               [--set SET] [--password PASSWORD] [--search SEARCH]
               [--avail AVAIL] [--check CHECK] [--model MODEL] [--port PORT]
               [--version] [--insecure] [--verbose] [--debug] [--mask]
               [--mesh]

optional arguments:
  -h, --help           show this help message and exit
  --ip IP
  --username USERNAME
  --type TYPE
  --get GET
  --set SET
  --password PASSWORD
  --search SEARCH
  --avail AVAIL
  --check CHECK
  --model MODEL
  --port PORT
  --version
  --insecure
  --verbose
  --debug
  --mask
  --mesh
  --options
```

Getting information about options:

```
./goat.py --options

Options:

--ip          Specify IP of OOB/Remote Management interface
--username    Set Username
--type        Set Type
--get         Get Parameter
--set         Set Parameter
--password    Set Password
--search      Search output for value
--avail       Get available version from vendor (e.g. BIOS)
--check       Check current version against available version from vendor (e.g. BIOS)
--model       Specify model (can be used with --avail)
--port        Specify port to run service on
--version     Display version
--insecure    Use HTTP/Telnet
--verbose     Enable verbose output
--debug       Enable debug output
--mask        Mask serial and hostname output output
--mesh        Use Meshcommander
--options     Display options information
```

Connecting to host over SOL:

```
$ ./goat.py --ip 192.168.1.171 --sol --type amt
Password for 192.168.1.171:
amtterm: NONE -> CONNECT (connection to host)
ipv4 (null) [192.168.1.171] 16994 open
amtterm: CONNECT -> INIT (redirection initialization)
amtterm: INIT -> AUTH (session authentication)
amtterm: AUTH -> INIT_SOL (serial-over-lan initialization)
amtterm: INIT_SOL -> RUN_SOL (serial-over-lan active)
serial-over-lan redirection ok
connected now, use ^] to escape

Ubuntu 18.04.2 LTS inn01 ttyS4

inn01 login:
```

Set hostname:

```
./goat.py --ip 192.168.1.171 --set hostname --value ecs01 --type amt
```

Get BIOS version:

```
./goat.py --ip 192.168.1.171 --get bios --type amt
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
./goat.py --ip 192.168.1.171 --avail bios --type amt
Computer model: NUC7i5DNKE
Available version:  0063
BIOS Download link: https://downloadcenter.intel.com//download/28789/BIOS-Update-DNKBLi5v-86A-
```

Check current BIOS version against available vendor version:

```
./goat.py --ip 192.168.1.171 --check bios --type amt
Computer model: NUC7i5DNKE
Version: DNKBLi5v.86A.0063.2019.0503.1714
Available version:  0063
BIOS Download link: https://downloadcenter.intel.com//download/28789/BIOS-Update-DNKBLi5v-86A-
Latest version of BIOS installed
```

Reset device:

```
./goat.py --ip 192.168.1.171 --set reset --type amt
Sending reset to 192.168.1.171 (Intel AMT has a 30s pause before operation is done)
```

Start MeshCommander:

```
./goat.py --mesh
MeshCommander running on http://127.0.0.1:3000.
```

Get the Memory configuration:

```
./goat.py --ip 192.168.1.171 --get memory --type amt
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
./goat.py --ip 192.168.1.171 --get system --type amt
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
$ ./goat.py --ip 192.168.1.171 --get events --type amt
Event Log,Event,Time,Source,Description
1,5/28/2019,9:59 pm,BIOS,Starting operating system boot process.
2,5/28/2019,9:59 pm,Add-in card,Starting ROM initialization.
3,5/28/2019,9:59 pm,BIOS,USB resource configuration.
4,5/28/2019,9:59 pm,Add-in card,Starting ROM initialization.
5,5/28/2019,9:59 pm,BIOS,Performing PCI configuration.
6,5/28/2019,9:59 pm,BIOS,Performing PCI configuration.
7,5/28/2019,9:59 pm,BIOS,Performing PCI configuration.
```