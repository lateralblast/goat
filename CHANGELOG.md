# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.8.8] - 2026-09-30

- Updated documentation: clarified which tools run in Docker in the security section

## [0.8.7] - 2026-09-30

- Updated documentation with a security section

## [0.8.6] - 2026-09-30

- Fixed usernames and passwords containing special characters (e.g. @ : / # ? %) breaking the AMT and ServerEdge PDU URLs: credentials are now percent-encoded

## [0.8.5] - 2026-09-30

- Fixed javaidrac writing the iDRAC password to a predictable world readable /tmp/<ip>.jnlp before chmod: the jnlp file is now created with mkstemp (unique name, mode 600 from creation)

## [0.8.4] - 2026-09-30

- Added --dryrun support for file downloads (BIOS and meshcmd binary)

## [0.8.3] - 2026-09-30

- Added --dryrun support for Homebrew package installs on Mac OS

## [0.8.2] - 2026-09-30

- Added --dryrun support for --meshcommander and --meshcentral (npm install and start)

## [0.8.1] - 2026-09-30

- Added --dryrun support for --meshcmd

## [0.8.0] - 2026-09-30

- Added --dryrun support for AMT set (hostname, domainname, DNS and power); no browser is started when only setting

## [0.7.9] - 2026-09-30

- Added --dryrun support for ServerEdge PDU outlet power; no browser is started when only setting

## [0.7.8] - 2026-09-30

- Added --dryrun support for APC PDU outlet power

## [0.7.7] - 2026-09-30

- Added --dryrun support for javaidrac

## [0.7.6] - 2026-09-30

- Added --dryrun support for --sol

## [0.7.5] - 2026-09-30

- Added --dryrun support for IPMI boot device and power set

## [0.7.4] - 2026-09-30

- Fixed --dryrun not being honoured for webidrac: docker pull, kill and run commands are now printed instead of executed

## [0.7.3] - 2026-09-30

- Fixed -h, --version and --options requiring third party Python modules: modules are now loaded after those switches are handled

## [0.7.2] - 2026-09-30

- Fixed Python module auto-install: use the running interpreter, install beautifulsoup4 for bs4, only use --user outside a virtualenv, refresh import paths after install, exit with a clear message on failure (e.g. externally managed Python), and removed the obsolete pip/easy_install bootstrap

## [0.7.1] - 2026-09-30

- Fixed BeautifulSoup deprecated findAll/text arguments in BIOS download code

## [0.7.0] - 2026-09-30

- Fixed Selenium 4.13+ headless mode: options.headless was removed, use the -headless argument

## [0.6.9] - 2026-09-30

- Fixed Selenium 4.3+ compatibility: replaced removed find_element_by_name and find_element_by_xpath with find_element(By...)

## [0.6.8] - 2026-09-30

- Fixed Firefox processes being leaked by ServerEdge and AMT commands, and AMT --check reusing a driver that had already been closed. The web driver is now closed once per host

## [0.6.7] - 2026-09-30

- Fixed check_local_config crash on Mac OS when Homebrew is not installed

## [0.6.6] - 2026-09-30

- Fixed AMT --check version comparison: numeric compare instead of string compare, and no crash when a version is missing or unparsable

## [0.6.5] - 2026-09-30

- Fixed AMT power: radio button was selected before the remote control page was loaded, and power on was not handled

## [0.6.4] - 2026-09-30

- Fixed APC power: only on and off are accepted (anything else used to power the outlet off), and the Docker SSH helper image is now built (ubuntu:16.04) before use

## [0.6.3] - 2026-09-30

- Fixed iDRAC --hostname being ignored: it now sets cfgDNSRacName

## [0.6.2] - 2026-09-30

- Fixed iDRAC values from a file: trailing newlines are stripped and blank, comment and invalid lines are skipped

## [0.6.1] - 2026-09-30

- Fixed iDRAC specific value command: misspelt group variables (server and serial groups were ignored) and inverted racadm set/config selection

## [0.6.0] - 2026-09-30

- Fixed iDRAC syslog port command missing a space before the value

## [0.5.9] - 2026-09-30

- Fixed iDRAC gateway being written to cfgNicNetmask instead of cfgNicGateway

## [0.5.8] - 2026-09-30

- Fixed unbound variable crashes in ServerEdge PDU get/set when outlet, power state or search value is missing or invalid

## [0.5.7] - 2026-09-30

- Fixed ~/.goatpass parsing: trailing newline in passwords, missing hosts, blank lines, two field entries and passwords containing colons

## [0.5.6] - 2026-09-30

- Fixed --allhosts with --sol using username and password before they were set

## [0.5.5] - 2026-09-30

- Fixed meshcmd binary detection, download and command line, and --meshcmd without --ip

## [0.5.4] - 2026-09-30

- Fixed crash on invalid IP caused by mask_mode being set after first use

## [0.5.3] - 2026-09-30

- Fixed iDRAC set: group, parameter and value switches were never read, and --set without --parameter raised TypeError

## [0.5.2] - 2023-03-16

- Added outlet power on/off support for ServerEdge PDU

## [0.5.1] - 2023-03-16

- Added read support for ServerEdge PDU

## [0.5.0] - 2023-03-15

- Added initial support for ServerEdge PDU

## [0.4.9] - 2023-02-12

- Improved brew/package detection code

## [0.4.8] - 2021-11-03

- Added dryrun switch

## [0.4.7] - 2021-10-25

- Added code to set a list of specific iDRAC values from a file

## [0.4.6] - 2021-10-25

- Added code to set specific iDRAC values

## [0.4.5] - 2021-10-25

- Code cleanup

## [0.4.4] - 2021-10-25

- Added group, parameter and values switch for setting specific iDRAC values

## [0.4.3] - 2021-10-25

- Replaced paramiko SSH client with pexpect due to issues

## [0.4.2] - 2020-09-15

- Updated meshcmd code

## [0.4.1] - 2020-09-15

- Fixed bug with meshcommander install

## [0.4.0] - 2020-05-30

- Added support for APC PDUs

## [0.3.9] - 2020-05-29

- Bug fixes

## [0.3.8] - 2020-05-02

- Cleaned up web iDRAC code and added Java iDRAC code

## [0.3.7] - 2020-05-02

- Added ipmi set/power function

## [0.3.6] - 2019-12-13

- Added verbose output for ipmitool command

## [0.3.5] - 2019-12-03

- Updated MeshCommander code to support global module install directory

## [0.3.5] - 2019-11-25

- Added iDRAC KVM redirection tool and iDRAC sol capability

## [0.3.4] - 2019-11-21

- Added iDRAC power on/off capability

## [0.3.3] - 2019-10-31

- Added iDRAC set capability

## [0.3.2] - 2019-10-31

- Improved search capability for get commands against iDRAC

## [0.3.1] - 2019-10-30

- Added initial iDRAC support

## [0.3.0] - 2019-10-27

- Added check for architecture for MeshCMD

## [0.2.9] - 2019-10-27

- Various bug fixes

## [0.2.8] - 2019-10-27

- Python pip and other fixes

## [0.2.7] - 2019-10-27

- Added initial support for MeshCmd

## [0.2.6] - 2019-10-26

- Fixed issue with HTML parsing and added connectivity test

## [0.2.5] - 2019-06-02

- Added code to set primary and secondary DNS for AMT

## [0.2.4] - 2019-06-02

- Updated set code to deal with more options

## [0.2.3] - 2019-06-02

- Added code to start MeshCentral

## [0.2.2] - 2019-06-01

- Added code to download BIOS

## [0.2.1] - 2019-06-01

- Added code to set hostname and domainname

## [0.2.0] - 2019-06-01

- Code cleanup

## [0.1.9] - 2019-05-31

- Fixed a couple of bugs and cleaned up web driver initiation

## [0.1.8] - 2019-05-31

- Updated documentation and added support to connect over SOL

## [0.1.7] - 2019-05-31

- Added initial code for dealing with passwords

## [0.1.6] - 2019-05-31

- Updated documentation

## [0.1.5] - 2019-05-31

- Bug fix with set code and documentation update

## [0.1.4] - 2019-05-30

- Added code to check for and start MeshCommander

## [0.1.3] - 2019-05-30

- Fixed headless mode for geckodriver

## [0.1.2] - 2019-05-30

- Initial working poweron/poweroff/reset function

## [0.1.1] - 2019-05-30

- Added mask function

## [0.1.0] - 2019-05-30

- Started adding set functionality

## [0.0.9] - 2019-05-29

- Added code to check current BIOS against available vendor version

## [0.0.8] - 2019-05-29

- Fixed and re-commit after a bad commit

## [0.0.7] - 2019-05-29

- Added code to get available BIOS version for Intel devices

## [0.0.6] - 2019-05-29

- Cleaned up code and added basic search functionality as well as serial and bios search

## [0.0.5] - 2019-05-29

- Initial working read/get only concept with clean output

## [0.0.4] - 2019-05-28

- Cleaned up output for memory

## [0.0.3] - 2019-05-28

- Moved to chromedriver

## [0.0.2] - 2019-05-27

- Initial working get version with geckodriver

## [0.0.1] - 2019-05-26

- Inital version with phantomjs support
