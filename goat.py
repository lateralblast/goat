#!/usr/bin/env python3

# Name:         goat (General OOB Automation Tool)
# Version:      0.8.10
# Release:      1
# License:      CC BY-NC-SA 4.0 (Creative Commons Attribution-NonCommercial-ShareAlike)
#               https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode
# Group:        System
# Source:       N/A
# URL:          N/A
# Distribution: UNIX
# Vendor:       Lateral Blast
# Packager:     Richard Spindler <richard@lateralblast.com.au>
# Description:  Script to drive OOB management interfaces

# Import modules

import urllib.request
import urllib.parse
import subprocess
import platform
import argparse
import binascii
import hashlib
import getpass
import socket
import time
import sys
import os
import re

from os.path import expanduser

# Set some defaults

verbose_mode = False
mask_mode    = False
debug_mode   = False
mesh_port    = "3000"
password_db  = "goatpass"
home_dir     = expanduser("~")
default_user = "admin"

# Python module names that differ from their pip package names

pip_names = { "bs4": "beautifulsoup4" }

# install and import a python module

def install_and_import(package):
  import importlib
  import site
  try:
    return importlib.import_module(package)
  except ImportError:
    pass
  pip_name = pip_names.get(package, package)
  command  = "%s -m pip install %s" % (sys.executable, pip_name)
  if sys.prefix == sys.base_prefix:
    command = "%s --user" % (command)
  if os.system(command) != 0:
    print("Warning:\tUnable to install Python module %s" % (pip_name))
    print("Information:\tInstall the requirements in a virtual environment: pip install -r requirements.txt")
    sys.exit(1)
  site.addsitedir(site.getusersitepackages())
  importlib.invalidate_caches()
  return importlib.import_module(package)

script_exe  = sys.argv[0]
script_dir  = os.path.dirname(os.path.abspath(script_exe))

# Get the meshcmd binary name for this OS and architecture

def get_meshcmd_name():
  os_type   = platform.system().lower()
  uname_arch = platform.machine().lower()
  if os_type == "windows":
    os_name = "win"
  else:
    os_name = os_type
  if re.search(r"aarch64|arm64", uname_arch):
    os_arch = "arm64"
  else:
    if re.search(r"arm", uname_arch):
      os_arch = "arm"
    else:
      if re.search(r"64", uname_arch):
        os_arch = "x86_64"
      else:
        os_arch = "i386"
  fetch_bin = "meshcmd_%s_%s" % (os_name, os_arch)
  if os_name == "win":
    fetch_bin = "%s.exe" % (fetch_bin)
  return fetch_bin

meshcmd_name = get_meshcmd_name()
meshcmd_bin  = "%s/meshcmd/%s" % (script_dir, meshcmd_name)

# Print help

def print_help(script_exe):
  print("\n")
  command    = "%s -h" % (script_exe)
  os.system(command)
  print("\n")

# Read a file into an array

def file_to_array(file_name):
  with open(file_name) as file_data:
    return file_data.readlines()

# If we have no command line arguments print help

if sys.argv[-1] == sys.argv[0]:
  print_help(script_exe)
  sys.exit()

# Get command line arguments

parser = argparse.ArgumentParser()
parser.add_argument("--ip", required=False)                  # Specify IP of OOB/Remote Management interface
parser.add_argument("--username", required=False)            # Set Username
parser.add_argument("--type", required=False)                # Set Type of OOB device
parser.add_argument("--get", required=False)                 # Get Parameter
parser.add_argument("--password", required=False)            # Set Password
parser.add_argument("--search", required=False)              # Search output for value
parser.add_argument("--avail", required=False)               # Get available version from vendor (e.g. BIOS)
parser.add_argument("--check", required=False)               # Check current version against available version from vendor (e.g. BIOS)
parser.add_argument("--model", required=False)               # Specify model (can be used with --avail)
parser.add_argument("--port", required=False)                # Specify port to run service on
parser.add_argument("--power", required=False)               # Set power state (on, off, reset)
parser.add_argument("--hostname", required=False)            # Set hostname
parser.add_argument("--gateway", required=False)             # Set gateway
parser.add_argument("--netmask", required=False)             # Set netmask
parser.add_argument("--outlet", required=False)              # Set outlet
parser.add_argument("--domainname", required=False)          # Set dommainname
parser.add_argument("--primarydns", required=False)          # Set primary DNS
parser.add_argument("--secondarydns", required=False)        # Set secondary DNS
parser.add_argument("--primarysyslog", required=False)       # Set primary Syslog
parser.add_argument("--secondarysyslog", required=False)     # Set secondary Syslog
parser.add_argument("--syslogport", required=False)          # Set Syslog port
parser.add_argument("--primaryntp", required=False)          # Set primary NTP
parser.add_argument("--secondaryntp", required=False)        # Set secondary NTP
parser.add_argument("--meshcmd", required=False)             # Run Meshcmd
parser.add_argument("--group", required=False)               # Set group
parser.add_argument("--parameter", required=False)           # Set parameter
parser.add_argument("--value", required=False)               # Set value
parser.add_argument("--boot", required=False)                # Set boot device
parser.add_argument("--file", required=False)                # File to read in (e.g. iDRAC values)
parser.add_argument("--set", action='store_true')            # Set value
parser.add_argument("--kill", action='store_true')           # Stop existing session
parser.add_argument("--version", action='store_true')        # Display version
parser.add_argument("--insecure", action='store_true')       # Use HTTP/Telnet
parser.add_argument("--verbose", action='store_true')        # Enable verbose output
parser.add_argument("--debug", action='store_true')          # Enable debug output
parser.add_argument("--dryrun", action='store_true')         # Dry run
parser.add_argument("--mask", action='store_true')           # Mask serial and hostname output output
parser.add_argument("--meshcommander", action='store_true')  # Use Meshcommander
parser.add_argument("--meshcentral", action='store_true')    # Use Meshcentral
parser.add_argument("--options", action='store_true')        # Display options information
parser.add_argument("--allhosts", action='store_true')       # Automate via .goatpass
parser.add_argument("--sol", action='store_true')            # Start a SOL connection to host
parser.add_argument("--download", action='store_true')       # Download BIOS

option = vars(parser.parse_args())

# Print version

def print_version(script_exe):
  file_array = file_to_array(script_exe)
  version    = list(filter(lambda x: re.search(r"^# Version", x), file_array))[0].split(":")[1]
  version    = re.sub(r"\s+", "", version)
  print(version)

# Print options

def print_options(script_exe):
  file_array = file_to_array(script_exe)
  opts_array = list(filter(lambda x:re.search(r"add_argument", x), file_array))
  print("\nOptions:\n")
  for line in opts_array:
    line = line.rstrip()
    if re.search(r"#", line):
      option = line.split('"')[1]
      info   = line.split("# ")[1]
      if len(option) < 8:
        string = "%s\t\t\t%s" % (option, info)
      else:
        if len(option) < 16:
          string = "%s\t\t%s" % (option, info)
        else:
          string = "%s\t%s" % (option, info)
      print(string)
  print("\n")

# Check IP

def check_valid_ip(ip):
  if not re.search(r"[a-z]", ip):
    try:
      socket.inet_pton(socket.AF_INET, ip)
    except AttributeError:
      try:
        socket.inet_aton(ip)
      except socket.error:
        return False
      return ip.count('.') == 3
    except socket.error:  # not a valid address
      return False
  return True

# Check host is up

def check_ping(ip):
  try:
    output = subprocess.check_output("ping -{} 1 {}".format('n' if platform.system().lower()=="windows" else 'c', ip), shell=True)
  except Exception:
    string = "Warning:\tHost %s not responding" % (ip)
    handle_output(string)
    return False
  return True

# Hash a password for storing

def hash_password(password):
    salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
    pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), salt, 100000)
    pwdhash = binascii.hexlify(pwdhash)
    return (salt + pwdhash).decode('ascii')

# Verify a stored password against one provided by user

def verify_password(stored_password, provided_password):
    salt = stored_password[:64]
    stored_password = stored_password[64:]
    pwdhash = hashlib.pbkdf2_hmac('sha512',
    provided_password.encode('utf-8'),
    salt.encode('ascii'), 100000)
    pwdhash = binascii.hexlify(pwdhash).decode('ascii')
    return pwdhash == stored_password

# Build a base URL with credentials, quoting characters that are special in URLs

def get_base_url(http_proto, username, password, ip, port_no):
  username = urllib.parse.quote(username, safe="")
  password = urllib.parse.quote(password, safe="")
  return "%s://%s:%s@%s:%s" % (http_proto, username, password, ip, port_no)

# Download file

def download_file(link, file, dryrun=False):
  if not os.path.exists(file):
    string = "Downloading %s to %s" % (link, file)
    if dryrun:
      handle_output("Information:\tDry run: %s" % (string))
      return
    wget.download(link, file)
  return

# Get AMT value from web

def get_web_amt_value(avail, model, driver, download, dryrun=False):
  if avail == "bios":
    found    = False
    base_url = "https://downloadcenter.intel.com"
    full_url = "%s/search?keyword=%s" % (base_url, model)
    driver.get(full_url)
    html_doc  = driver.page_source
    html_doc  = BeautifulSoup(html_doc, features='lxml')
    html_data = html_doc.find_all('td')
    for html_line in html_data:
      html_text = str(html_line)
      if debug_mode:
        handle_output(html_text)
      if re.search("BIOS Update", html_text):
        link_stub = BeautifulSoup(html_text, features='lxml').a.get("href")
        bios_url  = "%s/%s" % (base_url, link_stub)
        found = True
      if re.search("Latest", html_text) and found:
        version = BeautifulSoup(html_text, features='lxml').get_text()
        version = re.sub("Latest", "", version)
        string  = "Available version:  %s" % (version)
        handle_output(string)
        string  = "BIOS Download link: %s" % (bios_url)
        handle_output(string)
        if download:
          from selenium.webdriver.common.by import By
          driver.get(bios_url)
          html   = driver.page_source
          html   = BeautifulSoup(html, features='lxml')
          html   = html.find_all("a", string=re.compile(r"\.bio"))[0]
          html   = str(html)
          link   = html.split('"')[3]
          file   = os.path.basename(link)
          download_file(link, file, dryrun)
        return version
  return

# Handle output

def handle_output(output):
  if mask_mode:
    if re.search(r"serial|address|host|id", output.lower()):
      if re.search(":", output):
        param  = output.split(":")[0]
        output = "%s: XXXXXXXX" % (param)
  print(output)
  return

# Set SEP (ServerEdge PDU) value

def set_sep_power(power, ip, outlet, username, password, driver, http_proto, dryrun):
  if http_proto == "http":
    port_no = "80"
  else:
    port_no = "443"
  base_url = get_base_url(http_proto, username, password, ip, port_no)
  full_url = "%s/outlet.htm" % (base_url)
  if verbose_mode:
    string = "Information:\tConnecting to: %s" % (full_url)
    handle_output(string)
  button_id      = None
  check_box_name = None
  if re.search(r"on", power.lower()):
    button_id = "T18"
    button_name = "B5"
  if re.search(r"off", power.lower()):
    button_id = "T19"
    button_name = "B6"
  if re.search(r"offon|cycle|onoff|reset", power.lower()):
    button_id = "T21"
    button_name = "T21"
  if re.search(r"all", outlet.lower()):
    check_box_id = "C0"
    check_box_name = "C0"
  if re.search(r"a$|1", outlet.lower()):
    check_box_id = "C11"
    check_box_name = "C11"
  if re.search(r"b$|2", outlet.lower()):
    check_box_id = "C12"
    check_box_name = "C12"
  if re.search(r"c$|3", outlet.lower()):
    check_box_id = "C13"
    check_box_name = "C13"
  if re.search(r"d$|4", outlet.lower()):
    check_box_id = "C14"
    check_box_name = "C14"
  if re.search(r"e$|5", outlet.lower()):
    check_box_id = "C15"
    check_box_name = "C15"
  if re.search(r"f$|6", outlet.lower()):
    check_box_id = "C16"
    check_box_name = "C16"
  if re.search(r"g$|7", outlet.lower()):
    check_box_id = "C17"
    check_box_name = "C17"
  if re.search(r"h$|8", outlet.lower()):
    check_box_id = "C18"
    check_box_name = "C18"
  if button_id == None:
    handle_output("Warning:\tInvalid power state: %s" % (power))
    return
  if check_box_name == None:
    handle_output("Warning:\tInvalid or missing outlet: %s" % (outlet))
    return
  if dryrun:
    handle_output("Information:\tDry run: would set outlet %s to %s on %s" % (outlet, power, ip))
    return
  alert = driver.get(full_url)
  from selenium.webdriver.common.by import By
  check_box = driver.find_element(By.NAME, check_box_name)
  check_box.click()
  power_button = driver.find_element(By.NAME, button_name)
  power_button.click()
  alert = driver.switch_to.alert
  accept = alert.accept()
  return

# Get SEP (ServerEdge PDU) value

def get_sep_value(get_value, ip, username, password, driver, http_proto, search):
  if http_proto == "http":
    port_no = "80"
  else:
    port_no = "443"
  base_url = get_base_url(http_proto, username, password, ip, port_no)
  full_url = None
  if re.search("outlet|status", get_value):
    full_url = "%s/status.xml" % (base_url)
  if re.search("outlet|status", get_value):
    if verbose_mode:
      string = "Information:\tConnecting to: %s" % (full_url)
      handle_output(string)
    alert = driver.get(full_url)
    html_doc = driver.page_source
    html_doc = BeautifulSoup(html_doc, features='lxml')
    html_string = str(html_doc)
    html_lines  = html_string.split("\n")
    counter = 1
    outlet  = "A"
    for html_line in html_lines:
      if re.search("pot0", html_line):
        values = html_line.split(",")
        while counter < 9:
          amps   = values[1+counter]
          status = values[9+counter]
          if int(status) == 1:
            status = "ON "
          else:
            status = "OFF"
          string = "Outlet %s: %s (%s)" % (outlet, status, amps)
          if re.search(r"[a-z]", search.lower()):
            if search.lower() in string.lower():
              print(string)
          else:
            print(string)
          outlet = ord(outlet)
          counter = counter+1
          outlet = outlet+1
          outlet = chr(outlet)
  else:
    if not re.search(r"[a-z]", search.lower()):
      search = get_value
    if re.search("info|output|overload|warning", search):
      full_url = "%s/index.htm" % (base_url)
    if re.search("system|firmware|model|mac|systemname|contact|location", search):
      full_url = "%s/system.htm" % (base_url)
    if re.search("ssl|snmp|mail|threshold|net$|id|pdu", search):
      full_url = "%s/config%s.htm" % (base_url, search)
    if re.search("hostname|ipaddress|gateway|primary|secondary", search):
      full_url = "%s/confignet.htm" % (base_url)
    if re.search("receiver", search):
      full_url = "%s/configsnmp.htm" % (base_url)
    if full_url == None:
      handle_output("Warning:\tUnknown value: %s" % (search))
      return
    if verbose_mode:
      string = "Information:\tConnecting to: %s" % (full_url)
      handle_output(string)
    alert = driver.get(full_url)
    html_doc = driver.page_source
    html_doc = BeautifulSoup(html_doc, features='lxml')
    if search == "systemname":
      search = "system name"
    if search == "ipaddress":
      search = "ip address"
    if search == "hostname":
      search = "host name"
    if re.search("primary", search):
      search = "primary dns"
    if re.search("secondary", search):
      search = "secondary dns"
    if re.search("receiver", search):
      search = "receiver ip"
    counter = 0
    html_string = str(html_doc)
    html_lines  = html_string.split("\n")
    for html_line in html_lines:
      if re.search(r"{}".format(search), html_line.lower()) and not re.search("confirm", html_line.lower()):
        next_line = html_lines[counter+1]
        if not re.search("value=", next_line):
          test_line = html_lines[counter+2]
          if re.search("value=", test_line):
            next_line = html_lines[counter+2]
          else:
            if re.search(r"^\<", next_line):
              next_line = html_lines[counter+2]
        if re.search("value=", next_line):
          value = next_line.split("value=")[1]
          value = value.split('"')[1]
        else:
          html = BeautifulSoup(next_line, features='lxml')
          value = html.text
        print(value)
        return
      counter = counter+1

# Get AMT value

def get_amt_value(get_value, ip, username, password, driver, http_proto, search):
  sub_value = ""
  if not re.search(r"[A-Z]|[a-z]|[0-9]", search):
    search = ""
  if get_value == "bios":
    get_value = "system"
    sub_value = "bios"
    if not re.search(r"[A-Z]|[a-z]|[0-9]", search):
      search    = "Version"
  if get_value == "model":
    get_value = "system"
    sub_value = "model"
  if get_value == "serial":
    get_value = "system"
    sub_value = "serial"
  if http_proto == "http":
    port_no = "16992"
  else:
    port_no = "16993"
  base_url = get_base_url(http_proto, username, password, ip, port_no)
  full_url = "%s/index.htm" % (base_url)
  if re.search("model|version|serial|release|system", get_value):
    full_url = "%s/hw-sys.htm" % (base_url)
  if re.search("disk", get_value):
    full_url = "%s/hw-disk.htm" % (base_url)
  if re.search("network", get_value):
    full_url = "%s/ip.htm" % (base_url)
  if re.search("memory", get_value):
    full_url = "%s/hw-mem.htm" % (base_url)
  if re.search(r"events|fqdn", get_value):
    full_url = "%s/%s.htm" % (base_url, get_value)
  if re.search("remote|power", get_value):
    full_url  = "%s/remote.htm" % (base_url)
    get_value = re.sub("power", "state", get_value)
  if re.search("processor|cpu|socket|family|manufacturer|speed", get_value):
    full_url  = "%s/hw-proc.htm" % (base_url)
    get_value = re.sub("cpu", "version", get_value)
  if verbose_mode:
    string = "Information:\tConnecting to: %s" % (full_url)
    handle_output(string)
  alert = driver.get(full_url)
  html_doc  = driver.page_source
  html_doc  = BeautifulSoup(html_doc, features='lxml')
  html_data = html_doc.find_all('td', 'maincell')
  if re.search(r"state", get_value):
    html_data = str(html_data).split("<td>")
  else:
    html_data = str(html_data).split("<tr>")
  new_data = []
  for html_line in html_data:
    temp_data = html_line.split("\n")
    for temp_line in temp_data:
      if not re.search("hidden", temp_line):
        new_data.append(temp_line)
  html_data = new_data
  results   = []
  if re.search("processor|system|memory|disk|event|fqdn|network", get_value):
    temp_data = []
    counter   = 0
    for html_line in html_data:
      html_text  = str(html_line)
      if debug_mode:
        handle_output(html_text)
      if not re.search(r"hidden|onclick|colspan", html_text):
        html_text  = re.sub(r"^\<\/td\>", "", html_text)
        html_text  = re.sub(r"\<br\/\>", ",", html_text)
        plain_text = BeautifulSoup(html_text, features='lxml').get_text()
        plain_text = re.sub(r"\s+", " ", plain_text)
        plain_text = re.sub(r"^ | $", "", plain_text)
        if re.search("event", get_value):
          if re.search("border=", html_text):
            if counter == 5:
              temp_data.append(plain_text)
            else:
              temp_text = (",").join(temp_data)
              if re.search(r"[A-Z]|[a-z]|[0-9]", plain_text):
                results.append(temp_text)
                temp_data = []
              temp_data.append(plain_text)
          else:
            if re.search(r"[A-Z]|[a-z]|[0-9]", plain_text):
              temp_data.append(plain_text)
        else:
          if re.search(r"\<\/h1\>|\<\/h2\>", html_text):
            results.append(plain_text)
          else:
            if re.search(r"\<\/p\>", html_text):
              if re.search("checkbox", html_text):
                param = plain_text
                if re.search("checked", html_text):
                  value = "Yes"
                else:
                  value = "No"
              else:
                param = plain_text
                html  = html_data[counter+1]
                html  = str(html)
                html  = re.sub(r"^\<\/td\>", "", html)
                text  = BeautifulSoup(html, features='lxml').get_text()
                if re.search("value=", html) and not re.search(r"[A-Z]|[a-z]|[0-9]", text):
                  value = html.split('"')[-2]
                else:
                  value = text
                if not re.search(r"[A-Z]|[a-z]|[0-9]", value):
                  html = html_data[counter+2]
                  html = str(html)
                  html = re.sub(r"^\<\/td\>", "", html)
                  text = BeautifulSoup(html, features='lxml').get_text()
                  if re.search("value=", html) and not re.search(r"[A-Z]|[a-z]|[0-9]", text):
                    value = html.split('"')[-2]
                  else:
                    value = text
              plain_text = "%s: %s" % (param, value)
              plain_text = re.sub("::", ":", plain_text)
              plain_text = re.sub(r"\s+$", "", plain_text)
              plain_text = re.sub(r":$", "", plain_text)
              if re.search(r"[A-Z]|[a-z]|[0-9]", plain_text):
                results.append(plain_text)
      counter = counter+1
  if re.search("processor|system|memory|disk|event|fqdn|network", get_value):
    found = False
    for result in results:
      if debug_mode:
        handle_output(result)
      if re.search(r"[a-z]", sub_value):
        if re.search(sub_value, result.lower()):
          found = True
        if re.search(r"[A-Z]|[a-z]|[0-9]", search):
          if re.search(search, result) and found:
            handle_output(result)
            if re.search(r":", result):
              result = result.split(": ")[1]
            return(result)
        else:
          if re.search(sub_value, result.lower()):
            handle_output(result)
            if re.search(r":", result):
              result = result.split(": ")[1]
            return(result)
      else:
        if re.search(r"[A-Z]|[a-z]|[0-9]", search):
          if re.search(search, result):
            handle_output(result)
        else:
          handle_output(result)
  return

# Set AMT value

def set_amt_value(ip, username, password, driver, http_proto, hostname, dommainname, primarydns, secondarydns, power, dryrun):
  if http_proto == "http":
    port_no = "16992"
  else:
    port_no = "16993"
  base_url = get_base_url(http_proto, username, password, ip, port_no)
  if dryrun:
    if re.search(r"[a-z]", hostname):
      handle_output("Information:\tDry run: would set Hostname to %s" % (hostname))
    if re.search(r"[a-z]", domainname):
      handle_output("Information:\tDry run: would set Domainname to %s" % (domainname))
    if re.search(r"[a-z,0-9]", primarydns):
      handle_output("Information:\tDry run: would set Primary DNS to %s" % (primarydns))
    if re.search(r"[a-z,0-9]", secondarydns):
      handle_output("Information:\tDry run: would set Secondary DNS to %s" % (secondarydns))
    if re.search(r"[a-z]", power):
      handle_output("Information:\tDry run: would send power %s to %s" % (power, ip))
    return
  if re.search(r"[a-z]", hostname) or (r"[a-z]", domainname):
    full_url = "%s/fqdn.htm" % (base_url)
    if re.search(r"[a-z]", hostname):
      search = "HostName"
      driver.get(full_url)
      from selenium.webdriver.common.by import By
      field = driver.find_element(By.NAME, search)
      field.clear()
      field.send_keys(hostname)
      string = "Information:\tSetting Hostname to %s" % (hostname)
      handle_output(string)
      driver.find_element(By.XPATH, '//input[@value="   Submit   "]').click()
    if re.search(r"[a-z]", domainname):
      search = "DomainName"
      driver.get(full_url)
      from selenium.webdriver.common.by import By
      field = driver.find_element(By.NAME, search)
      field.clear()
      field.send_keys(domainname)
      string = "Information:\tSetting Domainname to %s" % (domainname)
      handle_output(string)
      driver.find_element(By.XPATH, '//input[@value="   Submit   "]').click()
  if re.search(r"[a-z,0-9]", primarydns) or (r"[a-z,0-9]", secondarydns):
    full_url = "%s/ip.htm" % (base_url)
    if re.search(r"[a-z,0-9]", primarydns):
      search = "DNSServer"
      driver.get(full_url)
      from selenium.webdriver.common.by import By
      field = driver.find_element(By.NAME, search)
      field.clear()
      field.send_keys(primarydns)
      string = "Information:\tSetting Primary DNS to %s" % (primarydns)
      handle_output(string)
      driver.find_element(By.XPATH, '//input[@value="   Submit   "]').click()
    if re.search(r"[a-z,0-9]", secondarydns):
      search = "AlternativeDns"
      driver.get(full_url)
      from selenium.webdriver.common.by import By
      field = driver.find_element(By.NAME, search)
      field.clear()
      field.send_keys(secondarydns)
      string = "Information:\tSetting Secondary DNS to %s" % (secondarydns)
      handle_output(string)
      driver.find_element(By.XPATH, '//input[@value="   Submit   "]').click()
  if re.search(r"[a-z]", power):
    full_url = "%s/remote.htm" % (base_url)
    power    = power.lower()
    if re.search(r"off", power):
      radio = "1"
    elif re.search(r"cycle", power):
      radio = "3"
    elif re.search(r"reset", power):
      radio = "4"
    elif re.search(r"on", power):
      radio = "2"
    else:
      handle_output("Warning:\tInvalid power state: %s" % (power))
      return
    driver.get(full_url)
    driver.find_element(By.XPATH, '//input[@value="%s"]' % (radio)).click()
    from selenium.webdriver.common.by import By
    driver.find_element(By.XPATH, '//input[@value="Send Command"]').click()
    time.sleep(2)
    object = driver.switch_to.alert
    time.sleep(2)
    object.accept()
    string = "Information:\tSending power %s to %s (Intel AMT has a 30s pause before operation is done)" % (power, ip)
    handle_output(string)
  return

# Compare versions

def compare_versions(bios, avail, oob_type):
  if oob_type == "amt":
    if not bios or not avail:
      handle_output("Warning:\tUnable to determine BIOS versions to compare")
      return
    parts = bios.split(".")
    if len(parts) < 3:
      handle_output("Warning:\tUnable to parse current BIOS version: %s" % (bios))
      return
    current = parts[2].strip()
    avail   = avail.strip()
    if current.isdigit() and avail.isdigit():
      current = int(current)
      avail   = int(avail)
    if avail > current:
      handle_output("Information:\tNewer version of BIOS available")
    if avail == current:
      handle_output("Information:\tLatest version of BIOS installed")
  return

# Run a command, or just print it when doing a dry run

def run_command(command, dryrun):
  if dryrun:
    print(command)
  else:
    os.system(command)
  return

# Get console output

def get_console_output(command):
  if verbose_mode:
    string = "Executing:\t%s" % (command)
    handle_output(string)
  process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, )
  output  = process.communicate()[0].decode()
  if verbose_mode:
    string = "Output:\t\t%s" % (output)
    handle_output(string)
  return output

# Check local config

def check_local_config(dryrun):
  pkg_list = [ "geckodriver", "amtterm", "npm", "ipmitool" ]
  output  = get_console_output("uname -a")
  pkg_dir = None
  if re.search("Darwin", output):
    if os.path.exists("/usr/local/bin/brew"):
      pkg_dir  = "/usr/local/bin"
    else:
      if os.path.exists("/opt/homebrew/bin/brew"):
        pkg_dir  = "/opt/homebrew/bin"
    if pkg_dir == None:
      handle_output("Warning:\tHomebrew not found, unable to install: %s" % (" ".join(pkg_list)))
      return
    brew_bin = "%s/brew" % (pkg_dir)
    for pkg_name in pkg_list:
      pkg_bin = "%s/%s" % (pkg_dir, pkg_name)
      if not os.path.exists(pkg_bin):
        command = "%s install %s" % (brew_bin, pkg_name)
        if dryrun:
          print(command)
        else:
          output  = get_console_output(command)
  return

# Check mesh config

def check_mesh_config(mesh_bin, dryrun):
  l_mesh_dir = "./%s" % (mesh_bin)
  l_mesh_bin = "./%s/%s" % (mesh_bin, mesh_bin)
  g_mesh_dir = "/usr/local/lib/node_modules/%s" % (mesh_bin)
  g_mesh_bin = "/usr/local/lib/node_modules/%s/%s" % (mesh_bin, mesh_bin)
  l_node_dir = "./%s/node_modules/%s" % (mesh_bin, mesh_bin)
  g_node_dir = "/usr/local/lib/node_modules/%s" % (mesh_bin)
  if not os.path.exists(l_mesh_bin) and not os.path.exists(g_mesh_bin):
    if not os.path.exists(l_mesh_dir):
      command = "cd %s ; npm install %s" % (l_mesh_dir, mesh_bin)
      if dryrun:
        print("mkdir %s" % (l_mesh_dir))
        print(command)
      else:
        os.mkdir(l_mesh_dir)
        output  = get_console_output(command)
        if verbose_mode:
           handle_output(output)
  return

# Start MeshCommander

def start_mesh(mesh_bin, mesh_port, dryrun):
  l_node_dir = "./%s/node_modules/%s" % (mesh_bin, mesh_bin)
  g_node_dir = "/usr/local/lib/node_modules/%s" % (mesh_bin)
  if os.path.exists(l_node_dir):
    command = "cd %s ; node %s --port %s" % (l_node_dir, mesh_bin, mesh_port)
    run_command(command, dryrun)
  else:
    if os.path.exists(g_node_dir):
      command = "cd %s ; node %s --port %s" % (g_node_dir, mesh_bin, mesh_port)
      run_command(command, dryrun)
    else:
      if dryrun:
        command = "cd %s ; node %s --port %s" % (l_node_dir, mesh_bin, mesh_port)
        print(command)
      else:
        string = "%s not installed" % (mesh_bin)
        handle_output(string)
  return

# Read entries (host, username, password) from ~/.goatpass

def get_pass_entries():
  entries   = []
  pass_file = "%s/.%s" % (home_dir, password_db)
  if os.path.exists(pass_file):
    with open(pass_file, "r") as file:
      for line in file.readlines():
        line = line.rstrip("\r\n")
        if not re.search(r"[A-Za-z0-9]", line):
          continue
        items = line.split(":", 2)
        while len(items) < 3:
          items.append("")
        entries.append(tuple(items))
  return entries

# Get IPs

def get_ips():
  ips = []
  for (file_ip, file_user, file_pass) in get_pass_entries():
    ips.append(file_ip)
  return ips

# Get username

def get_username(ip):
  if re.search(r"[a-z]|[0-9]", ip):
    for (file_ip, file_user, file_pass) in get_pass_entries():
      if file_ip == ip and file_user:
        return file_user
  return default_user

# Get password

def get_password(ip, username):
  prompt = "Password for %s:" % (ip)
  for (file_ip, file_user, file_pass) in get_pass_entries():
    if file_ip == ip and file_user == username and file_pass:
      return file_pass
  return getpass.getpass(prompt=prompt, stream=None)

# Sol to host

def sol_to_host(ip, username, password, oob_type, dryrun):
  if oob_type == "amt":
    command = "export AMT_PASSWORD=\"%s\" ; amtterm %s" % (password, ip)
  else:
    command = "ipmitool -I lanplus -U %s -P %s -H %s sol activate" % (username, password, ip)
  if dryrun:
    print(command)
    return
  if verbose_mode:
    string = "Executing:\t%s" % (command)
    handle_output(string)
  os.system(command)
  return

# Initiate web client

def start_web_driver():
  if not debug_mode:
    from selenium.webdriver.firefox.options import Options
    options = Options()
    options.add_argument("-headless")
    driver = webdriver.Firefox(options=options)
  else:
    driver = webdriver.Firefox()
  return driver

# Close web client

def quit_web_driver(driver):
  if driver:
    try:
      driver.quit()
    except Exception:
      pass
  return

# Run meshcmd

def mesh_command(ip, meshcmd, meshcmd_bin, dryrun):
  if platform.system() == "Darwin":
    handle_output("Warning:\tMeshCmd is not available for Mac OS")
    return
  if not os.path.exists(meshcmd_bin):
    meshcmd_url = "https://github.com/lateralblast/goat/blob/master/meshcmd/%s?raw=true" % (meshcmd_name)
    download_file(meshcmd_url, meshcmd_bin, dryrun)
  if not os.access(meshcmd_bin, os.X_OK) and not dryrun:
    command = "chmod +x %s" % (meshcmd_bin)
    os.system(command)
  if meshcmd == "help":
    command = "%s" % (meshcmd_bin)
  else:
    if re.search(r"[0-9]", ip):
      status = check_ping(ip)
      if not status:
        return
      username = get_username(ip)
      password = get_password(ip, username)
      command  = "sudo %s %s --host %s --user %s --pass %s" % (meshcmd_bin, meshcmd, ip, username, password)
    else:
      command  = "sudo %s %s" % (meshcmd_bin, meshcmd)
  handle_output(command)
  if dryrun:
    return
  os.system(command)
  return

# Initiate SSH Session

def start_ssh_session(ip, username, password):
  ssh_command = "ssh -o StrictHostKeyChecking=no"
  ssh_command = "%s %s@%s" % (ssh_command, username, ip)
  ssh_session = pexpect.spawn(ssh_command)
  ssh_session.expect("assword: ")
  ssh_session.sendline(password)
  return ssh_session

# Build the racadm command to set a specific iDRAC value

def get_idrac_set_command(group, parameter, value):
  if re.search(r"lan|network", group):
    group = "cfgLanNetworking"
  elif re.search(r"server", group):
    group = "cfgServerInfo"
  elif re.search(r"serial", group):
    group = "cfgSerial"
  if re.search(r"[A-Za-z]", group):
    command = "racadm config -g %s -o %s %s" % (group, parameter, value)
  else:
    command = "racadm set %s %s" % (parameter, value)
  return command

# Set a list of iDRAC values from a file

def set_specific_idrac_values(ip, username, password, file_array, dryrun):
  if not dryrun:
    ssh_session = start_ssh_session(ip, username, password)
  for line in file_array:
    line = line.strip()
    if not line or line.startswith("#"):
      continue
    items = [item.strip() for item in line.split(",")]
    if len(items) > 2:
      group = items[0]
      value = items[2]
      parameter = items[1]
    else:
      if len(items) < 2:
        handle_output("Warning:\tSkipping invalid line: %s" % (line))
        continue
      group = ""
      value = items[1]
      parameter = items[0]
    command = get_idrac_set_command(group, parameter, value)
    if dryrun:
      print(command)
    else:
      ssh_session.expect("/admin1-> ")
      ssh_session.sendline(command)
      ssh_session.expect("/admin1-> ")
      output = ssh_session.before
      output = output.decode()
      if verbose_mode:
        text = "Executing:\t%s" % (command)
        handle_output(text)
        text = "Output:\t\t%s" % (output)
        handle_output(text)
  if not dryrun:
    ssh_session.close()
  return

# Set specific know iDRAC value

def set_specific_idrac_value(ip, username, password, group, parameter, value, dryrun):
  command = get_idrac_set_command(group, parameter, value)
  if dryrun:
    print(command)
  else:
    ssh_session = start_ssh_session(ip, username, password)
    ssh_session.expect("/admin1-> ")
    ssh_session.sendline(command)
    ssh_session.expect("/admin1-> ")
    output = ssh_session.before
    output = output.decode()
    if verbose_mode:
      text = "Executing:\t%s" % (command)
      handle_output(text)
      text = "Output:\t\t%s" % (output)
      handle_output(text)
    ssh_session.close()
  return

# Get general iDRAC value

def set_idrac_value(ip,username, password, hostname, domainname, netmask, gateway, primarydns, secondarydns, primaryntp, secondaryntp, primarysyslog, secondarysyslog, syslogport, power, dryrun):
  commands = []
  if re.search(r"[a-z,0-9]", hostname):
    command = "racadm config -g cfgLanNetworking -o cfgDNSRacName %s" % (hostname)
    commands.append(command)
  if re.search(r"[a-z,0-9]", domainname):
    command = "racadm config -g cfgLanNetworking -o cfgDNSDomainNameFromDHCP 0"
    commands.append(command)
    command = "racadm config -g cfgLanNetworking -o cfgDNSDomainName %s" % (domainname)
    commands.append(command)
  if re.search(r"[0-9]", netmask):
    command = "racadm config -g cfgLanNetworking -o cfgNicNetmask %s" % (netmask)
    commands.append(command)
  if re.search(r"[0-9]", gateway):
    command = "racadm config -g cfgLanNetworking -o cfgNicGateway %s" % (gateway)
    commands.append(command)
  if re.search(r"[0-9]", primarydns):
    command = "racadm config -g cfgLanNetworking -o cfgDNSServersFromDHCP 0"
    commands.append(command)
    command = "racadm config -g cfgLanNetworking -o cfgDNSServer1 %s" % (primarydns)
    commands.append(command)
  if re.search(r"[0-9]", secondarydns):
    command = "racadm config -g cfgLanNetworking -o cfgDNSServersFromDHCP 0"
    commands.append(command)
    command = "racadm config -g cfgLanNetworking -o cfgDNSServer2 %s" % (secondarydns)
    commands.append(command)
  if re.search(r"[a-z,0-9]", primaryntp):
    command = "racadm config -g cfgLanNetworking -o cfgRhostsNtpEnable 1"
    commands.append(command)
    command = "racadm config -g cfgLanNetworking -o cfgRhostsNtpServer1 %s" % (primaryntp)
    commands.append(command)
  if re.search(r"[a-z,0-9]", secondaryntp):
    command = "racadm config -g cfgLanNetworking -o cfgRhostsNtpEnable 1"
    commands.append(command)
    command = "racadm config -g cfgLanNetworking -o cfgRhostsNtpServer2 %s" % (secondaryntp)
    commands.append(command)
  if re.search(r"[a-z,0-9]", primarysyslog):
    command = "racadm config -g cfgLanNetworking -o cfgRhostsSyslogEnable 1"
    commands.append(command)
    command = "racadm config -g cfgLanNetworking -o cfgRhostsSyslogServer1 %s" % (primarysyslog)
    commands.append(command)
  if re.search(r"[a-z,0-9]", secondarysyslog):
    command = "racadm config -g cfgLanNetworking -o cfgRhostsSyslogEnable 1"
    commands.append(command)
    command = "racadm config -g cfgLanNetworking -o cfgRhostsSyslogServer2 %s" % (secondarysyslog)
    commands.append(command)
  if re.search(r"[0-9]", syslogport):
    command = "racadm config -g cfgLanNetworking -o cfgRhostsSyslogEnable 1"
    commands.append(command)
    command = "racadm config -g cfgLanNetworking -o cfgRhostsSyslogPort %s" % (syslogport)
    commands.append(command)
  if re.search(r"[a-z]", power):
    power = re.sub(r"on", "up", power)
    power = re.sub(r"off", "down", power)
    if not re.search(r"^power", power):
      power = "power%s" % (power)
    command = "racadm serveraction %s" % (power)
    commands.append(command)
  if dryrun:
    for command in commands:
      print(command)
  else:
    ssh_session = start_ssh_session(ip, username, password)
    ssh_session.expect("/admin1-> ")
    for command in commands:
      ssh_session.sendline(command)
      ssh_session.expect("/admin1-> ")
      output = ssh_session.before
      output = output.decode()
      if verbose_mode:
        text = "Executing:\t%s" % (command)
        handle_output(text)
        text = "Output:\t\t%s" % (output)
        handle_output(text)
    ssh_session.close()
  return

# Get iDRAC value

def get_idrac_value(get_value, ip, username, password):
  ssh_session = start_ssh_session(ip, username, password)
  ssh_session.expect("/admin1-> ")
  if re.search(r"bios|idrac|usc", get_value.lower()):
    command = "racadm getversion"
  else:
    command = "racadm getsysinfo"
  ssh_session.sendline(command)
  ssh_session.expect("/admin1-> ")
  output = ssh_session.before
  output = output.decode()
  ssh_session.sendline("exit")
  ssh_session.close()
  lines = output.split("\r\n")
  for line in lines:
    line  = line.strip()
    regex = r'\b(?=\w){0}\b(?!\w)'.format(get_value)
    if re.search(get_value, line, re.IGNORECASE):
      line = re.sub(r" \s+", " ", line)
      handle_output(line)
  return

# Get IPMI value

def get_ipmi_value(get_value, ip, username, password):
  command = "ipmitool -I lanplus -U %s -P %s -H %s %s" % (username, password, ip, get_value)
  handle_output(command)
  os.system(command)
  return

# Set IPMI value

def set_ipmi_value(set_value, ip, username, password, dryrun):
  command = "ipmitool -I lanplus -U %s -P %s -H %s %s" % (username, password, ip, set_value)
  handle_output(command)
  if dryrun:
    return
  os.system(command)
  return

# Use javaws to iDRAC KVM

def java_idrac_kvm(ip, port, username, password, home_dir, dryrun):
  import tempfile
  web_url = "https://%s" % (ip)
  command = "which javaws"
  output  = os.popen(command).read()
  if not re.search(r"^/", output):
    output = "Warning:\tNo Java installation found"
    handle_output(output)
    sys.exit()
  if dryrun:
    print("javaws <temporary file>.jnlp")
    return
  command  = "uname -a"
  os_name  = os.popen(command).read()
  if re.search(r"^Darwin", os_name):
    command = "java --version"
    version = os.popen(command).read()
    if re.search(r"Oracle", version):
      exceptions = "%s/Library/Application Support/Oracle/Java/Deployment/security/exception.sites" % (home_dir)
      if os.path.exists(exceptions):
        with open(exceptions) as file:
          if not web_url in file.read():
            with open(exceptions, 'a') as file:
              file.write(web_url)
              file.write("\n")
      else:
        with open(exceptions, 'a') as file:
          file.write(web_url)
          file.write("\n")
  data = []
  data.append('<?xml version="1.0" encoding="UTF-8"?>')
  string = '<jnlp codebase="%s" spec="1.0+">' % (web_url)
  data.append(string)
  data.append('<information>')
  data.append('  <title>Virtual Console Client</title>')
  data.append('  <vendor>Dell Inc.</vendor>')
  string = '  <icon href="%s/images/logo.gif" kind="splash"/>' % (web_url)
  data.append(string)
  data.append('  <shortcut online="true"/>')
  data.append('</information>')
  data.append('<application-desc main-class="com.avocent.idrac.kvm.Main">')
  string = '  <argument>ip=%s</argument>' % (ip)
  data.append(string)
  data.append('  <argument>vm=1</argument>')
  string = '  <argument>title=%s</argument>' % (ip)
  data.append(string)
  string = '  <argument>user=%s</argument>' % (username)
  data.append(string)
  string = '  <argument>password=%s</argument>' % (password)
  data.append(string)
  string = '  <argument>kmport=%s</argument>' % (port)
  data.append(string)
  string = '  <argument>vport=%s</argument>' % (port)
  data.append(string)
  data.append('  <argument>apcp=1</argument>')
  data.append('  <argument>reconnect=2</argument>')
  data.append('  <argument>chat=1</argument>')
  data.append('  <argument>F1=1</argument>')
  data.append('  <argument>custom=0</argument>')
  data.append('  <argument>scaling=15</argument>')
  data.append('  <argument>minwinheight=100</argument>')
  data.append('  <argument>minwinwidth=100</argument>')
  data.append('  <argument>videoborder=0</argument>')
  data.append('  <argument>version=2</argument>')
  data.append('</application-desc>')
  data.append('<security>')
  data.append('  <all-permissions/>')
  data.append('</security>')
  data.append('<resources>')
  data.append('  <j2se version="1.6+"/>')
  string = '  <jar href="%s/software/avctKVM.jar" download="eager" main="true" />' % (web_url)
  data.append(string)
  data.append('</resources>')
  data.append('<resources os="Windows" arch="x86">')
  string = '  <nativelib href="%s/software/avctKVMIOWin32.jar" download="eager"/>' % (web_url)
  data.append(string)
  string = '  <nativelib href="%s/software/avctVMAPI_DLLWin32.jar" download="eager"/>' % (web_url)
  data.append(string)
  data.append('</resources>')
  data.append('<resources os="Windows" arch="amd64">')
  string = '  <nativelib href="%s/software/avctKVMIOWin64.jar" download="eager"/>' % (web_url)
  data.append(string)
  string = '  <nativelib href="%s/software/avctVMAPI_DLLWin64.jar" download="eager"/>' % (web_url)
  data.append(string)
  data.append('</resources>')
  data.append('<resources os="Windows" arch="x86_64">')
  string = '  <nativelib href="%s/software/avctKVMIOWin64.jar" download="eager"/>' % (web_url)
  data.append(string)
  string = '  <nativelib href="%s/software/avctVMAPI_DLLWin64.jar" download="eager"/>' % (web_url)
  data.append(string)
  data.append('</resources>')
  data.append('<resources os="Linux" arch="x86">')
  string = '  <nativelib href="%s/software/avctKVMIOLinux32.jar" download="eager"/>' % (web_url)
  data.append(string)
  string = '  <nativelib href="%s/software/avctVMAPI_DLLLinux32.jar" download="eager"/>' % (web_url)
  data.append(string)
  data.append('</resources>')
  data.append('<resources os="Linux" arch="i386">')
  string = '  <nativelib href="%s/software/avctKVMIOLinux32.jar" download="eager"/>' % (web_url)
  data.append(string)
  string = '  <nativelib href="%s/software/avctVMAPI_DLLLinux32.jar" download="eager"/>' % (web_url)
  data.append(string)
  data.append('</resources>')
  data.append('<resources os="Linux" arch="i586">')
  string = '  <nativelib href="%s/software/avctKVMIOLinux32.jar" download="eager"/>' % (web_url)
  data.append(string)
  string = '  <nativelib href="%s/software/avctVMAPI_DLLLinux32.jar" download="eager"/>' % (web_url)
  data.append(string)
  data.append('</resources>')
  data.append('<resources os="Linux" arch="i686">')
  string = '  <nativelib href="%s/software/avctKVMIOLinux32.jar" download="eager"/>' % (web_url)
  data.append(string)
  string = '  <nativelib href="%s/software/avctVMAPI_DLLLinux32.jar" download="eager"/>' % (web_url)
  data.append(string)
  data.append('</resources>')
  data.append('<resources os="Linux" arch="amd64">')
  string = '  <nativelib href="%s/software/avctKVMIOLinux64.jar" download="eager"/>' % (web_url)
  data.append(string)
  string = '  <nativelib href="%s/software/avctVMAPI_DLLLinux64.jar" download="eager"/>' % (web_url)
  data.append(string)
  data.append('</resources>')
  data.append('<resources os="Linux" arch="x86_64">')
  string = '  <nativelib href="%s/software/avctKVMIOLinux64.jar" download="eager"/>' % (web_url)
  data.append(string)
  string = '  <nativelib href="%s/software/avctVMAPI_DLLLinux64.jar" download="eager"/>' % (web_url)
  data.append(string)
  data.append('</resources>')
  data.append('<resources os="Mac OS X" arch="x86_64">')
  string = '  <nativelib href="%s/software/avctKVMIOMac64.jar" download="eager"/>' % (web_url)
  data.append(string)
  string = '  <nativelib href="%s/software/avctVMAPI_DLLMac64.jar" download="eager"/>' % (web_url)
  data.append(string)
  data.append('</resources>')
  data.append('</jnlp>')
  file_desc, xml_file = tempfile.mkstemp(suffix=".jnlp")
  with os.fdopen(file_desc, 'w') as file:
    for item in data:
      file.write("%s\n" % item)
  command = "javaws %s" % (xml_file)
  os.system(command)

# Set APC power

def set_apc_power(power, ip, outlet, username, password, dryrun):
  power = power.lower()
  if not power in [ "on", "off" ]:
    handle_output("Warning:\tInvalid power state for APC PDU: %s (use on or off)" % (power))
    return
  command = "ssh -V 2>&1 |cut -f1 -d, |cut -f2 -d_"
  output  = os.popen(command).read()
  version = output.rstrip()
  major   = version.split(".")[0]
  major   = int(major)
  minor   = version.split(".")[1]
  minor   = minor.split("p")[0]
  minor   = int(minor)
  ssh_opt = "-oKexAlgorithms=+diffie-hellman-group1-sha1 -oStrictHostKeyChecking=no"
  if major > 7:
    command = "which docker"
    output  = os.popen(command).read()
    if not re.search(r"^/", output):
      output = "Warning:\tNo docker installation found"
      handle_output(output)
      sys.exit()
    string  = "Docker old SSH version tool"
    command = "docker images |grep ostrich"
    output  = os.popen(command).read()
    if not re.search(r"ostrich", output) and dryrun:
      print("docker build -t ostrich <temporary directory with ubuntu:16.04 and openssh-client>")
    elif not re.search(r"ostrich", output):
      import tempfile
      output = "Information:\tInstalling %s" % (string)
      handle_output(output)
      build_dir = tempfile.mkdtemp()
      with open("%s/Dockerfile" % (build_dir), 'w') as file:
        file.write("FROM ubuntu:16.04\n")
        file.write("RUN apt-get update && apt-get install -y openssh-client\n")
      command = "docker build -t ostrich %s" % (build_dir)
      if verbose_mode:
        handle_output("Executing:\t%s" % (command))
      output  = os.popen(command).read()
      if verbose_mode:
        handle_output(output)
      command = "docker images |grep ostrich"
      output  = os.popen(command).read()
      if not re.search(r"ostrich", output):
        handle_output("Warning:\tFailed to build %s" % (string))
        return
    command = "docker run --rm -it ostrich /bin/bash -c \"ssh %s %s@%s\"" % (ssh_opt, username, ip)
  else:
    command = "ssh %s %s@%s" % (ssh_opt, username, ip)
  if dryrun:
    print(command)
    print("Would set outlet %s to %s" % (outlet, power))
    return
  #child.expect("")
  #child.sendline("")
  outlet = str(outlet)
  outlet = "%s\r" % (outlet)
  child  = pexpect.spawnu(command)
  if verbose_mode:
    child.logfile = sys.stdout
  child.expect("password: ")
  child.sendline(password)
  child.expect("- Control Console -")
  child.sendline("1\r")
  child.expect("- Device Manager -")
  child.sendline("2\r")
  child.expect("- Outlet Management -")
  child.sendline("1\r")
  child.expect("- Outlet Control/Configuration -")
  child.sendline(outlet)
  child.expect("1- Control Outlet")
  child.sendline("1\r")
  child.expect("- Control Outlet -")
  if power == "on":
    child.sendline("1\r")
  else:
    child.sendline("2\r")
  child.expect("YES")
  child.sendline("YES\r")
  child.expect("ENTER")
  child.sendline("\r")
  child.expect("- Control Outlet -")
  child.sendline("\033")
  child.expect(" 1- Control Outlet")
  child.sendline("\033")
  child.expect("- Outlet Control/Configuration -")
  child.sendline("\033")
  child.expect("- Outlet Management -")
  child.sendline("\033")
  child.expect("- Device Manager -")
  child.sendline("\033")
  child.expect("- Control Console -")
  child.sendline("4\r")
  child.close()
  return

# Use docker container to drive iDRAC KVM

def web_idrac_kvm(ip, port, username, password, dryrun):
  string  = "Docker iDRAC KVM redirection tool"
  command = "which docker"
  output  = os.popen(command).read()
  if not re.search(r"^/", output):
    output = "Warning:\tNo docker installation found"
    handle_output(output)
    sys.exit()
  command = "docker images |grep idrac6"
  output  = os.popen(command).read()
  if not re.search(r"idrac6", output):
    output = "Information:\tInstalling %s" % (string)
    handle_output(output)
    command = "docker pull domistyle/idrac6"
    if dryrun:
      print(command)
    else:
      if verbose_mode:
        output = "Executing:\t%s" % (command)
        handle_output(output)
      output  = os.popen(command).read()
      if verbose_mode:
        handle_output(output)
  command = "docker ps |grep idrac |awk '{print $1}'"
  process = os.popen(command).read()
  process = process.rstrip()
  if re.search(r"[0-9]", process):
    output = "Warning:\tInstance of %s already running" % (string)
    handle_output(output)
    if kill_mode:
      output = "Information:\tStopping existing %s instance" % (string)
      handle_output(output)
      command = "docker kill %s" % (process)
      if dryrun:
        print(command)
      else:
        output  = os.popen(command).read()
        if verbose_mode:
          handle_output(output)
    else:
      sys.exit()
  command = "docker run -d -p %s:%s -p 5900:5900 -e IDRAC_HOST=%s -e IDRAC_USER=%s -e IDRAC_PASSWORD=%s domistyle/idrac6" % (port, port, ip, username, password)
  if dryrun:
    print(command)
    return
  if verbose_mode:
    output = "Executing:\t%s" % (command)
    handle_output(output)
  output = os.popen(command).read()
  if verbose_mode:
    handle_output(output)
  output = "Information:\tStarting %s at http://127.0.0.1:%s" % (string, port)
  handle_output(output)
  return

# Handle dryrun

if option["dryrun"]:
  dryrun = True
else:
  dryrun = False

# Handle type

if option["type"]:
  oob_type = option["type"]
  oob_type = oob_type.lower()
  if oob_type == "amt":
    default_user = "admin"
  if oob_type == "idrac":
    default_user = "root"
  if oob_type == "ipmi":
    default_user = "root"

# Handle version switch

if option["version"]:
  script_exe = sys.argv[0]
  print_version(script_exe)
  sys.exit()

# Handle verbose switch

if option["ip"]:
  string = ""
  ip     = option["ip"]
  test   = check_valid_ip(ip)
  if not test:
    string = "Warning:\tInvalid IP: %s" % (ip)
    handle_output(string)
    sys.exit()

# Handle options switch

if option["options"]:
  script_exe = sys.argv[0]
  print_options(script_exe)
  sys.exit()

# Load third party modules (not needed for -h, --version or --options)

# Load selenium

try:
  from selenium import webdriver
  from selenium.webdriver.common.by import By
except ImportError:
  install_and_import("selenium")
  from selenium import webdriver
  from selenium.webdriver.common.by import By

# Load bs4

try:
  from bs4 import BeautifulSoup
except ImportError:
  install_and_import("bs4")
  from bs4 import BeautifulSoup

# Load lxml

try:
  import lxml
except ImportError:
  install_and_import("lxml")
  import lxml

from lxml import etree

# load wget

try:
  import wget
except ImportError:
  install_and_import("wget")
  import wget

# load paraminko

try:
  import paramiko
except ImportError:
  install_and_import("paramiko")
  import paramiko

# Load pexpect

try:
  import pexpect
except ImportError:
  install_and_import("pexpect")
  import pexpect

# Handle insecure switch

if option["insecure"]:
  http_proto = "http"
else:
  http_proto = "https"

# Handle mask switch

if option["mask"]:
  mask_mode = True
else:
  mask_mode = False

# Handle username switch

if option["username"]:
  username = option["username"]
else:
  if option["avail"]:
    if option["ip"]:
      username = get_username(ip)
  else:
    if option["type"] and not option["allhosts"]:
      if option['type'] == "apc":
        username = get_username(ip)
      if option["meshcmd"]:
        if option["ip"]:
          username = get_username(ip)
      else:
        if not option["ip"]:
          output = "Warning:\tNo IP specified"
          handle_output(output)
          sys.exit()
        else:
          username = get_username(ip)

# Handle password switch

if option["password"]:
  password = option["password"]
else:
  if option["avail"]:
    if option["ip"]:
      username = get_username(ip)
  else:
    if option["type"] and option["ip"] and not option["allhosts"]:
      password = get_password(ip, username)

# Handle search switch

if option["search"]:
  search = option["search"]
else:
  search = ""

# Handle model switch

if option["model"]:
  model = option["model"]

# Handle verbose switch

if option["verbose"]:
  verbose_mode = True
else:
  verbose_mode = False

# Handle kill switch

if option["kill"]:
  kill_mode = True
else:
  kill_mode = False

# Handle verbose switch

if option["debug"]:
  debug_mode = True
else:
  debug_mode = False

# Handle get switch

if option["get"]:
  get_value = option["get"]

# Handle power switch

if option["power"]:
  power = option["power"]
else:
  power = ""

# Handle domainname switch

if option["domainname"]:
  domainname = option["domainname"]
else:
  domainname = ""

# Handle hostname switch

if option["hostname"]:
  hostname = option["hostname"]
else:
  hostname = ""

# Handle gateway switch

if option["gateway"]:
  gateway = option["gateway"]
else:
  gateway = ""

# Handle netmask switch

if option["netmask"]:
  netmask = option["netmask"]
else:
  netmask = ""

# Handle primarydns switch

if option["primarydns"]:
  primarydns = option["primarydns"]
else:
  primarydns = ""

# Handle primaryntp switch

if option["primaryntp"]:
  primaryntp = option["primaryntp"]
else:
  primaryntp = ""

# Handle primarysyslog switch

if option["primarysyslog"]:
  primarysyslog = option["primarysyslog"]
else:
  primarysyslog = ""

# Handle secondaryntp switch

if option["secondaryntp"]:
  secondaryntp = option["secondaryntp"]
else:
  secondaryntp = ""

# Handle secondarydns switch

if option["secondarydns"]:
  secondarydns = option["secondarydns"]
else:
  secondarydns = ""

# Handle secondarysyslog switch

if option["secondarysyslog"]:
  secondarysyslog = option["secondarysyslog"]
else:
  secondarysyslog = ""

# Handle syslogport switch

if option["syslogport"]:
  syslogport = option["syslogport"]
else:
  syslogport = ""

# Handle group, parameter and value switches

group     = option["group"] or ""
parameter = option["parameter"] or ""
value     = option["value"] or ""

# Handle avail switch

if option["avail"]:
  avail = option["avail"]

# Handle check switch

if option["check"]:
  check = option["check"]

# Handle port switch

if option["port"]:
  port = option["port"]
else:
  if option["type"]:
    if option["type"].lower() == "webidrac":
      port = "5800"
    if option["type"].lower() == "javaidrac":
      port = "5900"

# Handle outlet switch

if option['outlet']:
  outlet = option['outlet']
else:
  outlet = ""

# Handle boot switch

if option['boot']:
  boot = option['boot']

# Handle MeshCmd option

if option["meshcmd"]:
  meshcmd = option["meshcmd"]

# Handle meshcommander switch

if option["meshcommander"]:
  mesh_bin = "meshcommander"

# Handle meshcentral switch

if option["meshcentral"]:
  mesh_bin = "meshcentral"

# Handle download value

if option["download"]:
  download = True
else:
  download = False

# Run meshcommander

if option["meshcommander"] or option["meshcentral"]:
  if option["port"]:
    mesh_port = option["port"]
  check_mesh_config(mesh_bin, dryrun)
  start_mesh(mesh_bin, mesh_port, dryrun)
  sys.exit()

# If option meshcmd is used the type of OOB is AMT

if option["meshcmd"]:
  option["type"] = "amt"

# Handle vendor switch

if option["type"]:
  ips = []
  check_local_config(dryrun)
  oob_type = option["type"]
  oob_type = oob_type.lower()
  if option["allhosts"]:
    ips = get_ips()
  else:
    if option["avail"] and not option["ip"]:
      if not option["model"]:
        handle_output("Warning:\tNo model specified")
        sys.exit()
      else:
        driver = start_web_driver()
        get_web_amt_value(avail, model, driver, download, dryrun)
        quit_web_driver(driver)
    else:
      if option["ip"]:
        ips.append(ip)
      else:
        if option["meshcmd"]:
          ips.append("")
          password = ""
          username = ""
        else:
          output = "Warning:\tNo IP specified"
          handle_output(output)
          sys.exit()
  for ip in ips:
    driver = None
    if option["allhosts"]:
      username = get_username(ip)
      password = get_password(ip, username)
    if re.search(r"amt|idrac|ipmi", oob_type) and option["sol"]:
      status = check_ping(ip)
      if status:
        sol_to_host(ip, username, password, oob_type, dryrun)
        sys.exit()
    if oob_type == "webidrac":
      web_idrac_kvm(ip, port, username, password, dryrun)
    if oob_type == "javaidrac":
      java_idrac_kvm(ip, port, username, password, home_dir, dryrun)
    if oob_type == "apc":
      if option['set']:
        set_apc_power(power, ip, outlet, username, password, dryrun)
    if oob_type == "ipmi":
      status = check_ping(ip)
      if status:
        if option['get']:
          get_ipmi_value(get_value, ip, username, password)
        if option['boot']:
          set_value = "chassis bootparam set bootflag %s" % (boot)
          set_ipmi_value(set_value, ip, username, password, dryrun)
        if option['power']:
          set_value = "chassis power %s" % (power)
          set_ipmi_value(set_value, ip, username, password, dryrun)
    if oob_type == "idrac":
      status = check_ping(ip)
      if status:
        if option["get"]:
          bios = get_idrac_value(get_value, ip, username, password)
        if option["set"]:
          if option["file"]:
            file_array = file_to_array(option["file"])
            set_specific_idrac_values(ip, username, password, file_array, dryrun)
          else:
            if re.search(r"[A-Z,a-z]", parameter):
              set_specific_idrac_value(ip, username, password, group, parameter, value, dryrun)
            else:
              set_idrac_value(ip, username, password, hostname, domainname, netmask, gateway, primarydns, secondarydns, primaryntp, secondaryntp, primarysyslog, secondarysyslog, syslogport, power, dryrun)
    if oob_type == "sep":
      if option['get'] or not dryrun:
        driver = start_web_driver()
      if option['get']:
        status = check_ping(ip)
        if status:
          get_sep_value(get_value, ip, username, password, driver, http_proto, search)
      if option['set']:
        status = check_ping(ip)
        if status:
          set_sep_power(power, ip, outlet, username, password, driver, http_proto, dryrun)
    if oob_type == "amt":
      if option["meshcmd"]:
        mesh_command(ip, meshcmd, meshcmd_bin, dryrun)
      else:
        if option["get"] or option["check"] or option["avail"] or not dryrun:
          driver = start_web_driver()
      if option["check"]:
        status = check_ping(ip)
        if status:
          model   = get_amt_value("model", ip, username, password, driver, http_proto, search)
          current = get_amt_value(check, ip, username, password, driver, http_proto, search)
          avail   = get_web_amt_value(check, model, driver, download, dryrun)
          compare_versions(current, avail, oob_type)
      if option["avail"]:
        if not option["model"]:
          status = check_ping(ip)
          if status:
            username = get_username(ip)
            password = get_password(ip, username)
            model = get_amt_value("model", ip, username, password, driver, http_proto, search)
            get_web_amt_value(avail, model, driver, download, dryrun)
        else:
          get_web_amt_value(avail, model, driver, download, dryrun)
      if option["get"]:
        status = check_ping(ip)
        if status:
          get_amt_value(get_value, ip, username, password, driver, http_proto, search)
      if option["set"]:
        status = check_ping(ip)
        if status:
          set_amt_value(ip, username, password, driver, http_proto, hostname, domainname, primarydns, secondarydns, power, dryrun)
    quit_web_driver(driver)
else:
  handle_output("Warning:\tNo OOB type specified")
  sys.exit()

