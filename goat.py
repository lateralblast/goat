#!/usr/bin/env python3

# Name:         goat (General OOB Automation Tool)
# Version:      0.4.3
# Release:      1
# License:      CC-BA (Creative Commons By Attribution)
#               http://creativecommons.org/licenses/by/4.0/legalcode
# Group:        System
# Source:       N/A
# URL:          N/A
# Distribution: UNIX
# Vendor:       Lateral Blast
# Packager:     Richard Spindler <richard@lateralblast.com.au>
# Description:  Script to drive OOB management interfaces

# Import modules

import urllib.request
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
mesh_port    = "3000"
password_db  = "goatpass"
home_dir     = expanduser("~")
default_user = "admin"

# Check we have pip installed

try:
  from pip._internal import main
except ImportError:
  os.system("easy_install pip")
  os.system("pip install --upgrade pip")

# install and import a python module

def install_and_import(package):
  import importlib
  try:
    importlib.import_module(package)
  except ImportError:
    command = "python3 -m pip install --user %s" % (package)
    os.system(command)
  finally:
    globals()[package] = importlib.import_module(package)

# Load selenium

try:
  from selenium import webdriver
except ImportError:
  install_and_import("selenium")
  from selenium import webdriver

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

script_exe  = sys.argv[0]
script_dir  = os.path.dirname(script_exe)
uname_arch  = subprocess.check_output("uname -m",shell=True)
meshcmd_bin = "%s/meshcmd.%s" % (script_dir,uname_arch)

# Print help

def print_help(script_exe):
  print("\n")
  command    = "%s -h" % (script_exe)
  os.system(command)
  print("\n")

# Read a file into an array

def file_to_array(file_name):
  file_data  = open(file_name)
  file_array = file_data.readlines()
  return file_array

# If we have no command line arguments print help

if sys.argv[-1] == sys.argv[0]:
  print_help(script_exe)
  exit()

# Get command line arguments

parser = argparse.ArgumentParser()
parser.add_argument("--ip",required=False)                  # Specify IP of OOB/Remote Management interface
parser.add_argument("--username",required=False)            # Set Username
parser.add_argument("--type",required=False)                # Set Type of OOB device
parser.add_argument("--get",required=False)                 # Get Parameter
parser.add_argument("--password",required=False)            # Set Password
parser.add_argument("--search",required=False)              # Search output for value
parser.add_argument("--avail",required=False)               # Get available version from vendor (e.g. BIOS)
parser.add_argument("--check",required=False)               # Check current version against available version from vendor (e.g. BIOS)
parser.add_argument("--model",required=False)               # Specify model (can be used with --avail)
parser.add_argument("--port",required=False)                # Specify port to run service on
parser.add_argument("--power",required=False)               # Set power state (on, off, reset)
parser.add_argument("--hostname",required=False)            # Set hostname
parser.add_argument("--gateway",required=False)             # Set gateway
parser.add_argument("--netmask",required=False)             # Set netmask
parser.add_argument("--outlet",required=False)              # Set netmask
parser.add_argument("--domainname",required=False)          # Set dommainname
parser.add_argument("--primarydns",required=False)          # Set primary DNS
parser.add_argument("--secondarydns",required=False)        # Set secondary DNS
parser.add_argument("--primarysyslog",required=False)       # Set primary Syslog
parser.add_argument("--secondarysyslog",required=False)     # Set secondary Syslog
parser.add_argument("--syslogport",required=False)          # Set Syslog port
parser.add_argument("--primaryntp",required=False)          # Set primary NTP
parser.add_argument("--secondaryntp",required=False)        # Set secondary NTP 
parser.add_argument("--meshcmd",required=False)             # Run Meshcmd
parser.add_argument("--boot",required=False)                # Set boot device
parser.add_argument("--set",action='store_true')            # Set value
parser.add_argument("--kill",action='store_true')           # Stop existing session
parser.add_argument("--version",action='store_true')        # Display version
parser.add_argument("--insecure",action='store_true')       # Use HTTP/Telnet
parser.add_argument("--verbose",action='store_true')        # Enable verbose output
parser.add_argument("--debug",action='store_true')          # Enable debug output
parser.add_argument("--mask",action='store_true')           # Mask serial and hostname output output
parser.add_argument("--meshcommander",action='store_true')  # Use Meshcommander
parser.add_argument("--meshcentral",action='store_true')    # Use Meshcentral
parser.add_argument("--options",action='store_true')        # Display options information
parser.add_argument("--allhosts",action='store_true')       # Automate via .goatpass
parser.add_argument("--sol",action='store_true')            # Start a SOL connection to host
parser.add_argument("--download",action='store_true')       # Download BIOS

option = vars(parser.parse_args())

# Print version

def print_version(script_exe):
  file_array = file_to_array(script_exe)
  version    = list(filter(lambda x: re.search(r"^# Version", x), file_array))[0].split(":")[1]
  version    = re.sub(r"\s+","",version)
  print(version)

# Print options

def print_options(script_exe):
  file_array = file_to_array(script_exe)
  opts_array = list(filter(lambda x:re.search(r"add_argument", x), file_array))
  print("\nOptions:\n")
  for line in opts_array:
    line = line.rstrip()
    if re.search(r"#",line):
      option = line.split('"')[1]
      info   = line.split("# ")[1]
      if len(option) < 8:
        string = "%s\t\t\t%s" % (option,info)
      else:
        if len(option) < 16:
          string = "%s\t\t%s" % (option,info)
        else:
          string = "%s\t%s" % (option,info)
      print(string)
  print("\n")

# Check IP

def check_valid_ip(ip):
  if not re.search(r"[a-z]",ip):
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
  else:
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

# Download file

def download_file(link,file):
  if not os.path.exists(file):
    string = "Downloading %s to %s" % (link,file)
    wget.download(link,file)
  return

# Get AMT value from web

def get_web_amt_value(avail,model,driver,download):
  if avail == "bios":
    found    = False
    base_url = "https://downloadcenter.intel.com"
    full_url = "%s/search?keyword=%s" % (base_url,model)
    driver.get(full_url)
    html_doc  = driver.page_source
    html_doc  = BeautifulSoup(html_doc,features='lxml')
    html_data = html_doc.find_all('td')
    for html_line in html_data:
      html_text = str(html_line)
      if debug_mode == True:
        handle_output(html_text)
      if re.search("BIOS Update",html_text):
        link_stub = BeautifulSoup(html_text,features='lxml').a.get("href")
        bios_url  = "%s/%s" % (base_url,link_stub)
        found = True
      if re.search("Latest",html_text) and found == True:
        version = BeautifulSoup(html_text,features='lxml').get_text()
        version = re.sub("Latest","",version)
        string  = "Available version:  %s" % (version)
        handle_output(string)
        string  = "BIOS Download link: %s" % (bios_url)
        handle_output(string)
        if download == True:
          from selenium.webdriver.common.by import By
          driver.get(bios_url)    
          html   = driver.page_source
          html   = BeautifulSoup(html,features='lxml')
          html   = html.findAll("a", text=re.compile(r"\.bio"))[0]
          html   = str(html)
          link   = html.split('"')[3]
          file   = os.path.basename(link)
          download_file(link,file)
        driver.quit()
        return version
    driver.quit()
  return

# Handle output

def handle_output(output):
  if mask_mode == True:
    if re.search(r"serial|address|host|id",output.lower()):
      if re.search(":",output):
        param  = output.split(":")[0]
        output = "%s: XXXXXXXX" % (param)
  print(output)
  return

# Get AMT value

def get_amt_value(get_value,ip,username,password,driver,http_proto,search):
  sub_value = ""
  if not re.search(r"[A-Z]|[a-z]|[0-9]",search):
    search = ""
  if get_value == "bios":
    get_value = "system"
    sub_value = "bios"
    if not re.search(r"[A-Z]|[a-z]|[0-9]",search):
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
  base_url = "%s://%s:%s@%s:%s" % (http_proto,username,password,ip,port_no)
  full_url = "%s/index.htm" % (base_url)
  if re.search("model|version|serial|release|system",get_value):
    full_url = "%s/hw-sys.htm" % (base_url)
  if re.search("disk",get_value):
    full_url = "%s/hw-disk.htm" % (base_url)
  if re.search("network",get_value):
    full_url = "%s/ip.htm" % (base_url)
  if re.search("memory",get_value):
    full_url = "%s/hw-mem.htm" % (base_url)
  if re.search(r"events|fqdn",get_value):
    full_url = "%s/%s.htm" % (base_url,get_value)
  if re.search("remote|power",get_value):
    full_url  = "%s/remote.htm" % (base_url)
    get_value = re.sub("power","state",get_value)
  if re.search("processor|cpu|socket|family|manufacturer|speed",get_value):
    full_url  = "%s/hw-proc.htm" % (base_url)
    get_value = re.sub("cpu","version",get_value)
  if verbose_mode == True:
    string = "Information:\tConnecting to: %s" % (full_url)
    handle_output(string)
  driver.get(full_url)
  html_doc  = driver.page_source
  html_doc  = BeautifulSoup(html_doc,features='lxml')
  html_data = html_doc.find_all('td','maincell')
  if re.search(r"state",get_value):
    html_data = str(html_data).split("<td>")
  else:
    html_data = str(html_data).split("<tr>")
  new_data = []
  for html_line in html_data:
    temp_data = html_line.split("\n")
    for temp_line in temp_data:
      if not re.search("hidden",temp_line):
        new_data.append(temp_line)
  html_data = new_data
  results   = []
  if re.search("processor|system|memory|disk|event|fqdn|network",get_value):
    temp_data = []
    counter   = 0
    for html_line in html_data:
      html_text  = str(html_line)
      if debug_mode == True:
        handle_output(html_text)
      if not re.search(r"hidden|onclick|colspan",html_text):
        html_text  = re.sub(r"^\<\/td\>","",html_text)
        html_text  = re.sub(r"\<br\/\>",",",html_text)
        plain_text = BeautifulSoup(html_text,features='lxml').get_text()
        plain_text = re.sub(r"\s+"," ",plain_text)
        plain_text = re.sub(r"^ | $","",plain_text)
        if re.search("event",get_value):
          if re.search("border=",html_text):
            if counter == 5:
              temp_data.append(plain_text)
            else:
              temp_text = (",").join(temp_data)
              if re.search(r"[A-Z]|[a-z]|[0-9]",plain_text):
                results.append(temp_text)
                temp_data = []
              temp_data.append(plain_text)
          else:
            if re.search(r"[A-Z]|[a-z]|[0-9]",plain_text):
              temp_data.append(plain_text)
        else:
          if re.search(r"\<\/h1\>|\<\/h2\>",html_text):
            results.append(plain_text)
          else:
            if re.search(r"\<\/p\>",html_text):
              if re.search("checkbox",html_text):
                param = plain_text
                if re.search("checked",html_text):
                  value = "Yes"
                else:
                  value = "No"
              else:
                param = plain_text
                html  = html_data[counter+1]
                html  = str(html)
                html  = re.sub(r"^\<\/td\>","",html)
                text  = BeautifulSoup(html,features='lxml').get_text()
                if re.search("value=",html) and not re.search(r"[A-Z]|[a-z]|[0-9]",text):
                  value = html.split('"')[-2]
                else:
                  value = text
                if not re.search(r"[A-Z]|[a-z]|[0-9]",value):
                  html = html_data[counter+2]
                  html = str(html)
                  html = re.sub(r"^\<\/td\>","",html)
                  text = BeautifulSoup(html,features='lxml').get_text()
                  if re.search("value=",html) and not re.search(r"[A-Z]|[a-z]|[0-9]",text):
                    value = html.split('"')[-2]
                  else:
                    value = text
              plain_text = "%s: %s" % (param,value)
              plain_text = re.sub("::",":",plain_text)
              plain_text = re.sub(r"\s+$","",plain_text)
              plain_text = re.sub(r":$","",plain_text)
              if re.search(r"[A-Z]|[a-z]|[0-9]",plain_text):
                results.append(plain_text)
      counter = counter+1
  if re.search("processor|system|memory|disk|event|fqdn|network",get_value):
    found = False
    for result in results:
      if debug_mode == True:
        handle_output(result)
      if re.search(r"[a-z]",sub_value):
        if re.search(sub_value,result.lower()):
          found = True
        if re.search(r"[A-Z]|[a-z]|[0-9]",search):
          if re.search(search,result) and found == True:
            handle_output(result)
            if re.search(r":",result):
              result = result.split(": ")[1]
            return(result)
        else:
          if re.search(sub_value,result.lower()):
            handle_output(result)
            if re.search(r":",result):
              result = result.split(": ")[1]
            return(result)
      else:
        if re.search(r"[A-Z]|[a-z]|[0-9]",search):
          if re.search(search,result):
            handle_output(result)
        else:
          handle_output(result)
  driver.quit()
  return

# Set AMT value

def set_amt_value(ip,username,password,driver,http_proto,hostname,dommainname,primarydns,secondarydns,power):
  if http_proto == "http":
    port_no = "16992"
  else:
    port_no = "16993"
  base_url = "%s://%s:%s@%s:%s" % (http_proto,username,password,ip,port_no)
  if re.search(r"[a-z]",hostname) or (r"[a-z]",domainname):
    full_url = "%s/fqdn.htm" % (base_url)
    if re.search(r"[a-z]",hostname):
      search = "HostName"
      driver.get(full_url)
      from selenium.webdriver.common.by import By
      field = driver.find_element_by_name(search)
      field.clear()
      field.send_keys(hostname)
      string = "Information:\tSetting Hostname to %s" % (hostname)
      handle_output(string)
      driver.find_element_by_xpath('//input[@value="   Submit   "]').click()
    if re.search(r"[a-z]",domainname):
      search = "DomainName"
      driver.get(full_url)
      from selenium.webdriver.common.by import By
      field = driver.find_element_by_name(search)
      field.clear()
      field.send_keys(domainname)
      string = "Information:\tSetting Domainname to %s" % (domainname)
      handle_output(string)
      driver.find_element_by_xpath('//input[@value="   Submit   "]').click()
  if re.search(r"[a-z,0-9]",primarydns) or (r"[a-z,0-9]",secondarydns):
    full_url = "%s/ip.htm" % (base_url)
    if re.search(r"[a-z,0-9]",primarydns):
      search = "DNSServer"
      driver.get(full_url)
      from selenium.webdriver.common.by import By
      field = driver.find_element_by_name(search)
      field.clear()
      field.send_keys(primarydns)
      string = "Information:\tSetting Primary DNS to %s" % (primarydns)
      handle_output(string)
      driver.find_element_by_xpath('//input[@value="   Submit   "]').click()
    if re.search(r"[a-z,0-9]",secondarydns):
      search = "AlternativeDns"
      driver.get(full_url)
      from selenium.webdriver.common.by import By
      field = driver.find_element_by_name(search)
      field.clear()
      field.send_keys(secondarydns)
      string = "Information:\tSetting Secondary DNS to %s" % (secondarydns)
      handle_output(string)
      driver.find_element_by_xpath('//input[@value="   Submit   "]').click()
  if re.search(r"[a-z]",power):
    full_url = "%s/remote.htm" % (base_url)
    if re.search(r"off",power):
      driver.find_element_by_xpath('//input[@value="1"]').click()
    if re.search(r"cycle",power):
      driver.find_element_by_xpath('//input[@value="3"]').click()
    if re.search(r"reset",power):
      driver.find_element_by_xpath('//input[@value="4"]').click()
    driver.get(full_url)
    from selenium.webdriver.common.by import By
    driver.find_element_by_xpath('//input[@value="Send Command"]').click()
    time.sleep(2)
    object = driver.switch_to.alert
    time.sleep(2)
    object.accept()
    string = "Information:\tSending power %s to %s (Intel AMT has a 30s pause before operation is done)" % (power,ip)
    handle_output(string)
  driver.quit()
  return

# Compare versions

def compare_versions(bios,avail,oob_type):
  if oob_type == "amt":
    if re.search(".",bios):
      current = bios.split(".")[2]
    if avail > current:
      handle_output("Information:\tNewer version of BIOS available")
    if avail == current:
      handle_output("Information:\tLatest version of BIOS installed")
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

def check_local_config():
  pkg_list = [ "geckodriver", "amtterm", "npm", "ipmitool" ]
  pkg_dir  = "/usr/local/bin"
  brew_bin = "%s/brew" % (pkg_dir)
  output = get_console_output("uname -a")
  if re.search("Darwin",output):
    for pkg_name in pkg_list:
      pkg_bin = "%s/%s" % (pkg_dir,pkg_name)
      if not os.path.exists(pkg_bin):
        command = "%s install %s" % (brew_bin, pkg_name)
        output  = get_console_output(command)
  return

# Check mesh config

def check_mesh_config(mesh_bin):
  l_mesh_dir = "./%s" % (mesh_bin)
  l_mesh_bin = "./%s/%s" % (mesh_bin,mesh_bin)
  g_mesh_dir = "/usr/local/lib/node_modules/%s" % (mesh_bin)
  g_mesh_bin = "/usr/local/lib/node_modules/%s/%s" % (mesh_bin,mesh_bin)
  l_node_dir = "./%s/node_modules/%s" % (mesh_bin,mesh_bin)
  g_node_dir = "/usr/local/lib/node_modules/%s" % (mesh_bin)
  if not os.path.exists(l_mesh_bin) and not os.path.exists(g_mesh_bin):
    if not os.path.exists(l_mesh_dir):
      os.mkdir(l_mesh_dir)
      command = "cd %s ; npm install %s" % (l_mesh_dir,mesh_bin)
      output  = get_console_output(command)
      if verbose_mode == True:
         handle_output(output)
  return

# Start MeshCommander

def start_mesh(mesh_bin,mesh_port):
  l_node_dir = "./%s/node_modules/%s" % (mesh_bin,mesh_bin)
  g_node_dir = "/usr/local/lib/node_modules/%s" % (mesh_bin)
  if os.path.exists(l_node_dir):
    command = "cd %s ; node %s --port %s" % (l_node_dir,mesh_bin,mesh_port)
    os.system(command)
  else:
    if os.path.exists(g_node_dir):
      command = "cd %s ; node %s --port %s" % (g_node_dir,mesh_bin,mesh_port)
      os.system(command)
    else:
      string = "%s not installed" % (mesh_bin)
      handle_output(string)
  return

def get_ips():
  ips = []
  pass_file = "%s/.%s" % (home_dir,password_db)
  if os.path.exists(pass_file):
    file = open(pass_file,"r")
    data = file.readlines()
    for line in data:
      line.rstrip()
      file_ip = line.split(":")[0]
      ips.append(file_ip)
  return ips

# Get username

def get_username(ip):
  username  = default_user
  pass_file = "%s/.%s" % (home_dir,password_db)
  if os.path.exists(pass_file) and re.search(r"[a-z]|[0-9]",ip):
    file = open(pass_file,"r")
    data = file.readlines()
    for line in data:
      line.rstrip()
      file_user = line.split(":")[1]
      file_ip   = line.split(":")[0]
      if file_ip == ip:
        return file_user
  else:
    return username

# Get password

def get_password(ip,username):
  password  = ""
  pass_file = "%s/.%s" % (home_dir,password_db)
  prompt    = "Password for %s:" % (ip)
  if os.path.exists(pass_file):
    file = open(pass_file,"r")
    data = file.readlines()
    for line in data:
      line.rstrip()
      (file_ip,file_user,file_pass) = line.split(":")
      if file_ip == ip and file_user == username:
        if re.search(r"[A-Z]|[a-z]|[0-9]",file_pass):
          return file_pass
        else:
          password = getpass.getpass(prompt=prompt, stream=None)
          return password
  else:
    password = getpass.getpass(prompt=prompt, stream=None)
  return password

# Sol to host

def sol_to_host(ip,username,password,oob_type):
  if oob_type == "amt":
    command = "export AMT_PASSWORD=\"%s\" ; amtterm %s" % (password,ip)
  else:
    command = "ipmitool -I lanplus -U %s -P %s -H %s sol activate" % (username,password,ip)
  if verbose_mode == True:
    string = "Executing:\t%s" % (command)
    handle_output(string)
  os.system(command)
  return

# Initiate web client

def start_web_driver():
  if debug_mode == False:
    from selenium.webdriver.firefox.options import Options
    options = Options()
    options.headless = True
    driver = webdriver.Firefox(options=options)
  else:
    driver = webdriver.Firefox()
  return driver

# Run meshcmd

def mesh_command(ip,command,meshcmd,meshcmd_bin):
  if not os.path.exists(meshcmd_bin):
    uname_arch  = subprocess.check_output("uname",shell=True)
    if uname == "Darwin":
      return
    else:
      if uname == "Linux":
        os_name   = "linux"
        if re.search(r"i386|x86", uname_arch):
          if re.seach(r"64",uname_arch):
            os_arch = "x86_64"
          else:
            os_arch = "i386"
        else:
          if re.seach(r"64",uname_arch):
            os_arch = "arm64"
          else:
            os_arch = "arm"
        fetch_bin = "meshcmd_%s_%s" % (os_name,os_arch) 
      else:
        os_name   = "win"
        fetch_bin = "meshcmd_%s_%s.exe" % (os_name,os_arch) 
    uname_arch  = subprocess.check_output("uname -m",shell=True)
    meshcmd_url = "https://github.com/lateralblast/goat/blob/master/meshcmd/%s?raw=true" % (fetch_bin)
    download_file(meshcmd_url,meshcmd_bin)
    command = "chmod +x %s" % (meshcmd_bin)
    os.system(command)
  if meshcmd == "help":
    command = "%s" % (meshcmd_bin)
  else:
    if re.search(r"[0-9]",ip):
      status = check_ping(ip)
      if not status == False:
        username = get_username(ip)
        password = get_password(ip,username)
        command  = "sudo %s %s --host %s --host %s --user %s --pass %s" % (meshcmd_bin,meshcmd,ip,username,password)
    else:
      command  = "sudo %s %s" % (meshcmd_bin,meshcmd)
  handle_output(command)
  os.system(command)
  return

# Initiate SSH Session

def start_ssh_session(ip,username,password):
  ssh_command = "ssh -o StrictHostKeyChecking=no"
  ssh_command = "%s %s@%s" % (ssh_command, username, ip)
  ssh_session = pexpect.spawn(ssh_command)
  ssh_session.expect("assword: ")
  ssh_session.sendline(password)
  return ssh_session

# Get iDRAC value

def set_idrac_value(ip,username,password,hostname,domainname,netmask,gateway,primarydns,secondarydns,primaryntp,secondaryntp,primarysyslog,secondarysyslog,syslogport,power):
  commands = []
  ssh_session = start_ssh_session(ip, username, password)
  if re.search(r"[a-z,0-9]",domainname):
    command = "racadm config -g cfgLanNetworking -o cfgDNSDomainNameFromDHCP 0"
    commands.append(command)
    command = "racadm config -g cfgLanNetworking -o cfgDNSDomainName %s" % (domainname)
    commands.append(command)
  if re.search(r"[0-9]",netmask):
    command = "racadm config -g cfgLanNetworking -o cfgNicNetmask %s" % (netmask)
    commands.append(command)
  if re.search(r"[0-9]",gateway):
    command = "racadm config -g cfgLanNetworking -o cfgNicNetmask %s" % (gateway)
    commands.append(command)
  if re.search(r"[0-9]",primarydns):
    command = "racadm config -g cfgLanNetworking -o cfgDNSServersFromDHCP 0"
    commands.append(command)
    command = "racadm config -g cfgLanNetworking -o cfgDNSServer1 %s" % (primarydns)
    commands.append(command)
  if re.search(r"[0-9]",secondarydns):
    command = "racadm config -g cfgLanNetworking -o cfgDNSServersFromDHCP 0"
    commands.append(command)
    command = "racadm config -g cfgLanNetworking -o cfgDNSServer2 %s" % (secondarydns)
    commands.append(command)
  if re.search(r"[a-z,0-9]",primaryntp):
    command = "racadm config -g cfgLanNetworking -o cfgRhostsNtpEnable 1"
    commands.append(command)
    command = "racadm config -g cfgLanNetworking -o cfgRhostsNtpServer1 %s" % (primaryntp)
    commands.append(command)
  if re.search(r"[a-z,0-9]",secondaryntp):
    command = "racadm config -g cfgLanNetworking -o cfgRhostsNtpEnable 1"
    commands.append(command)
    command = "racadm config -g cfgLanNetworking -o cfgRhostsNtpServer2 %s" % (secondaryntp)
    commands.append(command)
  if re.search(r"[a-z,0-9]",primarysyslog):
    command = "racadm config -g cfgLanNetworking -o cfgRhostsSyslogEnable 1"
    commands.append(command)
    command = "racadm config -g cfgLanNetworking -o cfgRhostsSyslogServer1 %s" % (primarysyslog)
    commands.append(command)
  if re.search(r"[a-z,0-9]",secondarysyslog):
    command = "racadm config -g cfgLanNetworking -o cfgRhostsSyslogEnable 1"
    commands.append(command)
    command = "racadm config -g cfgLanNetworking -o cfgRhostsSyslogServer2 %s" % (secondarysyslog)
    commands.append(command)
  if re.search(r"[0-9]",syslogport):
    command = "racadm config -g cfgLanNetworking -o cfgRhostsSyslogEnable 1"
    commands.append(command)
    command = "racadm config -g cfgLanNetworking -o cfgRhostsSyslogPort%s" % (syslogport)
    commands.append(command)
  if re.search(r"[a-z]",power):
    power = re.sub(r"on","up",power)
    power = re.sub(r"off","down",power)
    if not re.search(r"^power",power):
      power = "power%s" % (power)
    command = "racadm serveraction %s" % (power)
    commands.append(command)
  ssh_session.expect("/admin1-> ")
  for command in commands:
    ssh_session.sendline(command)
    ssh_session.expect("/admin1-> ")
    output = ssh_session.before
    output = output.decode()
    if verbose_mode == True:
      output = "Executing:\t%s" % (command)
      handle_output(output)
      output = "Output:\t\t%s" % (output)
      handle_output(output)
  ssh_session.close()
  return

# Get iDRAC value

def get_idrac_value(get_value,ip,username,password):
  ssh_session = start_ssh_session(ip, username, password)
  ssh_session.expect("/admin1-> ")
  if re.search(r"bios|idrac|usc",get_value.lower()):
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
    if re.search(get_value,line,re.IGNORECASE):
      line = re.sub(r" \s+", " ", line)
      handle_output(line)
  return

# Get IPMI value

def get_ipmi_value(get_value,ip,username,password):
  command = "ipmitool -I lanplus -U %s -P %s -H %s %s" % (username,password,ip,get_value)
  handle_output(command)
  os.system(command)
  return

# Set IPMI value

def set_ipmi_value(set_value,ip,username,password):
  command = "ipmitool -I lanplus -U %s -P %s -H %s %s" % (username,password,ip,set_value)
  handle_output(command)
  os.system(command)
  return

# Use javaws to iDRAC KVM

def java_idrac_kvm(ip,port,username,password,home_dir):
  web_url = "https://%s" % (ip)
  command = "which javaws"
  output  = os.popen(command).read()
  if not re.search(r"^/",output):
    output = "Warning:\tNo Java installation found"
    handle_output(output)
    exit()
  xml_file = "/tmp/%s.jnlp" % (ip)
  command  = "uname -a"
  os_name  = os.popen(command).read()
  if re.search(r"^Darwin",os_name):
    command = "java --version"
    version = os.popen(command).read()
    if re.search(r"Oracle",version):
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
  with open(xml_file, 'w') as file:
    for item in data:
      file.write("%s\n" % item)
  if os.path.exists(xml_file):
    command = "chmod 700 %s" % (xml_file)
    os.system(command)
    command = "javaws %s" % (xml_file)
    os.system(command)

# Set APC power

def set_apc_power(power,ip,outlet,username,password):
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
    if not re.search(r"^/",output):
      output = "Warning:\tNo docker installation found"
      handle_output(output)
      exit()
    string  = "Docker old SHH version tool"
    command = "docker images |grep ostrich"
    output  = os.popen(command).read()
    if not re.search(r"ostrich",output):
      output = "Information:\tInstalling %s" % (string) 
      handle_output(output)
      with open("/tmp/Dockerfile", 'w') as file:
        file.write("FROM ubuntu:16.0\n")
        file.write("RUN apt-get update && apt-get install -y openssh-client\n")
      with open("/tmp/docker-compose.yml", 'w') as file:
        file.write('version: "3"\n')
        file.write("services:\n")
        file.write("  ostrich:\n")
        file.write("    build:\n")
        file.write("      context: .\n")
        file.write("      dockerfile: Dockerfile\n")
        file.write("    image: ostrich\n")
        file.write("    container_name: ostrich\n")
        file.write("    entrypoint: /bin/bash\n")
        file.write("    working_dir: /root\n")
    command = "docker run -it ostrich /bin/bash -c \"ssh %s %s@%s\"" % (ssh_opt,username,ip)
  else:
    command = "ssh %s %s@%s" % (ssh_opt,username,ip)
  #child.expect("")
  #child.sendline("")
  outlet = str(outlet) 
  outlet = "%s\r" % (outlet)
  child  = pexpect.spawnu(command)
  if verbose_mode == True:
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

def web_idrac_kvm(ip,port,username,password):
  string  = "Docker iDRAC KVM redirection tool"
  command = "which docker"
  output  = os.popen(command).read()
  if not re.search(r"^/",output):
    output = "Warning:\tNo docker installation found"
    handle_output(output)
    exit()
  command = "docker images |grep idrac6"
  output  = os.popen(command).read()
  if not re.search(r"idrac6",output):
    output = "Information:\tInstalling %s" % (string) 
    handle_output(output)
    command = "docker pull domistyle/idrac6"
    if verbose_mode == True:
      output = "Executing:\t%s" % (command)
      handle_output(output)
    output  = os.popen(command).read()
    if verbose_mode == True:
      handle_output(output)
  command = "docker ps |grep idrac |awk '{print $1}'"
  process = os.popen(command).read()
  process = process.rstrip()
  if re.search(r"[0-9]",process):
    output = "Warning:\tInstance of %s already running" % (string)
    handle_output(output)
    if kill_mode == True:
      output = "Information:\tStopping existing %s instance" % (string)
      handle_output(output)
      command = "docker kill %s" % (process)
      output  = os.popen(command).read()
      if verbose_mode == True:
        handle_output(output)
    else:
      exit()
  command = "docker run -d -p %s:%s -p 5900:5900 -e IDRAC_HOST=%s -e IDRAC_USER=%s -e IDRAC_PASSWORD=%s domistyle/idrac6" % (port,port,ip,username,password)
  if verbose_mode == True:
    output = "Executing:\t%s" % (command)
    handle_output(output)
  output = os.popen(command).read()
  if verbose_mode == True:
    handle_output(output)
  output = "Information:\tStarting %s at http://127.0.0.1:%s" % (string,port)
  handle_output(output)
  return

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
  exit()

# Handle verbose switch

if option["ip"]:
  string = ""
  ip     = option["ip"]
  test   = check_valid_ip(ip)
  if test == False:
    string = "Warning:\tInvalid IP: %s" % (ip)
    handle_output(string)
    exit()

# Handle options switch

if option["options"]:
  script_exe = sys.argv[0]
  print_options(script_exe)
  exit()

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
          exit()
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
    if option["type"] and not option["allhosts"]:
      password = get_password(ip,username)

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
  check_mesh_config(mesh_bin)
  start_mesh(mesh_bin,mesh_port)
  exit()

# If option meshcmd is used the type of OOB is AMT

if option["meshcmd"]:
  option["type"] = "amt"

# Handle vendor switch

if option["type"]:
  ips = []
  check_local_config()
  oob_type = option["type"]
  oob_type = oob_type.lower()
  if option["allhosts"]:
    ips = get_ips()
  else:
    if option["avail"] and not option["ip"]:
      if not option["model"]:
        handle_output("Warning:\tNo model specified")
        exit()
      else:
        driver = start_web_driver()
        get_web_amt_value(avail,model,driver,download)
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
          exit()
  for ip in ips:
    if re.search(r"amt|idrac|ipmi",oob_type) and option["sol"]:
      status = check_ping(ip)
      if not status == False:
        sol_to_host(ip,username,password,oob_type)
        exit()    
    if option["allhosts"]:
      username = get_username(ip)
      password = get_password(ip,username)
    if oob_type == "webidrac":
      web_idrac_kvm(ip,port,username,password)
    if oob_type == "javaidrac":
      java_idrac_kvm(ip,port,username,password,home_dir)
    if oob_type == "apc":
      if option['set']:
        set_apc_power(power,ip,outlet,username,password)
    if oob_type == "ipmi":
      status = check_ping(ip)
      if not status == False:
        if option['get']:
          get_ipmi_value(get_value,ip,username,password)
        if option['boot']:
          set_value = "chassis bootparam set bootflag %s" % (boot)
          set_ipmi_value(set_value,ip,username,password)
        if option['power']:
          set_value = "chassis power %s" % (power)
          set_ipmi_value(set_value,ip,username,password)
    if oob_type == "idrac":
      status = check_ping(ip)
      if not status == False:
        if option["get"]:
          bios = get_idrac_value(get_value,ip,username,password)
        if option["set"]:
          set_idrac_value(ip,username,password,hostname,domainname,netmask,gateway,primarydns,secondarydns,primaryntp,secondaryntp,primarysyslog,secondarysyslog,syslogport,power)
    if oob_type == "amt":
      if option["meshcmd"]:
        mesh_command(ip,password,meshcmd,meshcmd_bin)
      else:
        driver = start_web_driver()
      if option["check"]:
        status = check_ping(ip)
        if not status == False:
          model   = get_amt_value("model",ip,username,password,driver,http_proto,search)
          current = get_amt_value(check,ip,username,password,driver,http_proto,search)
          avail   = get_web_amt_value(check,model,driver,download)
          compare_versions(current,avail,oob_type)
      if option["avail"]:
        if not option["model"]:
          status = check_ping(ip)
          if not status == False:
            username = get_username(ip)
            password = get_password(ip,username)
            model = get_amt_value("model",ip,username,password,driver,http_proto,search)
            get_web_amt_value(avail,model,driver,download)
        else:
          get_web_amt_value(avail,model,driver,download)
      if option["get"]:
        status = check_ping(ip)
        if not status == False:
          get_amt_value(get_value,ip,username,password,driver,http_proto,search)
      if option["set"]:
        status = check_ping(ip)
        if not status == False:
          set_amt_value(ip,username,password,driver,http_proto,hostname,domainname,primarydns,secondarydns,power)
else:
  handle_output("Warning:\tNo OOB type specified")
  exit()
  
