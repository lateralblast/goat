#!/usr/bin/env python

# Name:         goat (General OOB Automation Tool)
# Version:      0.2.0
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

import subprocess
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
mesh_bin     = "meshcommander"
mesh_port    = "3000"
password_db  = "goatpass"
home_dir     = expanduser("~")
default_user = "admin"

# Check we have pip installed

try:
  from pip._internal import main
except ImportError:
  os.system("easy_install pip")

# install and import a python module

def install_and_import(package):
  import importlib
  try:
    importlib.import_module(package)
  except ImportError:
    main(["install", "--user", package])
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

# Print help

def print_help():
  script_exe = sys.argv[0]
  command    = "%s -h" % (script_exe)
  os.system(command)

# Read a file into an array

def file_to_array(file_name):
  file_data  = open(file_name)
  file_array = file_data.readlines()
  return file_array

# If we have no command line arguments print help

if sys.argv[-1] == sys.argv[0]:
  print_help()
  exit()

# Get command line arguments

parser = argparse.ArgumentParser()
parser.add_argument("--ip",required=False)            # Specify IP of OOB/Remote Management interface
parser.add_argument("--username",required=False)      # Set Username
parser.add_argument("--type",required=False)          # Set Type
parser.add_argument("--get",required=False)           # Get Parameter
parser.add_argument("--set",required=False)           # Set Parameter
parser.add_argument("--password",required=False)      # Set Password
parser.add_argument("--search",required=False)        # Search output for value
parser.add_argument("--avail",required=False)         # Get available version from vendor (e.g. BIOS)
parser.add_argument("--check",required=False)         # Check current version against available version from vendor (e.g. BIOS)
parser.add_argument("--model",required=False)         # Specify model (can be used with --avail)
parser.add_argument("--port",required=False)          # Specify port to run service on
parser.add_argument("--version",action='store_true')  # Display version
parser.add_argument("--insecure",action='store_true') # Use HTTP/Telnet
parser.add_argument("--verbose",action='store_true')  # Enable verbose output
parser.add_argument("--debug",action='store_true')    # Enable debug output
parser.add_argument("--mask",action='store_true')     # Mask serial and hostname output output
parser.add_argument("--mesh",action='store_true')     # Use Meshcommander
parser.add_argument("--options",action='store_true')  # Display options information
parser.add_argument("--allhosts",action='store_true') # Automate via .goatpass
parser.add_argument("--sol",action='store_true')      # Start a SOL connection to host

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

# Hash a password for storing

def hash_password(password):
    salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
    pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'),
                                  salt, 100000)
    pwdhash = binascii.hexlify(pwdhash)
    return (salt + pwdhash).decode('ascii')

# Verify a stored password against one provided by user

def verify_password(stored_password, provided_password):
    salt = stored_password[:64]
    stored_password = stored_password[64:]
    pwdhash = hashlib.pbkdf2_hmac('sha512',
                                  provided_password.encode('utf-8'),
                                  salt.encode('ascii'),
                                  100000)
    pwdhash = binascii.hexlify(pwdhash).decode('ascii')
    return pwdhash == stored_password

# Get AMT value from web

def get_web_amt_value(avail,model,driver):
  if avail == "bios":
    found    = False
    base_url = "https://downloadcenter.intel.com"
    full_url = "%s/search?keyword=%s" % (base_url,model)
    driver.get(full_url)
    html_doc  = driver.page_source
    html_doc  = BeautifulSoup(html_doc,'html.parser')
    html_data = html_doc.find_all('td')
    for html_line in html_data:
      html_text = str(html_line)
      if debug_mode == True:
        print(html_text)
      if re.search("BIOS Update",html_text):
        link_stub = BeautifulSoup(html_text,features='lxml').a.get("href")
        bios_url  = "%s/%s" % (base_url,link_stub)
        found = True
      if re.search("Latest",html_text) and found == True:
        version = BeautifulSoup(html_text,features='lxml').get_text()
        version = re.sub("Latest","",version)
        string  = "Available version:  %s" % (version)
        print(string)
        string  = "BIOS Download link: %s" % (bios_url)
        print(string)
        driver.quit()
        return version
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
    string = "Connecting to: %s" % (full_url)
    print(string)
  driver.get(full_url)
  html_doc  = driver.page_source
  html_doc  = BeautifulSoup(html_doc,'html.parser')
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
        print(html_text)
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
        print(result)
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

def set_amt_value(set_value,ip,username,password,driver,http_proto,search):
  if http_proto == "http":
    port_no = "16992"
  else:
    port_no = "16993"
  base_url = "%s://%s:%s@%s:%s" % (http_proto,username,password,ip,port_no)
  if re.search(r"power|reset",set_value):
    full_url = "%s/remote.htm" % (base_url)
  driver.get(full_url)
  if set_value == "poweroff":
    driver.find_element_by_xpath('//input[@value="1"]').click()
  if set_value == "powercycle":
    driver.find_element_by_xpath('//input[@value="3"]').click()
  if set_value == "reset":
    driver.find_element_by_xpath('//input[@value="4"]').click()
  from selenium.webdriver.common.by import By
  driver.find_element_by_xpath('//input[@value="Send Command"]').click()
  time.sleep(2)
  object = driver.switch_to.alert
  time.sleep(2)
  object.accept()
  driver.quit()
  string = "Sending %s to %s (Intel AMT has a 30s pause before operation is done)" % (set_value,ip)
  print(string)
  return

# Compare versions

def compare_versions(bios,avail,oob_type):
  if oob_type == "amt":
    if re.search(".",bios):
      current = bios.split(".")[2]
    if avail > current:
      print("Newer version of BIOS available")
    if avail == current:
      print("Latest version of BIOS installed")
  return

# Get console output

def get_console_output(command):
  if verbose_mode:
    string = "Executing: "+command
    print(string)
  process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, )
  output  = process.communicate()[0].decode()
  return output

# Check local config

def check_local_config():
  pkg_list = [ "geckodriver", "amtterm", "npm" ]
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
  mesh_dir = "./%s" % (mesh_bin)
  node_dir = "./%s/node_modules/%s" % (mesh_bin,mesh_bin)
  if not os.path.exists(mesh_dir):
    os.mkdir(mesh_dir)
    uname = os.uname
    if re.search("Darwin",uname):
      if not os.path.exists(node_dir):
        command = "cd %s ; npm install meshcommander" % (mesh_dir)
        output  = get_console_output(command)
        if verbose_mode == True:
          print(output)
  return

# Start MeshCommander

def start_mesh(mesh_bin,mesh_port):
  node_dir = "./%s/node_modules/%s" % (mesh_bin,mesh_bin)
  if os.path.exists(node_dir):
    command = "cd %s ; node %s --port %s" % (node_dir,mesh_bin,mesh_port)
    os.system(command)
  else:
    string = "%s not installed" % (mesh_bin)
    print(string)
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

def sol_to_host(ip,password):
  command = "export AMT_PASSWORD=\"%s\" ; amtterm %s" % (password,ip)
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
    string = "Invalid IP: %s" % (ip)
    print(string)
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

# Handle username switch

if option["username"]:
  username = option["username"]
else:
  if option["avail"]:
    if option["ip"]:
      username = get_username(ip)
  else:
    if option["type"] and not option["allhosts"]:
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

# Handle verbose switch

if option["debug"]:
  debug_mode = True 
else:
  debug_mode = False

# Handle mask switch

if option["mask"]:
  mask_mode = True
else:
  mask_mode = False

# Handle get switch

if option["get"]:
  get_value = option["get"]

# Handle set switch

if option["set"]:
  set_value = option["set"]

# Handle avail switch

if option["avail"]:
  avail = option["avail"]

# Handle check switch

if option["check"]:
  check = option["check"]

# Handle port switch

if option["port"]:
  port = option["port"]

# Handle mesh switch

if option["mesh"]:
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
        print("Not model specified")
        exit()
      else:
        driver = start_web_driver()
        get_web_amt_value(avail,model,driver)
    else:
      ips.append(ip)
  for ip in ips:
    if option["allhosts"]:
      username = get_username(ip)
      password = get_password(ip,username)
    if oob_type == "amt":
      if option["sol"]:
        sol_to_host(ip,password)
      if option["mesh"]:
        if option["port"]:
          mesh_port = option["port"]
        check_mesh_config(mesh_bin)
        start_mesh(mesh_bin,mesh_port)
      driver = start_web_driver()
      if option["check"]:
        model    = get_amt_value("model",ip,username,password,driver,http_proto,search)
        current  = get_amt_value(check,ip,username,password,driver,http_proto,search)
        avail    = get_web_amt_value(check,model,driver)
        compare_versions(current,avail,oob_type)
      if option["avail"]:
        if not option["model"]:
          model = get_amt_value("model",ip,username,password,driver,http_proto,search)
        get_web_amt_value(avail,model,driver)
      if option["get"]:
        get_amt_value(get_value,ip,username,password,driver,http_proto,search)
      if option["set"]:
        set_amt_value(set_value,ip,username,password,driver,http_proto,search)
else:
  print("No OOB type specified")
  exit()
  