#!/usr/bin/env python

# Name:         goat (General OOB Automation Tool) 
# Version:      0.0.8
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

import argparse
import socket
import sys
import os
import re

# Set some defaults

verbose_mode = False

# Check we have pip installed

try:
  from pip._internal import main
except:
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
except:
  install_and_import(selenium)
  from selenium import webdriver

# Load bs4

try:
  from bs4 import BeautifulSoup 
except:
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
parser.add_argument("--version",action='store_true')  # Display version 
parser.add_argument("--insecure",action='store_true') # Use HTTP/Telnet
parser.add_argument("--verbose",action='store_true')  # Enable verbose output
parser.add_argument("--debug",action='store_true')    # Enable debug output
parser.add_argument("--search",required=False)        # Search output for value
parser.add_argument("--avail",required=False)         # Get available version from vendor (e.g. BIOS)
parser.add_argument("--model",required=False)         # Specify model (can be used with --avail)

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
        return
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
        html_text  = re.sub("^\<\/td\>","",html_text)
        html_text  = re.sub("\<br\/\>",",",html_text)
        plain_text = BeautifulSoup(html_text,features='lxml').get_text()
        plain_text = re.sub("\s+"," ",plain_text)
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
            if re.search("\<\/p\>",html_text):
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
                html  = re.sub("^\<\/td\>","",html)
                text  = BeautifulSoup(html,features='lxml').get_text()
                if re.search("value=",html) and not re.search(r"[A-Z]|[a-z]|[0-9]",text):
                  value = html.split('"')[-2]
                else:
                  value = text
                if not re.search(r"[A-Z]|[a-z]|[0-9]",value):
                  html = html_data[counter+2]
                  html = str(html)
                  html = re.sub("^\<\/td\>","",html)
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
            print(result)
            if re.search(r":",result):
              result = result.split(": ")[1]
            return(result)
        else:
          if re.search(sub_value,result.lower()):
            print(result)
            if re.search(r":",result):
              result = result.split(": ")[1]
            return(result)
      else:
        if re.search(r"[A-Z]|[a-z]|[0-9]",search):
          if re.search(search,result):
            print(result)
        else:
          print(result)
  driver.quit()
  return

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

# Handle insecure switch

if option["insecure"]:
  http_proto = "http"
else:
  http_proto = "https"

# Handle username switch

if option["username"]:
  username = option["username"]

# Handle password switch

if option["password"]:
  password = option["password"]

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

# Handle get switch

if option["get"]:
  get_value = option["get"]

# Handle get switch

if option["set"]:
  set_value = option["set"]

# Handle avail switch

if option["avail"]:
  avail = option["avail"]

# Handle vendor switch

if option["type"]:
  oob_type = option["type"]
  oob_type = oob_type.lower()
  if oob_type == "amt":
    from selenium.webdriver.chrome.options import Options
    options = Options()
    options.headless = True
    driver = webdriver.Chrome(options=options)
  if oob_type == "amt":
    if option["avail"]:
      if not option["model"]:
        model = get_amt_value("model",ip,username,password,driver,http_proto,search)
      get_web_amt_value(avail,model,driver)
      exit()
    if option["get"]:
      get_amt_value(get_value,ip,username,password,driver,http_proto,search)
    if option["set"]:
      set_amt_value(set_value,ip,username,password,driver,http_proto,search)
      get_amt_value(get_value,ip,username,password,driver,http_proto,search)
      exit()
    if option["set"]:
      set_amt_value(set_value,ip,username,password,driver,http_proto,search)
      exit()
else:
  print("No OOB type specified")
  exit()
  