#!/usr/bin/python3
# note: my packetcallback function is super long and could easily be broken into many functions, 
#but I didn't do this to make it run faster which is very important when analyzing network packets

from scapy.all import *
import argparse
import base64

# setting incident count as a global variable
inc_count = 1

def set_globvar_to_one():
  global inc_count   
  inc_count = 1

def add_to_inc_count():
  global inc_count
  inc_count+=1


def packetcallback(packet):

  try:
   if TCP in packet:
      # getting the packet summary to find the sender's IP adress
      summary = packet.summary() 
      summary = summary.split()
      send_IP = (summary[5])

      # detecting scans using flags:
      currflag = (packet.sprintf("%TCP.flags%"))
      if currflag == '':
        print( "Alert #" , inc_count , "Null scan is detected from ", send_IP) 
        add_to_inc_count()
      elif currflag == 'F' :
        print( "Alert #" , inc_count , "FIN scan is detected from ", send_IP) 
        add_to_inc_count()
      elif currflag == 'FPU' :
        print( "Alert #" , inc_count , "XMAS scan is detected from ", send_IP) 
        add_to_inc_count()

      # this line of code strips the payload into readible ascii text
      payload = packet[TCP].load.decode("ascii").strip()

      #checking fo nikto scan or smb scan is being performed
      if 'SMB2' in (packet.summary() ) :
        print( "Alert #" , inc_count , "Someone scanning for SMB is detected from ", send_IP) 
        add_to_inc_count()
      if 'scan' in payload and 'Nikto' in payload:
        print( "Alert #" , inc_count , "Nikto scan is detected from ", send_IP) 
        add_to_inc_count()
      payload_list = payload.split()

      #searching for usernames and passwords
      if 'Authorization: Basic' in payload:
        counter = 0
        while(payload_list[counter] != 'Basic'):
          counter=counter+1
        hexuserpass = payload_list[counter+1]
        userpass = base64.b64decode(hexuserpass)
        (username, password) = userpass.decode('ascii').split(":")
        print( "Alert #" , inc_count , "Usernames and passwords sent in-the-clear (HTTP) username:" \
        , username, "password: ", password )
        add_to_inc_count()

      if 'USER 'in payload:
        counter = 0
        while(payload_list[counter] != 'USER'):
          counter=counter+1
        username = payload_list[counter+1] 
        if username != '--/.html':
          print( "Alert #" , inc_count , "Username sent in-the-clear (FTP) username:", username )
        add_to_inc_count()

      if 'PASS ' in payload:
        counter = 0
        while(payload_list[counter] != 'PASS'):
          counter=counter+1
        password = payload_list[counter+1] 
        print( "Alert #" , inc_count , "Password sent in-the-clear (FTP) password:", password )
        add_to_inc_count()

      if payload_list[1] == 'LOGIN':
        username = payload_list[2]
        password = payload_list[3]
        print( "Alert #" , inc_count , "Usernames and passwords sent in-the-clear (IMAP) username:" \
        , username, "password: ", password )
        add_to_inc_count()

  except:
    pass

parser = argparse.ArgumentParser(description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
args = parser.parse_args()
if args.pcapfile:
  try:
    print("Reading PCAP file %(filename)s..." % {"filename" : args.pcapfile})
    sniff(offline=args.pcapfile, prn=packetcallback)    
  except:
    print("Sorry, something went wrong reading PCAP file %(filename)s!" % {"filename" : args.pcapfile})
else:
  print("Sniffing on %(interface)s... " % {"interface" : args.interface})
  try:
    sniff(iface=args.interface, prn=packetcallback)
  except:
    print("Sorry, can\'t read network traffic. Are you root?")
