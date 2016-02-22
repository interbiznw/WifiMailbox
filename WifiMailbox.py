#! /usr/bin/env python
import logging
import os
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from chump import Application

def arp_display(pkt):
	if pkt[ARP].op == 1: #who-has (request)
	  if pkt[ARP].psrc == '0.0.0.0': #ARP Probe
	    if pkt[ARP].hwsrc == '74:75:48:__fill in unique MAC Add__': #ELEMENTS
	      app = Application('a    ---app id here---         b')
	      user = app.get_user('u   ---user id here    ---   W')
	      message = user.create_message("Ding-Dong The Mail Is Here!")
	      app.is_authenticated
	      user.is_authenticated, user.devices
	      message.is_sent, message.id
	      message.send()
	      message.is_sent, message.id, str(message.sent_at)
	      os.system('aplay bluesclues-mailtime.wav')

print sniff(prn=arp_display, filter="arp", store=0)
