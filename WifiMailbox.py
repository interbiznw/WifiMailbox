#! /usr/bin/env python
import logging
import os
logging.getLogger("scrapy.runtime").setLevel(logging.ERROR)
from scrapy.all import *
from chump import Application

def arp_display(pkt):
	if pkt[ARP].op == 1: #who-has (request)
	  if pkt[ARP].psrc == '0.0.0.0': #ARP Probe
	    if pkt[ARP].hwsrc == '74:75:48:           ': #ELEMENTS
	      app = Application('a                    b')
	      user = app.get_user('u                     W')
	      message = user.create_message("Ding-Dong The Mail Is Here!")
	      app.is_authenticated
	      user.is_authenticated, user.devices
	      message.is_sent, message.id
	      message.send()
	      message.is_sent, message.id, str(message.sent_at)
	      os.system('aplay youGotMail.wav')

print sniff(prn=arp_display, filter="arp", store=0)
