#!/bin/python3
import sys #allows us to enter command line arguments, among other things
import socket
from datetime import datetime 

#Define our target
if len(sys.argv) == 2:
    target = socket.gethostbyname(sys.argv[1]) #Translate a host name to IPV4
else:
    print("Invalid amount of arguments.")
    print("Syntax: python3 scanner.py <ip>")
    sys.exit()
