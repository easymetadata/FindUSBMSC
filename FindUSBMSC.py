# This script attempts to extract USBMSC entries from Mac OS X kernel logs and
# then correlate the product id of the log entry with usb id's from "http://www.linux-usb.org/usb.ids".
#	-Script will handle compressed log files automatically.
#	*As of OSX Sierra kernel log's are legacy. Unified logging has taken over.
#		Refs: https://www.mac4n6.com/blog/2016/11/13/new-macos-sierra-1012-forensic-artifacts-introducing-unified-logging
#		-
# Author: David Dym
# Version 20170720 - Ported from perl to python. Derived from Jason Hale's usbmsc.pl script version 20130125

import os
import sys, csv, sqlite3
import os,fnmatch
import datetime
import re
import urllib2
import gzip

url = "http://www.linux-usb.org/usb.ids"
repattern = "(^[a-z]{3}\s{1,2}\d{1,2})\s(\d\d:\d\d:\d\d)\s(.+)\s[a-z]+\[\d+\]:\sUSBMSC\s.+:\s(.*)0x(.*)\s0x(.*)\s0x(.*)"
dirpath = sys.argv[1]

def get_usbid_file(url):
	#url="http://.../"
	# Translate url into a filename
	filename = url.split('/')[-1]

	if not os.path.exists(filename):
	  outfile = open(filename, "w")
	  outfile.write(urllib2.urlopen(url).read())
	  outfile.close()
	
	if os.path.exists(filename):
		text_file = open(filename, "r")
		usbs = text_file.readlines()
		text_file.close()
		
	return list(usbs)


def find_files(directory, pattern):
    for root, dirs, files in os.walk(directory):
        for basename in files:
            if fnmatch.fnmatch(basename, pattern):
                filename = os.path.join(root, basename)
                yield filename

def analyze_file(filename):	
	#print 'File:', filename
	
	#check for gzip File
	if ".gz" in filename:
		filename = compressedLog(filename)

	bufsize = 65536
	with open(filename) as infile: 
		while True:
			lines = infile.readlines(bufsize)
			if not lines:
				break
			for line in lines:
				usbDev = findUSBMSC(line)
				if usbDev:
					print usbDev

def compressedLog(filename):
	with gzip.open(filename, 'rb') as infile:
		tempDFileName = "tmp000.log"
		with open(tempDFileName, 'wb') as outfile:
			for line in infile:
				outfile.write(line)
	return filename

def findUSBMSC(line):
	matches = re.match(r"(^[a-z]{3}\s{1,2}\d{1,2})\s(\d\d:\d\d:\d\d)\s(.+)\s[a-z]+\[\d+\]:\sUSBMSC\s.+:\s(.*)0x(.*)\s0x(.*)\s0x(.*)", line, re.IGNORECASE)
	
	if matches:
		logDate = matches.group(1) + " "  + matches.group(2)
		serial = matches.group(4)
		vid = matches.group(5)
		pid = matches.group(6)

		#if pid:
		usbs = get_usbid_file(url)
		for line2 in usbs:
			#print "\n test: %s" % line2
			if re.match(r"^\t", line2):
				if pid in line2:
					if re.match("\t0*" + pid + "\s",line2):
						return "%s, %s, %s, %s, %s" % (logDate,serial, vid, pid, line2.strip())

#header
print "date, serial, vid, pid, usb info"

#read each file		
for filename in find_files(dirpath, '*.log*'):
	#print 'File:', filename

	#analyze each file
	analyze_file(filename)


# usbids into array