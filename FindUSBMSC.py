# This script attempts to extract USBMSC entries from Mac OS X kernel logs and
# then correlate the product id of the log entry with usb id's from "http://www.linux-usb.org/usb.ids".
#	-Script will handle compressed log files automatically.
#	*As of OSX Sierra kernel log's are legacy. Unified logging has taken over.
#		Refs: https://www.mac4n6.com/blog/2016/11/13/new-macos-sierra-1012-forensic-artifacts-introducing-unified-logging
#		-
# Author: David Dym
# v20170720 - Ported from perl to python. Derived from Jason Hale's usbmsc.pl script version 20130125.
# v20171003 - changes to regex pattern matching to account for commma change in system log. Logic changes to pid matching. Fixes to logic. 
# v20171016 - Logic cleanup. Improve pid and vid parsing. Added list of unique devices. Added options parser.
# v20171017 - Add option to parse any file or just system log files. Useful for carved logs.
# v20171023 - bugfix to pattern for alllogs. missing * at end of *.log caused some logs to be missed.
# v20171026 - Fixes issue with gzipped logs not being processed due to wrong variable being returned.

import os
import time
from datetime import datetime, timedelta
import sys
import fnmatch
import re
import urllib2
import gzip
import numpy
from optparse import OptionParser

version = 'v20171026'
url = "http://www.linux-usb.org/usb.ids"

tempDFileName = ""
USBMSCmatches = []
USBMSCdevices = []

print '\n========================================================================'
print 'FindUSBMSC ', version, ' -- by David Dym'
print '========================================================================\n'

def GetOptions():
	'''Get needed options for processesing'''
	usage = "usage: %prog -d logpath -a 1";
	options = OptionParser(usage=usage);

	options.add_option("-d", action="store", type="string", dest="logpath", default=True,  help="Path to the system logs. -d ");
	options.add_option("-a", action="store", type="int", dest="all", default=False,  help="Process all logs. Useful for carved. -a 1");
	return options;

def ParseOptions():
	# Get options
	options = GetOptions()
	(opts,args) = options.parse_args()
	# The meta will store all information about the arguments passed #
	meta = {
		'logpath':opts.logpath,
		'all':opts.all
		}
	# Test arguments passed #
	if os.path.exists(meta['logpath']):
		pass
	else:
		options.error("Unable to proceed. Check the proper command syntax using -h\n")
	# Return meta to caller #
	return meta;


# deletes file if older than 2 days
def oldFileCleanup(file, days):
	current_time = time.time()
	creation_time = os.path.getctime(file)
	if (current_time - creation_time) // (24 * 3600) >= days:
		os.unlink(file)

def get_usbid_file(url):
	#url="http://.../"
	# Translate url into a filename
	filename = url.split('/')[-1]

	#check age of usb.ids and delete if older than 2 days
	if os.path.exists(filename):
		oldFileCleanup(filename, 2)
		
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

def compressedLog(filename):
	with gzip.open(filename, 'rb') as infile:
		tempDFileName = "system_tmp.log"
		with open(tempDFileName, 'wb') as outfile:
			for line in infile:
				outfile.write(line)
	return tempDFileName

def USBMSCEntry(logDate, host, serial, vid, pid, miscother):
	return "%s, %s, %s, %s, %s, %s" % (logDate, host, serial, vid, pid, miscother.strip())

def findUSBMSC(filename):
	with open(filename) as infile: 
		while True:
			lines = infile.readlines()
			if not lines:
				break
			for line in lines:

				matches = re.match(r"(^[a-z]{3}\s{1,2}\d{1,2})\s(\d\d:\d\d:\d\d)\s(.+)\s[a-z]+\[\d+\]:\sUSBMSC\s.+:\s(.*)\s0x(.*)\s0x(.*)\s0x(.*)", line, re.IGNORECASE)		
		
				if matches:
					#print line
					logDate = matches.group(1) + " "  + matches.group(2)
					host = matches.group(3).strip()
					serial = matches.group(4).strip()
					vid = matches.group(5).strip()
					pid = matches.group(6).strip()
					miscother = matches.group(7)

					USBmatch = USBMSCEntry(logDate, host, serial, vid, pid, miscother)
					if USBmatch not in USBMSCmatches:
						USBMSCmatches.append(USBmatch)

def matchUSBids(line, usbs):
	manufacturer = ""
	items = line.split(',')
	vid = items[3].strip()
	pid = items[4].strip()

	for line2 in usbs:		
		
		if line2.startswith("0"):
			if vid in line2:
				manufacturer = "%s" % re.sub(r"^0" + vid, '', line2).strip()
		elif line2.startswith("\t"):
			if pid in line2:
				if manufacturer:
					line += " [%s" % manufacturer
					line += ", %s" % line2.replace(pid,'').strip()
					line += "]"
					manufacturer = ""
	if manufacturer:
		line += " [%s]" % manufacturer
	USBMSCdevices.append(line)
	return line

#### Main ####
meta = ParseOptions()
dirpath = meta['logpath']
alllogs = meta['all']

# get usbid's
usbidlist = get_usbid_file(url)

print "Logs processed"
#read each file
if alllogs == 1:
	pattern = '*.log*'
else:
	pattern = '*system*.log*'

for filename in find_files(dirpath, pattern):
	#print filename
	#check for gzip File
	if ".gz" in filename:
		filename = compressedLog(filename)
	
	#process system log
	findUSBMSC(filename)

print "\nUSBMSC devices"
for line in USBMSCmatches:
	print matchUSBids(line, usbidlist)

#lets get distinct devices
print "\nUnique devices"
uDevices = []
for item in USBMSCdevices:
	items = item.split(',')[2:]
	if ", ".join(items) not in uDevices:
		uDevices.append(", ".join(items))
for item in uDevices:
	print item

#cleanup temp file
if tempDFileName:
	os.remove(tempDFileName)
