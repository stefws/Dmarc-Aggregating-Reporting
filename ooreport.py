#!/usr/bin/env python26
#--
#-- DMARC report generator
#-- 
#Copyright 2014 TDC
#
#Licensed under the Apache License, Version 2.0 (the "License");
#you may not use this file except in compliance with the License.
#You may obtain a copy of the License at
#
#http://www.apache.org/licenses/LICENSE-2.0
#
#Unless required by applicable law or agreed to in writing, software
#distributed under the License is distributed on an "AS IS" BASIS,
#WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#See the License for the specific language governing permissions and
#limitations under the License.
#
# Version 1.0

import sys
from datetime import date
from datetime import timedelta
import time
import getopt
import os
import errno
from struct import *
from socket import *
import ipaddr
import dmarc


#-- Config Settings
dmarclog = '/opt/msys/var/log/eccluster/'
dmarcreportdir = '/tmp/dmarcreports'
# see other def. in dmarc.report class as well

#-- while trialing only report to specific domains
trialmode = True
trialreport = dict({
 # testing domains
 'example.com' : True,
 'foo.bar' : True
})


#-- Helpers

def usage():
    print "Parses log files created by momentum and generate daily aggregate reports"
    print "ooreport.py [-h|-?|--help] [-v|--verbose] [-d <num>|--days <num>] [-n|--dryrun]"
    print "  -h|-?|--help - print this"
    print "  -v|--verbose - verbose processing"
    print "  -d <num>|--days <num> - process log data <num> days back in time, def. 1 ie. startdate"
    print "  -n|--dryrun - process log data, but don't send report(s)"


def ip_isprivate(ip):
  private = ("127.0.0.0/8","192.168.0.0/16","172.16.0.0/12","10.0.0.0/8","fc00::/7","fe80::/10")
  try:
    f=ipaddr.IPAddress(ip)
  except ValueError:
    print 'address/netmask is invalid: %s' % ip
  for net in private:
    try:
      p=ipaddr.IPNetwork(net)
    except ValueError:
      print 'address/netmask is invalid: %s' % net
    if f in p:
      return True
  return False



#-- Main body

# option parsing
try:
    opts, args = getopt.getopt(sys.argv[1:], "?hd:vn", ["help", "days=", "verbose", "dryrun"])                                
except getopt.GetoptError, err:
        usage()
        sys.exit(2)

global verbose
verbose = False
days = 1
dryrun = False

for opt, arg in opts:
    if opt in ("-?", "-h", "--help"):
        usage()     
        sys.exit()
    elif opt in ("-v", "--verbose"):
        verbose = True
    elif opt in ("-d", '--days'):
        days = int(arg)
    elif opt in ("-n", '--dryrun'):
        dryrun = True
        trialmode = True


#-- dates involved
today = date.today()
startdate = today - timedelta(days)
deltaendday = today - timedelta(days-1)
ebegin = int(time.mktime(startdate.timetuple()))
eend = int(time.mktime(deltaendday.timetuple()))

dmarcreport = {}
cacti = dmarc.cactistat()

#-- collect and count DICs from logs per domain
directory = '%s%s/dmarclog/momi' % (dmarclog,startdate.strftime('%Y/%m/%d'))
if verbose: print('walking log dir: %s...' % (directory))
for root, dirs, files in os.walk(directory):
  if verbose: print('looking under: %s,%s,%s' % (root, dirs, files))
  for file in files:
    filename = '%s/%s' % (root,file)
    if verbose: print('		parsing log: %s...' % (file))
    fp = open(filename)
    for ln in fp:
      line = dmarc.logline(ln)
      if line.valid():
        dom = line.fromdom
        if not dom in dmarcreport:
          dmarcreport[dom] = dmarc.report(dom,startdate,ebegin,eend)
        ts = int(line.ts)
        if ebegin <= ts and ts <= eend and not ip_isprivate(line.ip):
          dmarcreport[dom].update(line)
          cacti.update(line)

    fp.close()
    if dryrun: break

try:
  os.makedirs(dmarcreportdir)
except OSError, e:
  if e.errno != errno.EEXIST:
    raise

#-- report per domain collected
for dom in dmarcreport:
  if not trialmode or dom in trialreport:
    dmarcreport[dom].generateNsubmit(verbose,dryrun,dmarcreportdir)

cacti.dump2path()
