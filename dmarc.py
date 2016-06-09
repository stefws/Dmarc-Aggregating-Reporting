#!/usr/bin/env python26
#--
#-- DMARC Classes
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
# Version 1.1

import sys
from datetime import date
from datetime import timedelta
import time
import getopt
import os
import errno
import dns.resolver
import re
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from email.encoders import encode_base64
import gzip


#** type defines


#--define dmarc classes

class dnstags(object):

  def __init__(self, dom):
    # input
    self.domain = dom
    self.dnstxt = ''
    # parsed/default tag values
    self.v = None  # required
    self.p = None  # required
    self.sp = None
    self.rua = None
    self.ruf = None
    self.adkim = 'r'
    self.aspf = 'r'
    self.fo = '0'
    self.pct = 100
    self.rf = 'afrf'
    self.ri = 86400
    self._parse()
    #EOF

  def __del__(self):
    pass #EOF

  def _parse(self):

    # get tag list from DNS
    try:
      answers = dns.resolver.query('_dmarc.%s' % self.domain, 'TXT')
    except dns.exception.DNSException:
      answers=[]
    # TODO: possible unfold TXT rr according to rfc6541
    # We only handle v=DMARC1 tags
    expr = r'^v\s*=\s*DMARC1\s*;\s*p\s*=\s*\S+'
    for rdata in answers:
      txt=rdata.to_text().strip('"')
      if re.match(expr, txt):
        self.dnstxt = txt.lower()
        break

    tags = re.split(r'\s*;\s*', self.dnstxt);
    for tag in tags:
      try:
        kv = re.search(r'(?P<key>\S+)\s*=\s*(?P<val>.+)', tag)
        key = kv.group('key')
        val = kv.group('val')
        try:
          nval = int(val)
        except:
          nval = -1
        #-- look for known valid tags & values of v=DMARC1, ignore others
        if (key=='p' or key=='sp'):
          if (val=='reject' or val=='quarantine'):
            setattr(self, key, val)
          else:
            setattr(self, key, 'none')
        elif (key=='adkim' or key=='aspf' and (val=='r' or val=='s')) or \
             (key=='v' or key=='rua' or key=='ruf' or key=='fo') or \
             (key=='rf' and (val=='afrf' or val=='iodef')):
          setattr(self, key, val)
        elif (key=='pct' and 0 <= nval and nval <= 100) or (key=='ri' and nval >= 3600):
          setattr(self, key, nval)
        else:
          #print '%s: %s: ignored tag %s of %s' % (self.__name__,self.domain,key,self.dnstxt)
          pass

      except:
        pass
    if not self.sp: self.sp = self.p
    #EOF

  def valid(self):
    # only if required tags are
    return (self.v=='dmarc1' and self.p)
    #EOF

  def __str__(self):
    return "domain: %s =>\n\tv:%s\n\tp:%s\n\tsp:%s\n\taspf:%s\n\tadkim:%s\n\tpct:%d\n\tri:%d\n\trf:%s\n\trua:%s\n\truf:%s\n" % (self.domain,self.v,self.p,self.sp,self.aspf,self.adkim,self.pct,self.ri,self.rf,self.rua,self.ruf)
    #EOF

  #EOC


class uri(object):

  def __init__(self, encodeduri):
    self.protocol = None  # 'mailto' | 'http[s]'
    self.uri = None       # <decoded email> | <URL>
    self.szlimit = 0      # optional: #bytes, 0=unlimited
    self.factor = 1       # numical factor of unit
    self.unit = None      # optional: '[k|m|g|t]{1}'
    try:
      lim = 0; fac = 1
      elem = re.search(r'^(?P<proto>\S+):(?P<uri>\S+)$', encodeduri)
      self.protocol = elem.group('proto')
      if re.search('^http',self.protocol):
        self.uri = elem.group('uri')
      elif self.protocol=='mailto':
        uripart = elem.group('uri').split('!')
        self.uri = re.sub('%2c', ',', re.sub('%21', '!', uripart[0]))
        if len(uripart) == 2:
          try:
            elem = re.search(r'^(?P<num>\d+)(?P<unit>[kmgt]{1})?$', uripart[1])
            lim = int(elem.group('num'))
            if lim <= 0:
              lim = 0
            self.unit = elem.group('unit')
            if not self.unit:
              fac=1
            elif self.unit=='k':
              fac=1024
            elif self.unit=='m':
              fac=1024**2
            elif self.unit=='g':
              fac=1024**3
            elif self.unit=='t':
              fac=1024**4
            else:
              fac=1
            self.szlimit = lim * fac
            self.factor = fac

          except:
            self.protocol = None
            self.uri = None
      else:
        self.protocol = None
        self.uri = None

    except:
      pass
    #EOF

  def __del__(self):
    pass #EOF

  def __str__(self):
    if self.protocol=='mailto':
      if self.szlimit==0:
        sztag = ''
      elif self.unit:
        sztag = '!%d%s' % ((self.szlimit/self.factor),self.unit)
      else:
        sztag = '!%d' % self.szlimit
      return  '%s:%s%s' % (self.protocol,re.sub(',','%2C',re.sub('!','%21',self.uri)),sztag)

    return ''
    #EOF

  #EOC


class urilist(object):

  def __init__(self, urilist, domain):
    self.list = []
    dotdom = '.' + domain
    urisets = re.split(r'\s*,\s*', urilist)
    for u in urisets:
      dmuri = uri(u)
      if dmuri.protocol == 'mailto':  # we only deal with mailto URIs so far :)
        uripart = dmuri.uri.split('@')
        if len(uripart) == 2:
          uridotdom = '.' + uripart[1]
          if dotdom.find(uridotdom) >= 0: # maybe also this: or uridotdom.find(dotdom) >= 0:
            self.list.append(dmuri)
          else:
            try:
              txtrrs = dns.resolver.query('%s._report._dmarc%s' % (domain, uridotdom), 'TXT')
              for txt in txtrrs:
                txt=txt.to_text().strip('"')
                if txt == 'v=DMARC1':
                  self.list.append(dmuri)
            except dns.exception.DNSException:
              pass

    #EOF

  def __del__(self):
    for u in self.list:
      del u
    #EOF

  def __str__(self):
    str = ''
    sep = ''
    for u in self.list:
      str = '%s%s%s' % (str,sep,u)
      sep = ','
    return str
    #EOF

  def len(self):
    return len(self.list)
    #EOF

  def uris(self):
    str = ''
    sep = ''
    for u in self.list:
      str = '%s%s%s' % (str,sep,u.uri)
      sep = ','
    return str
    #EOF

  #EOC


class policy(object):

  def __init__(self,poldom,aspf=None,adkim=None,p=None,sp=None,pct=None):
    if isinstance(poldom, policy) and aspf==None:
      #self = poldom
      self.dom = poldom.dom
      self.aspf = poldom.aspf
      self.adkim = poldom.adkim
      self.p = poldom.p
      self.sp = poldom.sp
      self.pct = poldom.pct
    else:
      self.dom = poldom
      self.aspf = aspf
      self.adkim = adkim
      self.p = p
      self.sp = sp
      self.pct = pct
    #EOF

  def __del__(self):
    pass #EOF

  def _tuple(self):
    return (self.dom,self.aspf,self.adkim,self.p,self.sp,self.pct)
    pass #EOF

  def __str__(self):
    if self.p:
      return '%s@%s@%s@%s@%s@%s' % self._tuple()
    else:
      return ''
    #EOF

  def __eq__(self, pol):
    return (pol and isinstance(pol, policy) and str(self)==str(pol))
    #EOF

  def __ne__(self, pol):
    return not (self == pol)
    #EOF

  def xml(self):
    if self.p:
      xml = '  <policy_published>\n    <domain>%s</domain>\n    <adkim>%s</adkim>\n    <aspf>%s</aspf>\n    <p>%s</p>\n    <sp>%s</sp>\n    <pct>%s</pct>\n  </policy_published>\n' % self._tuple()
    else:
      xml = ''
    return xml
    #EOF

  #EOC


class logline(object):

  def __init__(self, line):
    try:
      (self.ts,self.vtag,self.node,self.msgid,self.ip,
       self.status,self.polrequest,self.dispos,self.comment,self.fromdom,
       dom,aspf,adkim,pol,subpol,pct,
       SPFtag,self.spfaligned,self.envdom,self.spfstatus,
       DKIMtag,self.dkimaligned,self.dkimrec) = line.split('@',22)
      if self.vtag.lower()=='dmarc1':
        self.dkimrec = self.dkimrec[0:-1] # strip newline
        dkimstat = self.dkimrec.split('@')
        self.policy = policy(dom,aspf,adkim,pol,subpol,pct)
      else:
        self.ts = None
    except:
      self.ts = None  #-- invalidate object
      self.vtag = None
      self.node = None
      self.msgid = None
      self.ip = None
      self.status = None
      self.polrequest = None
      self.dispos = None
      self.comment = None
      self.spfaligned = None
      self.dkimaligned = None
      self.fromdom = None
      self.envfrom = None
      self.spfstatus = None
      self.dkimrec = None
      self.signlist = []
      self.signs = None
      self.policy = None
    #EOF

  def __del__(self):
    pass #EOF

  def valid(self):
    return (self.ts!=None)
    #EOF

  def __str__(self):
    if self.ts:
      return '%s@%s@%s@%s@%s@%s@%s@%s@%s@%s@%s@SPF@%s@%s@%s@DKIM@%s@%s' % (
              self.ts,self.vtag,self.node,self.msgid,self.ip,
              self.status,self.polrequest,self.dispos,self.comment,self.fromdom,
              self.policy,
              self.spfaligned,self.envdom,self.spfstatus,
              self.dkimaligned,self.dkimrec)
    else:
      return ''
    #EOF

  def hash(self):
    return '%s|%s|%s|%s|%s|%s|%s|%s|%s' % (self.ip,self.polrequest,self.fromdom,self.dispos,self.spfaligned,self.dkimaligned,self.envdom,self.spfstatus,self.dkimrec)
    #EOF

  #EOC


class dkimsign(object):

  def __init__(self, dom, status):
    self.dom = dom
    self.status = status
    #EOF

  def __del__(self):
    pass #EOF

  def __str__(self):
    return '%s@%s' % (self.dom,self.status)
    #EOF

  #EOC


class dkimsignlist(object):

  def __init__(self, dkimrec):
      dkimstat = dkimrec.split('@')
      n = len(dkimstat)
      self.list = []
      if n > 1 and (n % 2) == 0: #-- split dkim validation status up per signature pairs
        for i in range(0,n,2):
          sign = dkimsign(dkimstat[i], dkimstat[i+1])
          self.list.append(sign)
      self.signs = (self.list and len(self.list)) or 0
    #EOF

  def __del__(self):
    for s in self.list:
      del s
    #EOF

  def __str__(self):
    str = ''
    sep = ''
    for sign in self.list:
      str = '%s%s%s' % (str, sep, sign)
      sep = '@'
    return str
    #EOF

  def xml(self):
    xml = ''
    for sign in self.list:
      xml += '      <dkim>\n        <domain>%s</domain>\n        <result>%s</result>\n      </dkim>\n' % (sign.dom,sign.status)
    return xml
    #EOF

  #EOC


class stathash(object):

  def __init__(self, key):
    try:
      (self.ip,self.polrequest,self.fromdom,self.dispos,self.spfaligned,self.dkimaligned,self.envdom,self.spfstatus,self.dkimrec) = key.split('|', 8)
      self.signlist = dkimsignlist(self.dkimrec)
    except:
      self.ip = None
    #EOF

  def __del__(self):
    #if self.signlist and isinstance(self.signlist, dkimsignlist):
    #  del self.signlist
    pass #EOF

  def __str__(self):
    if self.valid():
      return '%s|%s|%s|%s|%s|%s|%s|%s|%s' % (self.ip,self.polrequest,self.fromdom,self.dispos,self.spfaligned,self.dkimaligned,self.envdom,self.spfstatus,self.dkimrec)
    else:
      return 'no stathash object defined'
    
  def valid(self):
    return (self.ip!=None)
    #EOF

  #EOC


class statrec(object):

  def __init__(self, logl):
    if isinstance(logl, logline) and logl.valid():
      self.pol = logl.policy
      self.msgcount = 1
      self.hash = stathash(logl.hash())
      if not self.hash.valid():
        self.pol = None
        self.hash = None
      self.comment = logl.comment
    else:
      self.pol = None
      self.hash = None
      self.comment = None
    #EOF

  def __del__(self):
    #if self.pol and isinstance(self.pol, policy):
    #  del self.pol
    #if self.hash and isinstance(self.hash, stathash):
    #  del self.hash
    pass #EOF

  def __str__(self):
    if isinstance(self.hash, stathash): # and isinstance(self.pol, policy):
      s = '%s|%s' % (self.pol, self.hash)
    else:
      s = ''
    return s
    #EOF

  def valid(self):
    return isinstance(self.hash, stathash)
    #EOF

  def xml(self, pol):
    if isinstance(self.hash, stathash):
      xml = ''
      if pol==None or self.pol != pol:
        xml = self.pol.xml()
      dispos = self.hash.dispos
      comment = not (dispos=='none' or dispos=='reject' or dispos=='quarantine')
      if comment:
        dispos = 'none'
      xml += '  <record>\n    <row>\n      <source_ip>%s</source_ip>\n      <count>%d</count>\n      <policy_evaluated>\n        <disposition>%s</disposition>\n        <dkim>%s</dkim>\n        <spf>%s</spf>\n' % (self.hash.ip, self.msgcount, dispos, self.hash.dkimaligned, self.hash.spfaligned)
      if comment:
        cmt = self.comment
        if len(cmt)==0:
          cmt = 'none'
        xml += '        <reason>\n          <type>%s</type>\n          <comment>%s</comment>\n        </reason>\n' % (self.hash.dispos, cmt)
      xml += '      </policy_evaluated>\n    </row>\n    <identifiers>\n      <header_from>%s</header_from>\n    </identifiers>\n    <auth_results>\n      <spf>\n        <domain>%s</domain>\n        <result>%s</result>\n      </spf>\n%s    </auth_results>\n  </record>\n' % (self.hash.fromdom, self.hash.envdom, self.hash.spfaligned, self.hash.signlist.xml())
    else:
      xml = ''
    return xml
    #EOF

  def inc(self,i=None):
    i = i or 1
    self.msgcount+=i
    #EOF

  #EOC


class report(object):

  def __init__(self,domain,sdate,begin,end,rtag='dmarc'):

    #-- default report settings, change through object 'setters' if desired
    self.repenv = 'dmarc.noreply@foo.bar'
    self.repfrom= 'dmarc.report@foo.bar'
    self.smtpsrv = 'smtp.foo.bar'
    self.smtpport= 25
    self.orgname = 'foo.bar'
    self.email = 'postmaster@foo.bar'
    self.contact = 'http://postmaster.foo.bar'

    self.sdate = sdate
    self.begin = begin
    self.end = end
    self.rtag = rtag
    self.tags = dnstags(domain)
    self.dul = None
    if self.tags.valid() and self.tags.rua: self.dul = urilist(self.tags.rua, domain)
    self.statdict = {}
    #EOF

  def _xml(self, rid):
    xml = ''
    if self.rtag and self.begin and self.end and self.begin < self.end:
      xml = '<?xml version="1.0" encoding="UTF-8" ?>\n<feedback>\n  <report_metadata>\n    <org_name>%s</org_name>\n    <email>%s</email>\n    <extra_contact_info>%s</extra_contact_info>\n    <report_id>%s</report_id>\n    <date_range>\n      <begin>%d</begin>\n      <end>%d</end>\n    </date_range>\n  </report_metadata>\n' % (self.orgname, self.email, self.contact, rid, self.begin, self.end)
      p = None
      for hash in self.statdict:
        sr = self.statdict[hash]
        xml += sr.xml(p)
        p = sr.pol
      xml += '</feedback>'
    return xml
    #EOF

  def update(self, line):
    if isinstance(line, logline) and line.valid():
      hash = line.hash()
      if hash in self.statdict:
        self.statdict[hash].inc()
      else:
        self.statdict[hash] = statrec(line)
    #EOF

  def generateNsubmit(self,verbose=False,dryrun=False,xmldir='/tmp/dmarcreports'):
    dom = self.tags.domain
    numstats = (self.statdict and len(self.statdict)) or 0
    if numstats==0:
      if verbose: print 'no report generated for %s due to empty statdict...' % dom
    elif self.dul==None or len(self.dul.uris())==0:
      print 'ERROR: no one to report to for %s' % dom
    else:
      if verbose: print '\nFound valid URI(s) for %s: %s' % (dom,self.dul.uris())
      if verbose: print '%s statdict %d entries...' % (dom,numstats)
      rid = "%s!%s!%d!%d!%s" % \
             (self.orgname,dom,self.begin,self.end,self.rtag)
      xmlreport = '%s/%s.xml' % (xmldir,rid)
      if verbose: print 'Writing XML report for %s into: %s ...' % (dom, xmlreport)
      frep = open (xmlreport,"w")
      frep.write(self._xml(rid))
      frep.close()
      # compress XML report
      gzxmlreport = xmlreport + '.gz'
      gzipped = True
      zr = gzip.open(gzxmlreport,'wb')
      xr = open(xmlreport,'rb')
      try:
        zr.writelines(xr)
      except:
        gzipped = False
      finally:
        zr.close()
        xr.close()
      # remove uncompressed report?
      if not dryrun: os.unlink(xmlreport)
      if not gzipped:
        if verbose: print 'failed to gzip report for %s, bailing out...' % dom
        return False
      # encode in a message
      zr = open(gzxmlreport,'rb')
      gzipmsg = MIMEApplication(zr.read(),'gzip',_encoder=encode_base64)
      zr.close()
      gzipmsg.add_header('Content-Disposition', 'attachment', filename=rid+'.xml.gz')
      msg = MIMEMultipart()
      msg['From']=self.repfrom
      msg['To']='"DMARC RUA recipient" <>'
      msg['Subject']= 'Report Domain: %s Submitter: %s Report-ID: %s' % (dom,self.orgname,rid)
      msg.attach(gzipmsg)
      msgtxt = msg.as_string(False)
      msgtxtlen = len(msgtxt)
      if verbose: print 'Msg size: %d' % msgtxtlen
      rcptlist = []
      for rcpt in self.dul.list:
        if rcpt.szlimit==0 or msgtxtlen < rcpt.szlimit:
          rcptlist.append(rcpt.uri)

      for rcpt in rcptlist: # send to rcpt(s)
        if verbose: print 'Email for %s to rcpt: %s' % (dom, rcpt)
        if dryrun:
          if verbose: print '  sending skipped in dryrun mode'
        else:
          try:
            smtpcnx = smtplib.SMTP(self.smtpsrv, self.smtpport)
            smtpcnx.sendmail(self.repenv, rcpt, msgtxt)
            smtpcnx.quit()
          except Exception:
            print 'ERROR: failed to send RUA report for %s to: %s' % (dom, rcpt)

      # remove compressed report
      os.unlink(gzxmlreport)

      return True
    #EOF

  #EOC


class cactistat(object):

  def __init__(self):
    self.status = { 'pass':0, 'fail':0 }
    self.spfalign = { 'relaxed':0, 'strict':0, 'failed':0 }
    self.dkimalign = { 'relaxed':0, 'strict':0, 'failed':0 }
    self.dispos = { 'none':0, 'rejected':0, 'quarantined':0, 'local_policy':0, 'sampled_out':0, 'unknowned':0 }
    #EOF

  def __str__(self):
    return 'status_pass:%d status_fail:%d spf_relaxed:%d spf_strict:%d spf_failed:%d dkim_relaxed:%d dkim_strict:%d dkim_failed:%d dispos_none:%d dispos_rejected:%d dispos_quarantined:%d dispos_local_policy:%s dispos_sampled_out:%d dispos_unknown:%d' % (self.status['pass'], self.status['fail'], self.spfalign['relaxed'], self.spfalign['strict'], self.spfalign['failed'], self.dkimalign['relaxed'], self.dkimalign['strict'], self.dkimalign['failed'], self.dispos['none'], self.dispos['rejected'], self.dispos['quarantined'], self.dispos['local_policy'], self.dispos['sampled_out'], self.dispos['unknowned'])

  def update(self, line):
    if isinstance(line, logline) and line.valid():
      if line.status == 'pass':
        self.status['pass']+=1
      else:
        self.status['fail']+=1

      if line.spfaligned == 'pass':
        if line.policy.aspf == 's':
          self.spfalign['strict']+=1
        else:
          self.spfalign['relaxed']+=1
      else:
        self.spfalign['failed']+=1

      if line.dkimaligned == 'pass':
        if line.policy.adkim == 's':
          self.dkimalign['strict']+=1
        else:
          self.dkimalign['relaxed']+=1
      else:
        self.dkimalign['failed']+=1

      if line.dispos == 'none':
        self.dispos['none']+=1
      elif line.dispos == 'reject':
        self.dispos['rejected']+=1
      elif line.dispos == 'quarantine':
        self.dispos['quarantined']+=1
      elif line.dispos == 'local_policy':
        self.dispos['local_policy']+=1
      elif line.dispos == 'sampled_out':
        self.dispos['sampled_out']+=1
      else:
        self.dispos['unknowned']+=1
    #EOF

  def dump2path(self):
    path = '/tmp/dmarc.cacti'
    try:
      frep = open (path,"w")
      frep.write('%s\n' % self)
      frep.close()
    except Exception:
      print 'ERROR: failed to write "%s" to %s' % (self, path)
    #EOF

  #EOC

#** End of Classes **



#** local helpers

def usage():
    print "lookup and parse dmarc record from dns of given domain"
    print "dmarc.py [-h|-?|--help] [-v|--verbose] {-d | --domain} <domain>"
    print "-h|-?|--help - print this"
    print "-v|--verbose - verbose processing"
    print "<domain> - domain to lookup and parse"


#** Main body for testing classes...

if __name__ == "__main__":
  # option parsing
  try:
    opts, args = getopt.getopt(sys.argv[1:], "?hvd:", ["help", "verbose", "domain"])                                
  except getopt.GetoptError, err:
    usage()
    sys.exit(2)

  domain = ''

  verbose = False
  for opt, arg in opts:
    if opt in ("-?", "-h", "--help"):
      usage()     
      sys.exit()
    elif opt in ("-v", '--verbose'):
      verbose = True
    elif opt in ("-d", '--domain'):
      domain = arg.lower()

  if len(domain) <= 0:
    usage()     
    sys.exit()
  else:
    dt = dnstags(domain)

    #print '%s obj found to have attr:\n%s' % (dt,dir(dt))
    if dt.valid():
      #print "%s\n" % dt
      if dt.rua:
        dmrua = urilist(dt.rua, domain)
      #  print 'RUA: %s' % dmrua
      #  for u in dmrua.list:
      #    print u
      if dt.ruf:
        dmruf = urilist(dt.ruf, domain)
      #  print 'RUF: %s' % dmruf
      #  print 'RUF: %s' % dmruf.uris()
      #print '\n\n'
    else:
      print "domain %s => not valid dmarc: '%s'\n\n" % (domain, dt.dnstxt)

  logl = '1396389581@dmarc1@fep29@A7/C9-20604-DC63B335@199.16.156.164@pass@reject@none@@twitter.com@twitter.com@r@r@reject@reject@100@s@pass@bounce.twitter.com@pass@d@pass@twitter.com@pass\n'
  rec1 = logline(logl)
  #print rec1
  #print '%s\n' % logl

  logl = '1396389583@dmarc1@fep29@88/C9-20604-FC63B335@66.220.155.169@pass@reject@none@@facebookmail.com@facebookmail.com@r@r@reject@reject@100@spf@pass@facebookmail.com@pass@d@pass@facebookmail.com@pass\n'
  rec2 = logline(logl)
  #print rec2
  #print '%s\n' % logl
  #print '%s' % rec2.policy.xml()
  #print '%s' % rec2.policy
  #dp = policy(rec2.policy)
  #print '%s\n' % dp

  logl = '1396558738@dmarc1@fep23@71/CB-26879-29BCD335@209.85.215.47@pass@none@none@@gmail.com@gmail.com@r@r@none@none@100@S@pass@gmail.com@pass@D@pass@gmail.com@pass\n'
  rec3 = logline(logl)
  #print rec3
  #print rec3.hash()
  #dmst = statrec(rec3)
  #print dmst.hash
  #print dmst.pol
  #print '%s=%d\n' % (dmst, dmst.msgcount)

  startdate = date.today()
  dr = report(domain,startdate,12345,23456)
  #dr.update(rec3)
  logl = '1396869553@dmarc1@fep25@DC/54-07107-1B982435@91.211.240.8@fail@reject@local_policy@DKIM validation bug@nyheder.bilka.dk@nyheder.bilka.dk@r@s@reject@reject@100@S@fail@emarsys.net@pass@D@fail@nyheder.bilka.dk@fail\n'
  rec = logline(logl)
  dr.update(rec)
  dr.update(rec1)
  dr.update(rec2)
  dr.update(rec3)
  print '\n'
  rid = "%s!%s!%d!%d!%s" % \
         (dr.orgname,domain,dr.begin,dr.end,dr.rtag)
  print '%s' % dr._xml(rid)

  cacti = cactistat()
  cacti.update(rec)
  cacti.update(rec1)
  cacti.update(rec2)
  cacti.update(rec3)
  print '\n\n%s\n' % (cacti)
  cacti.dump2path()
