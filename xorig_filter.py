## To roll your own milter, create a class that extends Milter.  
#  See the pymilter project at http://bmsi.com/python/milter.html
#  based on Sendmail's milter API 
#  This code is open-source on the same terms as Python.

## Milter calls methods of your class at milter events.
## Return REJECT,TEMPFAIL,ACCEPT to short circuit processing for a message.
## You can also add/del recipients, replacebody, add/del headers, etc.

import Milter
import StringIO
import time
import email
import sys
from socket import AF_INET, AF_INET6
from Milter.utils import parse_addr
if True:
  from multiprocessing import Process as Thread, Queue
else:
  from threading import Thread
  from Queue import Queue

import spf

logq = Queue(maxsize=4)

class xorigMilter(Milter.Base):

  def __init__(self):  # A new instance with each new connection.
    self.id = Milter.uniqueID()  # Integer incremented with each call.

  # each connection runs in its own thread and has its own xorigMilter
  # instance.  Python code must be thread safe.  This is trivial if only stuff
  # in xorigMilter instances is referenced.
  @Milter.noreply
  def connect(self, IPname, family, hostaddr):
    # (self, 'ip068.subnet71.example.com', AF_INET, ('215.183.71.68', 4720) )
    # (self, 'ip6.mxout.example.com', AF_INET6,
    #   ('3ffe:80e8:d8::1', 4720, 1, 0) )
    self.IP = hostaddr[0]
    self.port = hostaddr[1]
    if family == AF_INET6:
      self.flow = hostaddr[2]
      self.scope = hostaddr[3]
    else:
      self.flow = None
      self.scope = None
    self.IPname = IPname  # Name from a reverse IP lookup
    self.H = None
    self.xOriginatingIps = {}
    self.receiver = self.getsymval('j')
    self.log("connect from %s at %s" % (IPname, hostaddr) )
    
    return Milter.CONTINUE


  ##  def hello(self,hostname):
  def hello(self, heloname):
    self.H = heloname
    self.log("HELO %s" % heloname)
    return Milter.CONTINUE

  ##  def envfrom(self,f,*str):
  def envfrom(self, mailfrom, *str):
    self.F = mailfrom
    self.R = []  # list of recipients
    self.fromparms = Milter.dictfromlist(str)   # ESMTP parms
    self.user = self.getsymval('{auth_authen}') # authenticated user
    self.log("mail from:", mailfrom, *str)
    # NOTE: self.fp is only an *internal* copy of message data.  You
    # must use addheader, chgheader, replacebody to change the message
    # on the MTA.
    self.fp = StringIO.StringIO()
    self.canon_from = '@'.join(parse_addr(mailfrom))
    self.fp.write('From %s %s\n' % (self.canon_from,time.ctime()))
    return Milter.CONTINUE



  @Milter.noreply
  def header(self, name, hval):
    #if name == "Authentication-Results":
    #    print "{}: {}".format(name, hval)
    if name.lower() == "x-originating-ip":
        origip = hval[1:-1]
        self.log( "Got x-originating-ip: {} mail from: {}".format(origip, self.canon_from))

    #    res_aip, exp_aip  = spf.check2 (s=efrom2, i=self.IP, h=self.H, verbose=True)
    #    print ("aip: {}, res_aip: {}, exp_aip: {}".format(self.IP, res_aip, exp_aip))

    #    res_oip, exp_oip  = spf.check2 (s=efrom2, i=origip, h=self.H, verbose = True)
    #    print ("oip: {}, res_oip: {}, exp_oip: {}".format(origip, res_oip, exp_oip))

        # if sent by ESS and SPF for @doamin matches ESS then sender is also iour customer

        self.log( "Check if message  commes from ESS" )
        q = spf.query(s=self.canon_from, i=self.IP, h=self.H, verbose = False)
        res_hip, _, exp_hip = q.check(spf="v=spf1 include:spf.messagelabs.com ~all")
        self.log ("hip: {}, res_hip: {}, exp_hip: {}".format(self.IP, res_hip, exp_hip))

        if (res_hip == "pass"):     # it means that we received x-original-header and the mail comes from ESS 
            self.log("Message sent by ESS")
            self.log("Check if message is sent by our customer")
            res_aip, exp_aip  = spf.check2 (s=self.canon_from, i=self.IP, h=self.H, verbose=False)
            self.log(("aip: {}, res_aip: {}, exp_aip: {}".format(self.IP, res_aip, exp_aip)))

            if (res_aip == "pass"): # ESS IP is allowed to send messages as user@domain.
                self.log("Sent from symantec and comming from Symantec customer.")
                if name in self.xOriginatingIps:
                    self.xOriginatingIps[name]+=[hval]
                else:
                    self.xOriginatingIps[name]=[hval]
                self.log( "Mark header for remowal. We've seen {} x-originating-ips so far.".format(str(len(self.xOriginatingIps))))
                return Milter.CONTINUE

        self.log( "Sent not by Symantec Customer, keep x-originating-ip.")
        self.fp.write("%s: %s\n" % (name,hval))     # add header to buffer
    return Milter.CONTINUE

  def eom(self):
    self.fp.seek(0)
    msg = email.message_from_file(self.fp)
    if (len(self.xOriginatingIps)>0):
        for name, all_hvals in self.xOriginatingIps.iteritems():
            i=0
            for hval in all_hvals:
                i+=1
                self.log( "removing header {} number: {}".format(name, str(i)))
                self.chgheader(name, i, '')
                self.log( "adding new header {}-removed with value: {}".format(name, hval))
                self.addheader(name+"-removed", hval)
        self.log( "adding new header X-Originating-IP with connection ip: [{}]".format(self.IP))
        self.addheader("X-Originating-IP", "[{}]".format(self.IP))
    return Milter.ACCEPT

  ## === Support Functions ===


  def log(self,*msg):
    logq.put((msg,self.id,time.time()))

def background():
  while True:
    t = logq.get()
    if not t: break
    msg,id,ts = t
    print "%s [%d]" % (time.strftime('%Y%b%d %H:%M:%S',time.localtime(ts)),id),
    # 2005Oct13 02:34:11 [1] msg1 msg2 msg3 ...
    for i in msg: print i,
    print


    
def main():
  bt = Thread(target=background)
  bt.start()
  socketname = "/root/miltersock"
  timeout = 600
  # Register to have the Milter factory create instances of your class:
  Milter.factory = xorigMilter
  flags = Milter.CHGHDRS + Milter.ADDHDRS
  Milter.set_flags(flags)       # tell Sendmail which features we use
  print "%s milter startup" % time.strftime('%Y%b%d %H:%M:%S')
  sys.stdout.flush()
  Milter.runmilter("pythonfilter",socketname,timeout)
  logq.put(None)
  bt.join()
  print "%s bms milter shutdown" % time.strftime('%Y%b%d %H:%M:%S')

if __name__ == "__main__":
  main()

