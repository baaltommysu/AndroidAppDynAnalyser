################################################################################
# (c) 2011, The Honeynet Project
# Author: Patrik Lantz patrik@pjlantz.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#
################################################################################

import sys, json, time, curses, signal, os
import zipfile, StringIO
from threading import Thread
from xml.dom import minidom
from subprocess import call, PIPE
from utils import AXMLPrinter
import hashlib




import riskDynBehaviour


sendsms = {}
phonecalls = {}
cryptousage = {}
netbuffer = {}

dexclass = {}
dataleaks = {}
opennet = {}
sendnet = {}
recvnet = {}
fdaccess = {}
servicestart = {}
xml = {}
udpConn = []
permissions = []
activities = []
activityaction = {}
enfperm = []
packageNames = []
recvs = []
recvsaction = {}
accessedfiles = {}



riskactivities = {      	
    "FILE_READ"                                         : [ ],
    "FILE_WRITE"					: [ ],
    "INSTALL_APK"                                       : [ ],

    "CRYPTO_API"					: [ ],
	
    "OPEN_CONN"			         		: [ ],
    "OUTGOING_TRAF"					: [ ],
    "INCOMING_TRAF"					: [ ],

    "DEX_CLASS_LOADER"				        : [ ],

    "BROADCAST_RECEIVER"				: [ ],
    "START_SERVICE"					: [ ],
    "ENFORCED_PERMISSION"				: [ ],
    "BYPASSED_PERMISSION"				: [ ],

    "INFO_LEAKAGE_SMS"				        : [ ],
    "INFO_LEAKAGE_OTHERS"			        : [ ],

    "SENT_SMS_LEAKAGE"				        : [ ],
    "SENT_SMS_NORMAL"				        : [ ],
	
    "PHONE_CALLS"					: [ ],
	}


PHONE_NUMBER = []
URL = []
FILE_NAME=[]

services = []

tags = { 0x1 :   "TAINT_LOCATION",      0x2: "TAINT_CONTACTS",        0x4: "TAINT_MIC",            0x8: "TAINT_PHONE_NUMBER", 
         0x10:   "TAINT_LOCATION_GPS",  0x20: "TAINT_LOCATION_NET",   0x40: "TAINT_LOCATION_LAST", 0x80: "TAINT_CAMERA",
         0x100:  "TAINT_ACCELEROMETER", 0x200: "TAINT_SMS",           0x400: "TAINT_IMEI",         0x800: "TAINT_IMSI",
         0x1000: "TAINT_ICCID",         0x2000: "TAINT_DEVICE_SN",    0x4000: "TAINT_ACCOUNT",     0x8000: "TAINT_BROWSER",
         0x10000: "TAINT_OTHERDB",      0x20000: "TAINT_FILECONTENT", 0x40000: "TAINT_PACKAGE",    0x80000: "TAINT_CALL_LOG",
         0x100000: "TAINT_EMAIL",       0x200000: "TAINT_CALENDAR",   0x400000: "TAINT_SETTINGS" }

class CountingThread(Thread):
    """
    Used for user interface, showing in progress sign 
    and number of collected logs from the sandbox system
    """

    def __init__ (self):
        """
        Constructor
        """
        
        Thread.__init__(self)
        self.stop = False
        self.logs = 0
        
    def stopCounting(self):
        """
        Mark to stop this thread 
        """
        
        self.stop = True
        
    def increaseCount(self):
        
        self.logs = self.logs + 1

    def run(self):
        """
        Update the progress sign and 
        number of collected logs
        """
        
        signs = ['|', '/', '-', '\\']
        counter = 0
        while 1:
            sign = signs[counter % len(signs)]
            sys.stdout.write("     \033[1;32m[%s] Collected %s sandbox logs\033[1;m   (Ctrl-C to view logs)\r" % (sign, str(self.logs)))
            sys.stdout.flush()
            time.sleep(0.5)
            counter = counter + 1
            if self.stop:
                sys.stdout.write("   \033[1;32m[%s] Collected %s sandbox logs\033[1;m%s\r" % ('*', str(self.logs), ' '*25))
                sys.stdout.flush()
                break
                
class ActivityThread(Thread):
    """
    Run until the main Activity 
    within an APK have been started
    """

    def __init__ (self):
        """
        Constructor
        """
        
        Thread.__init__(self)
        
    def run(self):
        """
        Run main activity found in Manifest
        """

        runActivity = ''
        runPackage = ''
        for activity in activities:
            if activityaction.has_key(activity) and activityaction[activity] == 'android.intent.action.MAIN':
                if activity[0] == '.':
                    runActivity = activity
                    runPackage = packageNames[0]
                else:
                    for package in packageNames:
                        splitAct = activity.split(package)
                        if len(splitAct) > 1:
                            runActivity = splitAct[1]
                            runPackage = package
                            break
                        else:
                            runActivity = splitAct[0]
                            runPackage = package
                            break
                
                call(['monkeyrunner', 'scripts/monkeyrunner.py', apkName, runPackage, runActivity], stderr=PIPE)
                
                break
            

            




def fileHash(f, block_size=2**8):
    """
    Calculate MD5,SHA-1, SHA-256
    hashes of APK input file
    """
    
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    f = open(f, 'rb')
    while True:
        data = f.read(block_size)
        if not data:
            break
        md5.update(data)
        sha1.update(data)
        sha256.update(data)
    return [md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()]
    
def hexToStr(hexStr):
    """
    Convert a string hex byte values into a byte string
    """
 
    bytes = []
    hexStr = ''.join(hexStr.split(" "))
    for i in range(0, len(hexStr)-2, 2):
        bytes.append(chr(int(hexStr[i:i+2], 16)))
    return ''.join( bytes )
    
def decode(s, encodings=('ascii', 'utf8', 'latin1')):
    for encoding in encodings:
        try:
            return s.decode(encoding)
        except UnicodeDecodeError:
            pass
    return s.decode('ascii', 'ignore')

def getTags(tagParam):
    """
    Retrieve the tag names found within a tag
    """
    
    tagsFound = []
    for tag in tags.keys():
        if tagParam & tag != 0:
            tagsFound.append(tags[tag])
    return tagsFound

def interruptHandler(signum, frame):
    """ 
	Raise interrupt for the blocking call 'logcatInput = sys.stdin.readline()'
	
	"""
    raise KeyboardInterrupt	

try:
    fd = open( sys.argv[1], "rb" )
except:
    if len(sys.argv) > 1:
        print "File " + sys.argv[1] + " not found"
    else:
        print "Usage: ./droidbox.sh filename.apk <duration in seconds> (optional)"
    sys.exit(1)

duration = 0
if len(sys.argv) > 2 and len(sys.argv[2]) > 0:
    try:
        duration = int(sys.argv[2])
    except:
	    print "Usage: ./droidbox.sh filename.apk <duration in seconds> (optional)"
	    sys.exit(1)
	    
apkName = sys.argv[1]
raw = fd.read()
fd.close()
zip = zipfile.ZipFile( StringIO.StringIO( raw ) )
for i in zip.namelist() :
 if i == "AndroidManifest.xml" :
    try :
       xml[i] = minidom.parseString( zip.read( i ) )
    except:

       xml[i] = minidom.parseString( AXMLPrinter( zip.read( i ) ).getBuff() )

       for item in xml[i].getElementsByTagName('manifest'):
          packageNames.append( str( item.getAttribute("package") ) )
       for item in xml[i].getElementsByTagName('permission'):
          enfperm.append( str( item.getAttribute("android:name") ) )
       for item in xml[i].getElementsByTagName('uses-permission'):
          permissions.append( str( item.getAttribute("android:name") ) )
       for item in xml[i].getElementsByTagName('receiver'):
          recvs.append( str( item.getAttribute("android:name") ) )
          for child in item.getElementsByTagName('action'):
              recvsaction[str( item.getAttribute("android:name") )] = str( child.getAttribute("android:name") )
       for item in xml[i].getElementsByTagName('activity'):
          activities.append( str( item.getAttribute("android:name") ) )
          for child in item.getElementsByTagName('action'):
              activityaction[str( item.getAttribute("android:name") )] = (str( child.getAttribute("android:name") ))
        

             
curses.setupterm()
sys.stdout.write(curses.tigetstr("clear"))
sys.stdout.flush()
call(['adb', 'logcat', '-c'])

print " ____                        __  ____"               
print "/\  _`\               __    /\ \/\  _`\\"                  
print "\ \ \/\ \  _ __  ___ /\_\   \_\ \ \ \L\ \   ___   __  _"  
print " \ \ \ \ \/\`'__\ __`\/\ \  /'_` \ \  _ <' / __`\/\ \/'\\" 
print "  \ \ \_\ \ \ \/\ \L\ \ \ \/\ \L\ \ \ \L\ \\ \L\ \/>  </"
print "   \ \____/\ \_\ \____/\ \_\ \___,_\ \____/ \____//\_/\_\\"
print "    \/___/  \/_/\/___/  \/_/\/__,_ /\/___/ \/___/ \//\/_/"

count = CountingThread()
count.start()
actexec = ActivityThread()
actexec.start()
timeStamp = time.time()

activityrisk=riskDynBehaviour.activityRisk()


 
if duration:
    signal.signal(signal.SIGALRM, interruptHandler)
    signal.alarm(duration)
while 1:
    try:
        logcatInput = sys.stdin.readline()
        if not logcatInput:
            break
        boxlog = logcatInput.split('DroidBox:')
        if len(boxlog) > 1:
            try:
            	load = json.loads(decode(boxlog[1]))
            	# DexClassLoader
            	if load.has_key('DexClassLoader'):
            	    load['DexClassLoader']['type'] = 'dexload'
            	    dexclass[time.time() - timeStamp] = load['DexClassLoader']
                    count.increaseCount()
            	# service started
            	if load.has_key('ServiceStart'):
            	    load['ServiceStart']['type'] = 'service'
            	    servicestart[time.time() - timeStamp] = load['ServiceStart']
            	    count.increaseCount()
                # received data from net
                if load.has_key('RecvNet'):   
                    host = load['RecvNet']['srchost']
                    port = load['RecvNet']['srcport']
                    if load['RecvNet'].has_key('type') and load['RecvNet']['type'] == 'UDP':
                        recvdata = {'type': 'net read', 'host': host, 'port': port, 'data': load['RecvNet']['data']}
                        recvnet[time.time() - timeStamp] = recvdata
                        count.increaseCount()
                    else:
                        fd = load['RecvNet']['fd']
                        hostport = host + ":" + port + ":" + fd 
                        if netbuffer.has_key(hostport):
                            if len(netbuffer[hostport]) == 0:
                                netbuffer[hostport] = str(time.time()-timeStamp) + ":"
                            netbuffer[hostport] =  netbuffer[hostport] + load['RecvNet']['data']
                # fdaccess
                if load.has_key('FdAccess'):
                    accessedfiles[load['FdAccess']['id']] = load['FdAccess']['path']
                # file read or write     
                if load.has_key('FileRW'):
                    if accessedfiles.has_key(load['FileRW']['id']) and not "/dev/pts" in accessedfiles[load['FileRW']['id']]:
                        load['FileRW']['path'] = accessedfiles[load['FileRW']['id']]
                        if load['FileRW']['operation'] == 'write':
                            load['FileRW']['type'] = 'file write'
                        else:
                            load['FileRW']['type'] = 'file read'
                        fdaccess[time.time()-timeStamp] = load['FileRW']
                        count.increaseCount()
                # opened network connection log
                if load.has_key('OpenNet'):
                    if load['OpenNet'].has_key('type') and load['OpenNet']['type'] == 'UDP':
                        opennet[time.time()-timeStamp] = load['OpenNet']
                        ref = load['OpenNet']['desthost'] + load['OpenNet']['destport']
                        if ref not in udpConn:
                            udpConn.append(ref)
                    else:
                        load['OpenNet']['type'] = 'net open'                                                
                        opennet[time.time()-timeStamp] = load['OpenNet']
                        host = load['OpenNet']['desthost']
                        port = load['OpenNet']['destport']
                        fd = load['OpenNet']['fd']
                        netbuffer[host + ":" + port + ":" + fd] = ""
                    count.increaseCount()
                # closed socket
                if load.has_key('CloseNet'):
                    host = load['CloseNet']['desthost']
                    port = load['CloseNet']['destport']
                    ref = host + ":" + port
                    if ref not in udpConn:
                        fd = load['CloseNet']['fd']
                        try:
                            data = netbuffer[host + ":" + port + ":" + fd]
                        except KeyError:
                            continue
                        stamp = float(data.split(":")[0])
                        buffer = data.split(":")[1]
                        recvdata =  { 'type': 'net read', 'host': host, 'port': port, 'data': buffer}
                        recvnet[stamp] = recvdata
                        netbuffer[host + ":" + port + ":" + fd] = ""
                        count.increaseCount()
                    else:
                        ref.remove(ref)
                # outgoing network activity log
                if load.has_key('SendNet'):
                    if load['SendNet'].has_key('type') and load['SendNet']['type'] == 'UDP':
                        ref = load['SendNet']['desthost'] + load['SendNet']['destport']
                        if ref not in udpConn:
                            udpConn.append(ref)
                            opennet[time.time()-timeStamp] = load['SendNet']
                    load['SendNet']['type'] = 'net write'                                                               
                    sendnet[time.time()-timeStamp] = load['SendNet']
                    count.increaseCount()                                          
                # data leak log
                if load.has_key('DataLeak'):                   
                    if load['DataLeak']['sink'] == 'File':
                        if accessedfiles.has_key(load['DataLeak']['id']):
                            load['DataLeak']['path'] = accessedfiles[load['DataLeak']['id']]          
                    load['DataLeak']['type'] = 'leak'
                    dataleaks[time.time()-timeStamp] = load['DataLeak']
                    count.increaseCount()
                # sent sms log
                if load.has_key('SendSMS'):
                    load['SendSMS']['type'] = 'sms'
                    sendsms[time.time()-timeStamp] = load['SendSMS']
                    count.increaseCount()
                # phone call log
                if load.has_key('PhoneCall'):
                    load['PhoneCall']['type'] = 'call'
                    phonecalls[time.time()-timeStamp] = load['PhoneCall']
                    count.increaseCount()
                # crypto api usage log
                if load.has_key('CryptoUsage'):
                    load['CryptoUsage']['type'] = 'crypto'                                                                   
                    cryptousage[time.time()-timeStamp] = load['CryptoUsage']
                    count.increaseCount()
            except ValueError:
                pass

    except KeyboardInterrupt:  
        # Wait for counting thread to stop
        count.stopCounting()
        count.join()
        break

#because when I set the writting output into a file together, the key has an error, so I have to set the writing one by one
file_name= apkName + '.txt'
out_file = open(file_name, 'w',buffering=10000000)


print ''
space = ' ' * 5
space2 = ' ' * 8
space3 = ' ' * 11

hash = fileHash(apkName)
print "\n\n" + space + "\033[1;48m[Info]\033[1;m\n" + space + "------"
print "%s\033[1;36m%s\033[1;m\t%s" % (space2, "File name:", apkName)
print "%s\033[1;36m%s\033[1;m\t\t%s" % (space2, "MD5:", hash[0])
print "%s\033[1;36m%s\033[1;m\t\t%s" % (space2, "SHA1:", hash[1])
print "%s\033[1;36m%s\033[1;m\t\t%s" % (space2, "SHA256:", hash[2])
print "%s\033[1;36m%s\033[1;m\t%s" % (space2, "Duration:", str(time.time() - timeStamp) + "s") 


out_file.write(space + "[INFO]\n" + space + "-----------------------\n")
out_file.write("%s \t\t%s \t\t%s" % (space2, "File name: ", apkName)+"\n")
out_file.write("%s \t\t%s \t\t\t%s" % (space2, "MD5: ", hash[0])+"\n")
out_file.write("%s \t\t%s \t\t\t%s" % (space2, "SHA1: ", hash[1])+"\n")
out_file.write("%s \t\t%s \t\t%s" % (space2, "SHA256: ", hash[2])+"\n")
out_file.write("%s \t\t%s \t\t%s" % (space2, "Duration: ", str(time.time() - timeStamp) + "s\n\n\n\n\n"))


    

# Print file activity
keys = fdaccess.keys()
keys.sort()

print "\n\n" + space + "\033[1;48m[File activities]\033[1;m\n" + space + "-----------------\n"
print space2 + '\033[1;48m[Read operations]\033[1;m\n' + space2 + '-----------------'
out_file.write(space + "[File Activities]\n" + space + "--------------------\n")
out_file.write(space2 + "[Read Operations]\n" +space2 + "--------------------\n")
path = list()
for key in keys:
    temp = fdaccess[key]
    try:
        if temp['operation'] == 'read':
            #print "%s[\033[1;36m%s\033[1;m]\t\t Path: %s" % (space3, str(key), hexToStr(temp['path']))
            #print "%s\t\t\t\t Data: %s" % (space3, hexToStr(temp['data'])) + '\n'
            out_file.write("%s%s\t\t Path: %s" % (space3, str(key),hexToStr(temp['path'])) + "\n")

            if hexToStr( temp['path'] ).lower().endswith(('.txt','.xml','.tx','.xm')):
                out_file.write("%s\t\t\t\t Data: %s" % (space3, hexToStr(temp['data'])) + "\n\n")
            else :
                out_file.write("%s\t\t\t\t Data: %s" % (space3,temp['data'])+"\n\n")

            riskactivities['FILE_READ'].append( hexToStr(temp['path']))
            #out_file.write("%s\t\t\t\t Data: %s" % (space3,temp['data'])+"\n\n")
            if  hexToStr(temp['path']) not in FILE_NAME :
                FILE_NAME.append( hexToStr(temp['path']))
            
    except ValueError:
        pass
    except KeyError:
        pass
print ''

print space2 + '\033[1;48m[Write operations]\033[1;m\n' + space2 + '------------------'
out_file.write(space2 + "[Write Operations]\n" +space2 + "--------------------\n")
for key in keys:                                                       
    temp = fdaccess[key]
    try:
        if temp['operation'] == 'write':
           # sys.stdout.flush()
           # print "%s[\033[1;36m%s\033[1;m]\t\t Path: %s" % (space3, str(key), hexToStr(temp['path']))
           # print "%s\t\t\t\t Data: %s" % (space3, hexToStr(temp['data'])) + '\n'
            out_file.write("%s%s\t\t Path: %s" % (space3, str(key),hexToStr(temp['path'])) + "\n")

            riskactivities['FILE_WRITE'].append( hexToStr(temp['path']))
            
            if hexToStr( temp['path'] ).lower().endswith(('.txt','.xml','.tx','.xm')):
                out_file.write("%s\t\t\t\t Data: %s" % (space3, hexToStr(temp['data'])) + "\n\n")
               
            else :
 
                out_file.write("%s\t\t\t\t Data: %s" % (space3,temp['data'])+"\n\n")


            if  hexToStr(temp['path']) not in FILE_NAME :
                FILE_NAME.append( hexToStr(temp['path']))
            
    except ValueError:
        pass
    except KeyError:
        pass 



# Print crypto API usage
keys = cryptousage.keys()
keys.sort()

print "\n" + space + "\033[1;48m[Crypto API activities]\033[1;m\n" + space + "-----------------------"
out_file.write("\n" + space + "[Crypto API activities]\n" + space +"--------------------\n")

for key in keys:                                                               
    temp = cryptousage[key]
    try:
        riskactivities['CRYPTO_API'].append( str(key) )

        if temp['operation'] == 'keyalgo':
            print "%s[\033[1;36m%s\033[1;m]\t\t Key:{%s} Algorithm: %s" % (space3, str(key), temp['key'], temp['algorithm'])
            out_file.write("%s%s\t\t Key: {%s} Algorithm: %s" % (space3, str(key), temp['key'], temp['algorithm']) +"\n")
        else:
            print "%s[\033[1;36m%s\033[1;m]\t\t Operation:{%s} Algorithm: %s" % (space3, str(key), temp['operation'], temp['algorithm'])
            print "%s\t\t\t\t Data:{%s}" % (space3, temp['data']) + '\n'
            out_file.write("%s%s\t\t Operation:{%s} Algorithm: %s" % (space3, str(key), temp['operation'], temp['algorithm'])+"\n")
            out_file.write("%s\t\t\t\t Data:{%s}" % (space3, temp['data'])+"\n\n" )

    except ValueError:
        pass
    except KeyError:
        pass
if len(keys) == 0:
    print ''
    out_file.write(" \n")




# print network activity
print space + "\033[1;48m[Network activity]\033[1;m\n" + space + "------------------\n"
print space2 + "\033[1;48m[Opened connections]\033[1;m\n" + space2 + "--------------------"
out_file.write( space + "[Network activity]\n" + space + "--------------------\n")
out_file.write( space2 + "[Opened connections]\n" +space2 + "--------------------\n")
keys = opennet.keys()
keys.sort()
for key in keys:
    temp = opennet[key]
    try:
        print "%s[\033[1;36m%s\033[1;m]\t\t Destination: %s Port: %s" % (space3, str(key), temp['desthost'], temp['destport'])
        out_file.write("%s%s\t\t Destination: %s Port: %s" % (space3, str(key), temp['desthost'], temp['destport'])+"\n")
        riskactivities['OPEN_CONN'].append(temp['desthost'])

        if temp['desthost'] not in URL :
                URL.append( temp['desthost'] )

    except ValueError:
        pass
    except KeyError:
        pass


print "\n" + space2 + "\033[1;48m[Outgoing traffic]\033[1;m\n" + space2 + "------------------"
out_file.write("\n" + space2 + "[Outgoing traffic]\n"+space2+"--------------------\n\n")

keys = sendnet.keys()
keys.sort()
for key in keys:
    temp = sendnet[key]
    try:
        print "%s[\033[1;36m%s\033[1;m]\t\t Destination: %s Port: %s" % (space3, str(key), temp['desthost'], temp['destport'])
        print "%s\t\t\t\t Data: %s" % (space3, hexToStr(temp['data'])) + '\n'
        out_file.write("%s%s\t\t Destination: %s Port: %s" % (space3, str(key), temp['desthost'], temp['destport'])+"\n")	
        
        if temp['desthost'] == "localhost" and temp['destport'] == "123" :
            out_file.write("%s\t\t\t\t Data: %s" % (space3, temp['data']) +"\n\n")
        else :
            out_file.write("%s\t\t\t\t Data: %s" % (space3, hexToStr(temp['data'])) +"\n\n")
        
            
        if temp['desthost'] != "localhost" :
            riskactivities['OUTGOING_TRAF'].append(temp['desthost'])
        else :
            riskactivities['OPEN_CONN'].append(temp['desthost'])
         
        if temp['desthost'] not in URL :
                URL.append( temp['desthost'] )

    except ValueError:
        pass
    except KeyError:
        pass
if len(keys) == 0:
    print ''
    out_file.write(" \n")

print "\n" + space2 + "\033[1;48m[Incoming traffic]\033[1;m\n" + space2 + "------------------"
out_file.write("\n" + space2 + "[Incoming traffic]\n"+space2+"--------------------\n")
keys = recvnet.keys()
keys.sort()
for key in keys:
    temp = recvnet[key]
    try:
        print "%s[\033[1;36m%s\033[1;m]\t\t Source: %s Port: %s" % (space3, str(key), temp['host'], temp['port'])
        print "%s\t\t\t\t Data: %s" % (space3, hexToStr(temp['data']) + '\n')
        out_file.write("%s%s\t\t Source: %s Port: %s" % (space3, str(key), temp['host'], temp['port'])+"\n")	
	out_file.write("%s\t\t\t\t Data: %s" % (space3, hexToStr(temp['data'])) +"\n\n")

        if temp['host'] != "localhost" :
            riskactivities['INCOMING_TRAF'].append(temp['host'])
        else :
            riskactivities['OPEN_CONN'].append(temp['desthost'])
  
        if temp['host'] not in URL :
                URL.append( temp['host'] )
    except ValueError:
        pass
    except KeyError:
        pass
if len(keys) == 0:
    print ''
    out_file.write(" \n")



    
# print DexClass initializations
print space + "\033[1;48m[DexClassLoader]\033[1;m\n" + space + "-----------------"
out_file.write(space+"[DexClassLoader]\n" + space +"--------------------\n")
keys = dexclass.keys()
keys.sort()
for key in keys:
    temp = dexclass[key]
    try:
        print "%s\033[1;36m%s\033[1;m\t\t\t Path: %s\n" % (space3, str(key), temp['path'])
        out_file.write("%s%s\t\t\t Path: %s\n" % (space3, str(key), temp['path'])+"\n\n")
        riskactivities['DEX_CLASS_LOADER'].append(temp['path'])
    except ValueError:
        pass
    except KeyError:
        pass

# print registered broadcast receivers
print space + "\033[1;48m[Broadcast receivers]\033[1;m\n" + space + "---------------------"
out_file.write(space + "[Broadcast receivers]\n" + space+"--------------------\n")

for recv in recvsaction:
    print "%s\033[1;36m%s\033[1;m\t\t\t Action: %s\n" % (space3, recv, recvsaction[recv])
    out_file.write("%s%s\t\t\t Action: %s\n" % (space3, recv, recvsaction[recv]))
    riskactivities['BROADCAST_RECEIVER'].append( recv )
    
# list started services
print space + "\033[1;48m[Started services]\033[1;m\n" + space + "------------------"
out_file.write(space+"[Started services]\n" + space +"--------------------\n")
keys = servicestart.keys()
keys.sort()
for key in keys:
    temp = servicestart[key]
    print "%s\033[1;36m%s\033[1;m\t\t\t Class: %s\n" % (space3, str(key), temp['name'])
    if temp['name'] not in services :
        services.append(temp['name'])
        riskactivities['START_SERVICE'].append(temp['name'])
        out_file.write("%s%s\t\t\t Class: %s\n\n" % (space3, str(key), temp['name']))
    
    
# print enforced permissions
print space + "\033[1;48m[Enforced permissions]\033[1;m\n" + space + "----------------------"
out_file.write(space + "[Enforced permissions]\n" + space+"--------------------\n")
for perm in enfperm:
    print "%s\033[1;36m%s\033[1;m" % (space3, perm)
    out_file.write("%s%s\t\t\t\n" % (space3, perm))
    riskactivities['ENFORCED_PERMISSION'].append(perm)


# print bypassed permissions
print "\n" + space + "\033[1;48m[Permissions bypassed]\033[1;m\n" + space + "----------------------"
out_file.write("\n" + space +"[Permissions bypass]\n" +space +"--------------------\n")

if len(recvnet.keys()) > 0 or len(sendnet.keys()) > 0 or len(opennet.keys()) > 0:
    if 'android.permission.INTERNET' not in permissions:
        print "%s\033[1;36m%s\033[1;m" % (space3, 'android.permission.INTERNET')
        out_file.write("%s%s\n" % (space3, 'android.permission.INTERNET'))
if len(sendsms.keys()) > 0 and 'android.permission.SEND_SMS' not in permissions:
    print "%s\033[1;36m%s\033[1;m" % (space3, 'android.permission.SEND_SMS')
    out_file.write("%s%s\n" % (space3, 'android.permission.SEND_SMS'))
if len(phonecalls.keys()) > 0 and 'android.permission.CALL_PHONE' not in permissions:
    print "%s\033[1;36m%s\033[1;m" % (space3, 'android.permission.CALL_PHONE')
    out_file.write("%s%s\n" % (space3, 'android.permission.CALL_PHONE'))
if 'android.provider.Telephony.SMS_RECEIVED' in recvsaction and 'android.permission.RECEIVE_SMS' not in permissions:
    print "%s\033[1;36m%s\033[1;m" % (space3, 'android.permission.RECEIVE_SMS')
    out_file.write("%s%s\n" % (space3, 'android.permission.RECEIVE_SMS'))
    
contacts = False
phonestate = False
sms = False
book = False
for k in dataleaks.keys():	

    tagsInLeak = getTags(int(dataleaks[k]['tag'], 16))
    
    if 'TAINT_CONTACTS' in tagsInLeak or 'TAINT_CALL_LOG' in tagsInLeak:
        contacts = True
    if 'TAINT_IMEI' in tagsInLeak:
        phonestate = True
    if 'TAINT_IMSI' in tagsInLeak:
        phonestate = True
    if 'TAINT_PHONE_NUMBER' in tagsInLeak:
        phonestate = True
    if 'TAINT_SMS' in tagsInLeak:
        sms = True
    if 'TAINT_BROWSER' in tagsInLeak:
        book = True

if contacts and 'android.permission.READ_CONTACTS' not in permissions:
    print "%s\033[1;36m%s\033[1;m" % (space3, 'android.permission.READ_CONTACTS')
    out_file.write("%s%s\n" % (space3, 'android.permission.READ_CONTACTS'))
    riskactivities['BYPASSED_PERMISSION'].append('android.permission.READ_CONTACTS')
if phonestate and 'android.permission.READ_PHONE_STATE' not in permissions:
    print "%s\033[1;36m%s\033[1;m" % (space3, 'android.permission.READ_PHONE_STATE')
    out_file.write("%s%s\n" % (space3, 'android.permission.READ_PHONE_STATE'))
    riskactivities['BYPASSED_PERMISSION'].append('android.permission.READ_PHONE_STATE')
if sms and 'android.permission.READ_SMS' not in permissions:
    print "%s\033[1;36m%s\033[1;m" % (space3, 'android.permission.READ_SMS')
    out_file.write("%s%s\n" % (space3, 'android.permission.READ_SMS'))
    riskactivities['BYPASSED_PERMISSION'].append('android.permission.READ_SMS')
if book and 'com.android.browser.permission.READ_HISTORY_BOOKMARKS' not in permissions:
    print "%s\033[1;36m%s\033[1;m" % (space3, 'com.android.browser.permission.READ_HISTORY_BOOKMARKS')
    out_file.write("%s%s\n\n" % (space3, 'com.android.browser.permission.READ_HISTORY_BOOKMARKS'))
    riskactivities['BYPASSED_PERMISSION'].append('android.permission.READ_HISTORY_BOOKMARKS')
    

# Print data leaks
keys = dataleaks.keys()
keys.sort()
print "\n" + space + "\033[1;48m[Information leakage]\033[1;m\n" + space + "---------------------"
out_file.write("\n"+space+ "[Information leakage]\n"+space +"--------------------\n" )
for key in keys:
    temp = dataleaks[key]
    try:
        print "%s[\033[1;36m%s\033[1;m]\t\t Sink: %s" % (space3, str(key), temp['sink'])
        out_file.write("%s%s\t\t Sink: %s\n" % (space3, str(key), temp['sink']))
        if temp['sink'] == 'Network':
            print "%s\t\t\t\t Destination: %s" % (space3, temp['desthost'])
            print "%s\t\t\t\t Port: %s" % (space3, temp['destport'])
            print "%s\t\t\t\t Tag: %s" % (space3, ', '.join(getTags(int(temp['tag'], 16))))
            print "%s\t\t\t\t Data: %s" % (space3, hexToStr(temp['data']))

            out_file.write("%s\t\t\t\t Destination: %s\n" % (space3,temp['desthost']))
            out_file.write("%s\t\t\t\t Port: %s\n" % (space3,temp['destport']))
            out_file.write("%s\t\t\t\t Tag: %s\n" % (space3,', '.join(getTags(int(temp['tag'],16)))))
            out_file.write("%s\t\t\t\t Data: %s\n\n" % (space3,hexToStr(temp['data'])))
            
            if ', '.join(getTags(int(temp['tag'],16))) == 'TAINT_SMS':
                riskactivities['INFO_LEAKAGE_SMS'].append(temp['desthost'])
            else :
                riskactivities['INFO_LEAKAGE_OTHERS'].append(temp['desthost'])
            
            riskactivities['INTERNET_LEAKAGE'].append(temp['desthost'])
            if temp['desthost'] not in URL :
                URL.append( temp['desthost'] )

        if temp['sink'] == 'File':
            print "%s\t\t\t\t Path: %s" % (space3, hexToStr(temp['path']))
            print "%s\t\t\t\t Operation: %s" % (space3, temp['operation'])
            print "%s\t\t\t\t Tag: %s" % (space3, ', '.join(getTags(int(temp['tag'], 16))))
            print "%s\t\t\t\t Data: %s" % (space3, hexToStr(temp['data']))

            out_file.write("%s\t\t\t\t Path: %s\n" % (space3,hexToStr(temp['path'])))
            out_file.write("%s\t\t\t\t Operation: %s\n" % (space3,temp['operation']))
            out_file.write("%s\t\t\t\t Tag: %s\n" % (space3,', '.join(getTags(int(temp['tag'],16)))))
            out_file.write("%s\t\t\t\t Data: %s\n\n" % (space3,hexToStr(temp['data'])))
            
            if ', '.join(getTags(int(temp['tag'],16))) == 'TAINT_SMS':
                riskactivities['INFO_LEAKAGE_SMS'].append(hexToStr(temp['path']))
            else :
                riskactivities['INFO_LEAKAGE_OTHERS'].append(hexToStr(temp['path']))
            

            riskactivities['FILE_LEAKAGE'].append(temp['path'])
            if temp['path'] not in FILE_NAME :
                FILE_NAME.append( temp['path'] )

        if temp['sink'] == 'SMS':
            print "%s\t\t\t\t Number: %s" % (space3, temp['number'])
            print "%s\t\t\t\t Tag: %s" % (space3, ', '.join(getTags(int(temp['tag'], 16))))
            print "%s\t\t\t\t Data: %s" % (space3, temp['data'])

            out_file.write("%s\t\t\t\t Number: %s\n" % (space3,temp['number']))
            out_file.write("%s\t\t\t\t Tag: %s\n" % (space3,', '.join(getTags(int(temp['tag'],16)))))
            out_file.write("%s\t\t\t\t Data: %s\n\n" % (space3,temp['data']))

            riskactivities['SENT_SMS_LEAKAGE'].append(temp['number'])

            if ', '.join(getTags(int(temp['tag'],16))) == 'TAINT_SMS':
                riskactivities['INFO_LEAKAGE_SMS'].append(temp['number'])
            else:
                riskactivities['INFO_LEAKAGE_OTHERS'].append(temp['number'])
            
            if temp['number'] not in PHONE_NUMBER :
                PHONE_NUMBER.append( temp['number'] )
        print ''
        out_file.write(" ")
    except ValueError:
        pass
    except KeyError:
        pass
if len(keys) == 0:
    print ''
    out_file.write(" ")



# Print sent SMSs
keys = sendsms.keys()
keys.sort()
print space + "\033[1;48m[Sent SMS]\033[1;m\n" + space + "----------"
out_file.write("\n" + space + "[Sent SMS]\n" + space +"----------\n")
for key in keys:
    temp = sendsms[key]
    try:
        print "%s[\033[1;36m%s\033[1;m]\t\t Number: %s" % (space3, str(key), temp['number'])
        print "%s\t\t\t\t Message: %s" % (space3, temp['message'])
        out_file.write("%s%s\t\t Number: %s\n" % (space3, str(key), temp['number']))
        out_file.write("%s\t\t\t\t Message: %s\n\n" % (space3,temp['message']))
        riskactivities['SENT_SMS_NORMAL'].append(temp['number'])
        if temp['number'] not in PHONE_NUMBER :
                PHONE_NUMBER.append( temp['number'] )
    except ValueError:
        pass
    except KeyError:
        pass
        
# Print phone calls
keys = phonecalls.keys()
keys.sort()
print "\n" + space + "\033[1;48m[Phone calls]\033[1;m\n" + space + "-------------"
out_file.write("\n" + space + "[Phone calls]\n" + space +"-----------\n")
for key in keys:
    temp = phonecalls[key]
    try:
        print "%s[\033[1;36m%s\033[1;m]\t\t Number: %s" % (space3, str(key), temp['number'])
        out_file.write("%s%s\t\t Number: %s\n\n\n\n\n" % (space3, str(key), temp['number']))
        riskactivities['PHONE_CALLS'].append(temp['number'])
        if temp['number'] not in PHONE_NUMBER :
                PHONE_NUMBER.append( temp['number'] )
    except ValueError:
        pass
    except KeyError:
        pass
out_file.close()




#actuninstall = ActivityThreadUninstall()
#actuninstall.start()

print "The total score is %s " % ( activityrisk.CountingRisk(apkName, riskactivities, PHONE_NUMBER, URL, FILE_NAME))
#call(['time.sleep(5)'])
#call(['sys.stdout.flush()'])

sys.exit(0)
