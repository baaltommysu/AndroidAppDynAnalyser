from optparse import OptionParser
 
import sys, json, time, os
import zipfile, StringIO

from xml.dom import minidom

from subprocess import *
import subprocess

import apk, androconf
from utils import AXMLPrinter

xml = {}
timestamp = time.time()

option_0 = { 'name' : ('-i', '--input'), 'help' : 'file : use these filenames', 'nargs' : 1 }
option_1 = { 'name' : ('-d', '--directory'), 'help' : 'directory : use this directory', 'nargs' : 1 }
option_2 = { 'name' : ('-v', '--version'), 'help' : 'version of the API', 'action' : 'count' }

options = [option_0, option_1, option_2]

def main(options, arguments) :
    if options.input != None :					       
        if androconf.is_android( options.input ) == "APK" :	       
            try:
                fd = open( options.input, "rb" )
            except:
                if len(sys.argv) > 1:
                    print "File " + options.input + " not found"
                else:
                    print "Usage: Name ApkName"
                sys.exit(1)
            
            apkName = options.input
            raw = fd.read()
            fd.close()
            zip = zipfile.ZipFile( StringIO.StringIO( raw ) )
            for i in zip.namelist() :
                if i == "AndroidManifest.xml" :
                    try :
                        xml[i] = minidom.parseString( zip.read( i ) )
                    except:
                        xml[i] = minidom.parseString( AXMLPrinter( zip.read( i ) ).getBuff() )
                        target = None
 
                        if target == None:

                            for item in xml[i].getElementsByTagName('uses-sdk'):
                                if item.getAttribute("android:targetSdkVersion") is not "":
                                    target = str(item.getAttribute("android:targetSdkVersion"))
                                    print "The target sdk version of "+ apkName +" is " + str(item.getAttribute("android:targetSdkVersion"))
                                    break
                                else:
                                    target = 10
                                    print "Application "+ apkName +" specifies uses-sdk, but not target sdk version, uses android 10 as default"
                                    break
                        
                        if target is None:
                            target = 10
                            print "Application " + apkName +" doesn't specify uses-sdk, uses android 10 as default"
                         
                            
                            
                                    
            print target 
            if target == "7":
                print " I am using android 7 "
                myProcess = subprocess.Popen(['./create_avd7.sh'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                print "avd created!"
                time.sleep(2)
                myProcess = subprocess.Popen(['./startemu21.sh'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                print "emulator started!"
                time.sleep(120)
                print "Droidbox started!"
                myProcess = subprocess.Popen(['./droidbox23.sh', apkName],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                time.sleep(152)
                print "Droidbox ends!"
                myProcess = subprocess.Popen(['adb', 'emu', 'kill'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                time.sleep(2)
                myProcess.kill()   
            elif target == 7 :
                print " I am using android 7 "
                myProcess = subprocess.Popen(['./create_avd7.sh'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                time.sleep(2)
                print "avd created!"
                myProcess = subprocess.Popen(['./startemu21.sh'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                print "emulator started!"
                time.sleep(120)
                print "Droidbox started!"
                myProcess = subprocess.Popen(['./droidbox23.sh', apkName],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                time.sleep(152)
                print "Droidbox ends!"
                myProcess = subprocess.Popen(['adb', 'emu', 'kill'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                time.sleep(2)
                myProcess.kill()                 
            else:
                print " I am using android 10 "
                myProcess = subprocess.Popen(['./create_avd10.sh'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                time.sleep(2)
                print "avd created!"
                myProcess = subprocess.Popen(['./startemu23.sh'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                print "emulator started!"
                time.sleep(135)
                print "Droidbox started!"
                myProcess = subprocess.Popen(['./droidbox23.sh', apkName],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                time.sleep(152)
                print "Droidbox ends!"
                myProcess = subprocess.Popen(['adb', 'emu', 'kill'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                time.sleep(2)
                myProcess.kill() 
                
            









    elif options.directory != None :	
        
        for root, dirs, files in os.walk( options.directory, followlinks=True ) :
#            print files
#            print root
#            print dirs
#here need to add subdirectory
            if files != [] :
                for f in files :
                    real_filename = root
                    if real_filename[-1] != "/" :
                       real_filename += "/"
                    real_filename += f
                    
                    print real_filename
                    if androconf.is_android( real_filename ) == "APK"  :
                        try:
                            fd = open( real_filename, "rb" )
                        except:
                            if len(sys.argv) > 1:
                                print "File " + real_filename + " not found"
                            else:
                                print "Usage: Name ApkName"
                                sys.exit(1)
            
                        apkName = real_filename
                        raw = fd.read()
                        fd.close()
                        zip = zipfile.ZipFile( StringIO.StringIO( raw ) )
                        for i in zip.namelist() :
                            if i == "AndroidManifest.xml" :
                                try :
                                    xml[i] = minidom.parseString( zip.read( i ) )
                                except:
                                    xml[i] = minidom.parseString( AXMLPrinter( zip.read( i ) ).getBuff() )
                                    target = None
 
                                    if target is None:
                                        for item in xml[i].getElementsByTagName('uses-sdk'):
                                            if item.getAttribute("android:targetSdkVersion") is not "":
                                                target = str(item.getAttribute("android:targetSdkVersion"))
                                                print "The target sdk version of "+apkName+ " is " + target
                                                break
                                        
                                            else:
                                                target = 10
                                                print "Application "+ apkName +" specifies uses-sdk, but not target sdk version, uses android 2.3 as default"
                        
                                    if target is None:
                                        target = 10 
                                        print "Application " + apkName +" doesn't specify uses-sdk, uses android 2.3 as default"


                        print target 
                        if target == "7" :
                            print "I am using android 7"
                            myProcess = subprocess.Popen(['./create_avd7.sh'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                            time.sleep(2)
                            print "avd created!"
                            myProcess = subprocess.Popen(['./startemu21.sh'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                            print "emulator started!"
                            time.sleep(120)
                            print "Droidbox started!"
                            myProcess = subprocess.Popen(['./droidbox23.sh', apkName],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                            time.sleep(152)
                            print "Droidbox ends!"
                            myProcess = subprocess.Popen(['adb', 'emu', 'kill'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                            time.sleep(2)
                            myProcess.kill()

                        elif target == 7:
                            print "I am using android 7"
                            myProcess = subprocess.Popen(['./create_avd7.sh'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                            time.sleep(2)
                            print "avd created!"
                            myProcess = subprocess.Popen(['./startemu21.sh'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                            print "emulator started!"
                            time.sleep(120)
                            print "Droidbox started!"
                            myProcess = subprocess.Popen(['./droidbox23.sh', apkName],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                            time.sleep(152)
                            print "Droidbox ends!"
                            myProcess = subprocess.Popen(['adb', 'emu', 'kill'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                            time.sleep(2)
                            myProcess.kill()
                        else :
                            print "I am using android 10"
                            myProcess = subprocess.Popen(['./create_avd10.sh'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                            time.sleep(2)
                            print "avd created!"
                            myProcess = subprocess.Popen(['./startemu23.sh'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                            print "emulator started!"
                            time.sleep(140)
                            print "Droidbox started!"
                            myProcess = subprocess.Popen(['./droidbox23.sh', apkName],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                            time.sleep(152)
                            print "Droidbox ends!"
                            myProcess = subprocess.Popen(['adb', 'emu', 'kill'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                            time.sleep(2)
                            myProcess.kill()
            

            elif dirs != []:
                for di in dirs:
#                    print os.path.join(root,di)
                    for rootsub, diresub, filessub in os.walk(os.path.join(root,di)):
                        
#                        print rootsub
                        for f in filessub :
                            real_filename = rootsub
                            if real_filename[-1] != "/" :
                                real_filename += "/"
                            real_filename += f
                    
                            print real_filename
                            if androconf.is_android( real_filename ) == "APK"  :
                                try:
                                    fd = open( real_filename, "rb" )
                                except:
                                    if len(sys.argv) > 1:
                                        print "File " + real_filename + " not found"
                                    else:
                                        print "Usage: Name ApkName"
                                        sys.exit(1)
            
                                apkName = real_filename
                                raw = fd.read()
                                fd.close()
                                zip = zipfile.ZipFile( StringIO.StringIO( raw ) )
                                for i in zip.namelist() :
                                    if i == "AndroidManifest.xml" :
                                        try :
                                            xml[i] = minidom.parseString( zip.read( i ) )
                                        except:
                                            xml[i] = minidom.parseString( AXMLPrinter( zip.read( i ) ).getBuff() )
                                            target = None
 
                                            if target is None:
                                                for item in xml[i].getElementsByTagName('uses-sdk'):
                                                    if item.getAttribute("android:targetSdkVersion") is not "":
                                                        target = str(item.getAttribute("android:targetSdkVersion"))
                                                        print "The target sdk version of "+apkName+ " is " + target
                                                        break
                                                    else:
                                                        target = 10
                                                        print "Application "+ apkName +" specifies uses-sdk, but not target sdk version, uses android 2.3 as default"
                        
                                            if target is None:
                                                target = 10 
                                                print "Application " + apkName +" doesn't specify uses-sdk, uses android 10 as default"


                                print target 
                                if target == "7" :
                                    print "I am using android 7"
                                    myProcess = subprocess.Popen(['./create_avd7.sh'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                                    time.sleep(2)
                                    print "avd created!"
                                    myProcess = subprocess.Popen(['./startemu21.sh'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                                    print "emulator started!"
                                    time.sleep(120)
                                    print "Droidbox started!"
                                    myProcess = subprocess.Popen(['./droidbox23.sh', apkName],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                                    time.sleep(152)
                                    print "Droidbox ends!"
                                    myProcess = subprocess.Popen(['adb', 'emu', 'kill'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                                    time.sleep(2)
                                    myProcess.kill()

                                elif target == 7:
                                    print "I am using android 7"
                                    myProcess = subprocess.Popen(['./create_avd7.sh'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                                    time.sleep(2)
                                    print "avd created!"
                                    myProcess = subprocess.Popen(['./startemu21.sh'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                                    print "emulator started!"
                                    time.sleep(120)
                                    print "Droidbox started!"
                                    myProcess = subprocess.Popen(['./droidbox23.sh', apkName],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                                    time.sleep(152)
                                    print "Droidbox ends!"
                                    myProcess = subprocess.Popen(['adb', 'emu', 'kill'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                                    time.sleep(2)
                                    myProcess.kill()
                                else :
                                    print "I am using android 10"
                                    myProcess = subprocess.Popen(['./create_avd10.sh'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                                    time.sleep(2)
                                    print "avd created!"
                                    myProcess = subprocess.Popen(['./startemu23.sh'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                                    print "emulator started!"
                                    time.sleep(140)
                                    print "Droidbox started!"
                                    myProcess = subprocess.Popen(['./droidbox23.sh', apkName],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                                    time.sleep(152)
                                    print "Droidbox ends!"
                                    myProcess = subprocess.Popen(['adb', 'emu', 'kill'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                                    time.sleep(2)
                                    myProcess.kill()
                    dirs.remove(di)                    

            else:
                sys.exit(1)




                        
    elif options.version != None :
        print "Auto_dyn_analysis version 0.1! "

if __name__ == "__main__" :
    parser = OptionParser()
    for option in options :
        param = option['name']
        del option['name']
        parser.add_option(*param, **option)

    options, arguments = parser.parse_args()
    sys.argv[:] = arguments
    main(options, arguments)
