# EMILY'S COPY DEV VERSION
# 1/22/18
#
#
#version 16
#Written by Eric Kollmann xnih13@gmail.com
#Use at own risk
#
# This has been hacked together over time to make pretty pictures out of FW rules.  Not well documented at all, probably could be rewritten much better, but works for my needs.
#
# tested against ASA 9.2 output, may work with others
#
# version 13 updates  2016-09-27
# - added ability to auto determine inside/outside rules, no more having to manually add each one into the file!
# - added detection for log and debugging on rules, changes color of description to forest green for rules in this state 
# - added time-range reading in (and fixing rules that had it on it that were wrong before).  Does NOT show rules as disabled if time is past, still only flags rules as disabled if "inactive" set on them!
# - fixed when hostname section isn't in the 2nd "stanza", now do a find type feature looking for the section hostname is in and is at the first of the line.
# 
# verion 14 updates 2016-10-04
# - added ignore disabled rules to help clean up the drawing
# - fixed place where timerange did not get looked up on either inbound or outbound (don't recall now)
#
# version 15 updates 2016-12-20
# - fixed issue where udp ports were labeled as tcp
# - fixed issue where if the first record was not what was expected it would blow up
# - added some logic to print to screen if/when the inside or outside interface isn't detected
# - fixed pulling protocol in rules with 'eq' in them, in most cases (cases of ip, tcp, udp, but not cases where a protocol group has been created)
#
# version 16 updates 2017-04-10
# - changed default output to .gv instead of .dot
# - access-group is now processed as an array for when there is more than just inside/outside (or whatever names your team has created them as)
#
#
# Make sure you have graphviz installed:
# yum install graphviz
#



# add in dot as a library for ease of use?
import argparse, os, sys
parser = argparse.ArgumentParser(prog='parser.py', usage='%prog)s {-f input_file } [-o output_file]') 
parser.add_argument("-f", "--file", type=str, required=True, help="Parse a single asa fw file") 
parser.add_argument("-o", "--output", type=str, help="Filename, minus extension, of output files for .gv and .png files") 
parser.add_argument("-u", "--unused", help="Add the unused entries into the output as well", action='store_true')
parser.add_argument("-i", "--ignore", help="ignore disabled rules in drawn picture", action='store_true')
args = parser.parse_args() 

if not os.path.isfile(args.file):
  print '\nThere was an error opening file: %s' % args.file
  sys.exit() 
else:
  with open(args.file, 'r') as myfile:
    inFile=myfile.readlines() 

if args.output:
  outDotFile = open(args.output + '.gv', 'w') 
else:
  outDotFile = open(args.file + '.gv', 'w') 

nameRecords = []
routeGroupRecords = []
accessGroupRecords = []
timeRangeRecords = []
objectNetworkRecords = []
objectgroupNetworkRecords = []
objectgroupProtocolRecords = []
objectgroupServiceRecords = []
outside = []
inside = []


def lookupUnused():

  for s in nameRecords:
    if s[4] == 0:
     line = '"' + s[0] + '"' + s[1] + s[2] + s[3]
     outDotFile.write(line + '\n')

  for s in objectNetworkRecords:
    if s[4] == 0:
     line = '"' + s[0] + '"' + s[1] + s[2] + s[3]
     outDotFile.write(line + '\n')

  for s in objectgroupNetworkRecords:
    if s[4] == 0:
     line = '"' + s[0] + '"' + s[1] + s[2] + s[3]
     outDotFile.write(line + '\n')

  for s in objectgroupProtocolRecords:
    if s[4] == 0:
     line = '"' + s[0] + '"' + s[1] + s[2] + s[3]
     outDotFile.write(line + '\n')

  for s in objectgroupServiceRecords:
    if s[4] == 0:
     line = '"' + s[0] + '"' + s[1] + s[2] + s[3]
     outDotFile.write(line + '\n')




def lookupDraw(term):
  for s in nameRecords:
    if s[0] == term:
      line = '"' + s[0] + '"' + s[1] + s[2] + s[3]
      outDotFile.write(line + '\n')

  for s in objectNetworkRecords:
    if s[0] == term:
      line = '"' + s[0] + '"' + s[1] + s[2] + s[3]
      outDotFile.write(line + '\n')

  for s in objectgroupNetworkRecords:
    if s[0] == term:
      line = '"' + s[0] + '"' + s[1] + s[2] + s[3]
      outDotFile.write(line + '\n')

  for s in objectgroupProtocolRecords:
    if s[0] == term:
      line = '"' + s[0] + '"' + s[1] + s[2] + s[3]
      outDotFile.write(line + '\n')

  for s in objectgroupServiceRecords:
    if s[0] == term:
      line = '"' + s[0] + '"' + s[1] + s[2] + s[3]
      outDotFile.write(line + '\n')


# Keep this, works well
def findTimeRange(term):
  timeRange = ''
  for s in timeRangeRecords:
    #need to check for desc and other things here most likely
    name = s[0][11:]
    if name == term:
      timeRange = s[1][1:]
  return timeRange


# Keep this as well
def findPort(term):
  switched = False
  for s in objectgroupProtocolRecords:
    if s[0] == term:
      switched = True

  for s in objectgroupServiceRecords:
    if s[0] == term:
      switched = True

  return switched


# Keep this
def findHost(host):
  info = host
  for s in nameRecords:
    if s[0] == host:
      info = s[2]
      s[4] = 1

  for s in objectNetworkRecords:
    if s[0] == host:
      info = s[2]
      s[4] = 1

  for s in objectgroupNetworkRecords:
    if s[0] == host:
      info = s[2]
      s[4] = 1

  return info


# Keep this function, quick and dirty is what we want
def validIP(address):
  #there are better checks and ones that would do IPv6, but only interested in quick/dirty check for IPv4 for our env at this time
  try:
    parts = address.split(".")
    if len(parts) != 4:
      return False
    for item in parts:
      if not 0 <= int(item) <= 255:
        return False
    return True  
  except:
    return False
  

# runs through firewall rule file and returns neccessary information
# Seems like this could definitely be done more cleanly
def ruleProcess(search, line, count):
  proto = ''
  src = ''
  dst = ''
  inactive = ''
  debugging = ''
  log = ''
  port = ''
  port2 = ''
  deny = ''
  timeRange = ''

  temp = line[0][len(search):]
  temp = temp.split()

  try:
    i = temp.index('time-range')
    if i > 0:
      timeRange = temp[i+1]
      temp.pop(i+1)
      temp.pop(i)
  except:
    pass

  if temp[len(temp)-1] == 'inactive':
    inactive = 'true'
    temp.pop(len(temp)-1)

  if temp[len(temp)-1] == 'debugging':
    debugging = 'true'
    temp.pop(len(temp)-1)

  if temp[len(temp)-1] == 'log':
    log = 'true'
    temp.pop(len(temp)-1)

  if temp[0] == 'permit':
    deny = 'false'
    temp.pop(0)
  elif temp[0] == 'deny':
    deny = 'true'
    temp.pop(0)

  if temp[0] == 'tcp':  
    proto = 'tcp'
    temp.pop(0)
  elif temp[0] == 'udp':  
    proto = 'udp'
    temp.pop(0)
  elif temp[0] == 'ip':  
    proto = 'ip'
    temp.pop(0)
  elif temp[0] == 'icmp':  
    proto = 'icmp'
    temp.pop(0)
  elif temp[0] == 'icmp6':  
    proto = 'icmp6'
    temp.pop(0)

  if temp[0] == 'object':
    src = temp[1]
    temp.pop(1)
    temp.pop(0)
  elif temp[0] == 'host':
    src = temp[1]
    temp.pop(1)
    temp.pop(0)
  elif temp[0] == 'object-group':
    src = temp[1]
    temp.pop(1)
    temp.pop(0)
  elif temp[0] == 'any':
    src = temp[0]
    temp.pop(0)
  elif temp[0] == 'any4':
    src = temp[0]
    temp.pop(0)
  elif temp[0] == 'any6':
    src = temp[0]
    temp.pop(0)
  elif validIP(temp[0]):
    src = temp[0] + ' ' + temp[1]
    temp.pop(1)
    temp.pop(0)
  else:  
    src = temp[0]
    temp.pop(0)

  if temp[0] == 'object':
    dst = temp[1]
    temp.pop(1)
    temp.pop(0)
  elif temp[0] == 'host':
    dst = temp[1]
    temp.pop(1)
    temp.pop(0)
  elif temp[0] == 'object-group':
    dst = temp[1]
    temp.pop(1)
    temp.pop(0)
  elif temp[0] == 'any':
    dst = temp[0]
    temp.pop(0)
  elif temp[0] == 'any4':
    dst = temp[0]
    temp.pop(0)
  elif temp[0] == 'any6':
    dst = temp[0]
    temp.pop(0)
  elif validIP(temp[0]):
    dst = temp[0] + ' ' + temp[1]
    temp.pop(1)
    temp.pop(0)
  else:
    dst = temp[0]
    temp.pop(0)

  if proto == '':
    port = 'ip any'
  else:
    port = proto

  if len(temp) > 0:
    if temp[0] == 'object':
      port = temp[1]
      temp.pop(1)
      temp.pop(0)
    elif temp[0] == 'host':
      port = temp[1]
      temp.pop(1)
      temp.pop(0)
    elif temp[0] == 'object-group':
      port = temp[1]
      temp.pop(1)
      temp.pop(0)
    elif temp[0] == 'any':
      port = temp[0]
      temp.pop(0)
    elif temp[0] == 'any4':
      port = temp[0]
      temp.pop(0)
    elif temp[0] == 'any6':
      port = temp[0]
      temp.pop(0)
    elif temp[0] == 'eq':
      port = temp[1]
      if proto != '':
        port = proto + ' ' + port
      else:
        port = src + ' ' + port
      temp.pop(1)
      temp.pop(0)
    elif validIP(temp[0]):
      port = temp[0] + ' ' + temp[1]
      temp.pop(1)
      temp.pop(0)
    else:
      port = temp[0] 
      temp.pop(0)

  if len(temp) > 0:
    #overwrite existing port info
    if temp[0] == 'object':
      port2 = temp[1]
      temp.pop(1)
      temp.pop(0)
    elif temp[0] == 'host':
      port2 = temp[1]
      temp.pop(1)
      temp.pop(0)
    elif temp[0] == 'object-group':
      port2 = temp[1]
      temp.pop(1)
      temp.pop(0)
    elif temp[0] == 'any':
      port2 = temp[0]
      temp.pop(0)
    elif temp[0] == 'any4':
      port2 = temp[0]
      temp.pop(0)
    elif temp[0] == 'any6':
      port2 = temp[0]
      temp.pop(0)
    elif temp[0] == 'eq':
      port2 = temp[1]
      if proto != '':
        port2 = proto + ' ' + port2
      else:
        port2 = src + ' ' + port2
      print port2
      temp.pop(1)
      temp.pop(0)
    elif validIP(temp[0]):
      port2 = temp[0] + ' ' + temp[1]
      temp.pop(1)
      temp.pop(0)
    else:
      port = temp[0]
      temp.pop(0)

  if findPort(src):
    t = src
    src = dst
    dst = port
    if port2 <> '':
      port = port2
    else:
      port = t


  if findPort(dst):
    print line
    print 'src - ' + src
    print 'dst - ' + dst
    print 'port - ' + port

  return [src, port, dst, count, inactive, deny, debugging, log, timeRange]
  


records = [] 
record = [] 
end = 0 
for i in inFile:
  if i.find('!') == 0:
    end = 1
    records.append(record)
    record = []
  else:
    end = 0
  if end == 0:
    i = i.replace('\r', '')
    i = i.replace('\n', '')
    record.append(i) 

header = 'digraph G {\n graph [rankdir = "TB" overlap=false];\n ratio = auto;\n\n'

outDotFile.write(header) 

# Finds the desired hostname in the record I assume?
x = 0
found = 0
for i in records:
  if len(i) > 0:
    for j in i:
      if j.find('hostname') == 0:
        found = x
  x = x + 1

for i in records[found]:
  desc = ''
  if i.find('name ') == 0:
    s = i[5:].split()
    ip = s[0]
    host = s[1]
    x = len(s)
    if x > 2:
      for j in range (3, x):
        desc = desc + ' ' + s[j]
    line0 = '"' + host + '" [ style = filled shape = "Mrecord" label = <<table border="1" cellborder="0" cellpadding="3" bgcolor="white">'
    line1 = '<tr><td bgcolor="red" align="center" colspan="2"><font color="white">' + host + '</font></td></tr>'
    if desc <> '':
      line2 = '<tr><td bgcolor="gray" align="left" colspan="2"><font color="white">' + desc + '</font></td></tr>'
    else:
      line2 = ''
    line3 = '<tr><td bgcolor="white" align="left" colspan="2"><font color="black">' + ip + '</font></td></tr>'
    line4 = '</table>> ];'

    line = line0 + line1 + line2 + line3 + line4

    y = line.find(' [')
    header = line[y:]
    y = header.find('<<')
    leftover = header[y+1:]
    header = header[0:y+1]
    y = leftover.find('>>')
    info = leftover[0:y+1]
    footer = leftover[y+1:]
    record = [host, header, info, footer, 0]
    nameRecords.append(record)
    
x = 0
for i in records:
  if len(i) > 0:
    for j in i:
      if j.find('route') == 0:
        routeGroupRecords.append(j)
      if j.find('access-group') == 0:
        accessGroupRecords.append(j)
  x = x + 1

for i in routeGroupRecords:
  #determine which interface is the main one 
  parts = i.split(' ')
  outsideroute = parts[1]

ins = []
out = []
for i in accessGroupRecords:
  parts = i.split(' ')
  if parts[4] == outsideroute:
    out.append([parts[1], parts[4]])
  else:
    ins.append([parts[1], parts[4]])

if out == '':
  print 'Outside Interface not detected'
else:
  for i,j in out:
    outside.append([j, 'access-list ' + i + ' extended '])

if ins == '':
  print 'Inside Interface not detected'
else:
  for i,j in ins:
    inside.append([j, 'access-list ' + i + ' extended '])

x = 0
for i in records:
  if len(i) > 0:
    for j in i:
      if j.find('time-range') == 0:
        timeRangeRecords.append(records[x])
  x = x + 1

for i in timeRangeRecords:
  #need to check for desc and other things here most likely
  name = i[0][11:]
  timeRange = i[1][1:]

#determine which record has the info in it we need.
x = 0
found = 0
for i in records:
  if len(i) > 0:
    for j in i:
      if j.find('access-list') == 0:
        found = x
  x = x + 1


objectRecords = [] 
objectRecord = [] 
end = 0 
for i in records[found]:
  if i.find('object') == 0:
    if len(objectRecord) > 0:
      if objectRecord[0].find('object') == 0:
        objectRecords.append(objectRecord)
      objectRecord = []
    else:
      objectRecords.append(objectRecord)
  if (i.find(' ') == 0) or (i.find('object') == 0):
    objectRecord.append(i) 

#catch the last one
try:
  if objectRecord[0].find('object') == 0:
    objectRecords.append(objectRecord)
except:
  pass

for s in objectRecords:
  name = ''
  host = ''
  desc = ''
  x = len(s)
  line3 = ''
  desc = ''

  if s[0].find('object network ') == 0:
    name = s[0][15:]
    for j in range(1,x):
      if s[j].find(' host ') == 0:
        host = s[j][6:]
      elif s[j].find(' range ') == 0:
        host = s[j][7:]
      elif s[j].find(' subnet ') == 0:
        host = s[j][8:]
      elif s[j].find(' description ') == 0:
        desc = s[j][13:]
      elif s[j].find(' fqdn v4 ') == 0:
        host = s[j][9:]
      else:
        host = 'unknown1: ' + s[j]
    line0 = '"' + name + '" [ style = filled shape = "Mrecord" label = <<table border="1" cellborder="0" cellpadding="3" bgcolor="white">'
    line1 = '<tr><td bgcolor="black" align="center" colspan="2"><font color="white">' + name + '</font></td></tr>'
    if desc <> '':
      line2 = '<tr><td bgcolor="gray" align="left" colspan="2"><font color="white">' + desc + '</font></td></tr>'
    else:
      line2 = ''
    line3 = '<tr><td bgcolor="white" align="left" colspan="2"><font color="black">' + host + '</font></td></tr>'
    line4 = '</table>> ];'

    line = line0 + line1 + line2 + line3 + line4

    y = line.find(' [')
    header = line[y:]
    y = header.find('<<')
    leftover = header[y+1:]
    header = header[0:y+1]
    y = leftover.find('>>')
    info = leftover[0:y+1]
    footer = leftover[y+1:]
    record = [name, header, info, footer, 0]
    objectNetworkRecords.append(record)

#    outDotFile.write(line + '\n')

  elif s[0].find('object-group network ') == 0:
    name = s[0][21:]
    line0 = '"' + name + '" [ style = filled shape = "Mrecord" label = <<table border="1" cellborder="0" cellpadding="3" bgcolor="white">'
    line1 = '<tr><td bgcolor="blue" align="center" colspan="2"><font color="white">' + name + '</font></td></tr>'
    for j in range(1,x):
      if s[j].find(' network-object host ') == 0:
        host = s[j][21:]
        if validIP(host) == False:
          host = findHost(host)
        line3 = line3 + '<tr><td bgcolor="white" align="left" colspan="2"><font color="black">' + host + '</font></td></tr>'
      elif s[j].find(' network-object object ') == 0: # need to figure out how to point to existing object
        host = s[j][23:]
        if validIP(host) == False:
          host = findHost(host)
        line3 = line3 + '<tr><td bgcolor="white" align="left" colspan="2"><font color="black">' + host + '</font></td></tr>'
      elif s[j].find(' network-object ') == 0: 
        host = s[j][16:]
        temp = host.split(' ')
        if len(temp) == 1:
          host = temp[0] 
          host = findHost(host)
          line3 = line3 + '<tr><td bgcolor="white" align="left" colspan="2"><font color="black">' + host + '</font></td></tr>'
        if len(temp) == 2:
          host = temp[0] + ' ' + temp[1]
          line3 = line3 + '<tr><td bgcolor="white" align="left" colspan="2"><font color="black">' + host + '</font></td></tr>'
          
      elif s[j].find(' group-object ') == 0: #need to figure out how to point to existing object
        host = s[j][14:]
        if validIP(host) == False:
          host = findHost(host)
        line3 = line3 + '<tr><td bgcolor="white" align="left" colspan="2"><font color="black">' + host + '</font></td></tr>'
      elif s[j].find(' description ') == 0:
        desc = s[j][13:]
      else:
        host = 'unknown2: ' + s[j]   #ignoring this stuff as it picks up extra, may mean we drop some stuff out though!
    if desc <> '':
      line2 = '<tr><td bgcolor="gray" align="left" colspan="2"><font color="white">' + desc + '</font></td></tr>'
    else:
      line2 = ''
    line4 = '</table>> ];'

    line = line0 + line1 + line2 + line3 + line4

    y = line.find(' [')
    header = line[y:]
    y = header.find('<<')
    leftover = header[y+1:]
    header = header[0:y+1]
    y = leftover.find('>>')
    info = leftover[0:y+1]
    footer = leftover[y+1:]
    record = [name, header, info, footer, 0]
    objectgroupNetworkRecords.append(record)

  elif s[0].find('object-group protocol ') == 0:
    name = s[0][22:]
    line0 = '"' + name + '" [ style = filled shape = "Mrecord" label = <<table border="1" cellborder="0" cellpadding="3" bgcolor="white">'
    line1 = '<tr><td bgcolor="green" align="center" colspan="2"><font color="white">' + name + '</font></td></tr>'
    for j in range(1,x):
      if s[j].find(' protocol-object ') == 0:
        proto = s[j][17:]
        line3 = line3 + '<tr><td bgcolor="white" align="left" colspan="2"><font color="black">' + proto + '</font></td></tr>'
      elif s[j].find(' description ') == 0:
        desc = s[j][13:]
      else:
        host = 'unknown3: ' + s[j]
    if desc <> '':
      line2 = '<tr><td bgcolor="gray" align="left" colspan="2"><font color="white">' + desc + '</font></td></tr>'
    else:
      line2 = ''
    line4 = '</table>> ];'

    line = line0 + line1 + line2 + line3 + line4

    y = line.find(' [')
    header = line[y:]
    y = header.find('<<')
    leftover = header[y+1:]
    header = header[0:y+1]
    y = leftover.find('>>')
    info = leftover[0:y+1]
    footer = leftover[y+1:]
    record = [name, header, info, footer, 0]
    objectgroupProtocolRecords.append(record)

  elif s[0].find('object-group service ') == 0:
    temp = s[0][21:]
    temp = temp.split()
    name = temp[0]
    if len(temp) > 1:
      proto = temp[1]
    else:
      proto = ''
    line0 = '"' + name + '" [ style = filled shape = "Mrecord" label = <<table border="1" cellborder="0" cellpadding="3" bgcolor="white">'
    line1 = '<tr><td bgcolor="purple" align="center" colspan="2"><font color="white">' + name + '</font></td></tr>'
    for j in range(1,x):
      if s[j].find(' port-object eq ') == 0:
        port = s[j][16:]
        if proto <> '':
          line3 = line3 + '<tr><td bgcolor="white" align="left" colspan="2"><font color="black">' + proto + ' - ' + port + '</font></td></tr>'
        else:
          line3 = line3 + '<tr><td bgcolor="white" align="left" colspan="2"><font color="black">' + port + '</font></td></tr>'
      elif s[j].find(' port-object range ') == 0:
        port = s[j][19:]
        if proto <> '':
          line3 = line3 + '<tr><td bgcolor="white" align="left" colspan="2"><font color="black">' + proto + ' - ' + port + '</font></td></tr>'
        else:
          line3 = line3 + '<tr><td bgcolor="white" align="left" colspan="2"><font color="black">' + port + '</font></td></tr>'
      elif s[j].find(' service-object tcp ') == 0:
        temp = s[j][20:]
        if temp.find(' eq ') <> -1:
          x = temp.find(' eq ')
          port = temp[x + 4:]
        elif temp.find(' range ') <> -1:
          x = temp.find(' range ')
          port = temp[x + 7:]
        else:
          port = temp
        line3 = line3 + '<tr><td bgcolor="white" align="left" colspan="2"><font color="black">tcp ' + port + '</font></td></tr>'
      elif s[j].find(' service-object udp ') == 0:
        temp = s[j][20:]
        if temp.find(' eq ') <> -1:
          x = temp.find(' eq ')
          port = temp[x + 4:]
        elif temp.find(' range ') <> -1:
          x = temp.find(' range ')
          port = temp[x + 7:]
        else:
          port = temp
        line3 = line3 + '<tr><td bgcolor="white" align="left" colspan="2"><font color="black">udp ' + port + '</font></td></tr>'
      elif s[j].find(' service-object tcp-udp ') == 0:
        temp = s[j][24:]
        if temp.find(' eq ') <> -1:
          x = temp.find(' eq ')
          port = temp[x + 4:]
        elif temp.find(' range ') <> -1:
          x = temp.find(' range ')
          port = temp[x + 7:]
        else:
          port = temp
        line3 = line3 + '<tr><td bgcolor="white" align="left" colspan="2"><font color="black">tcp-udp ' + port + '</font></td></tr>'
      elif s[j].find(' service-object icmp6') == 0:
        line3 = line3 + '<tr><td bgcolor="white" align="left" colspan="2"><font color="black">icmp6</font></td></tr>'
      elif s[j].find(' service-object icmp') == 0:
        line3 = line3 + '<tr><td bgcolor="white" align="left" colspan="2"><font color="black">icmp</font></td></tr>'
      elif s[j].find(' service-object ip6') == 0:
        line3 = line3 + '<tr><td bgcolor="white" align="left" colspan="2"><font color="black">ip6</font></td></tr>'
      elif s[j].find(' service-object ip') == 0:
        line3 = line3 + '<tr><td bgcolor="white" align="left" colspan="2"><font color="black">ip</font></td></tr>'
      elif s[j].find(' group-object ') == 0:
        port = s[j][14:]
        if proto <> '':
          line3 = line3 + '<tr><td bgcolor="white" align="left" colspan="2"><font color="black">' + proto + ' - ' + port + '</font></td></tr>'
        else:
          line3 = line3 + '<tr><td bgcolor="white" align="left" colspan="2"><font color="black">' + port + '</font></td></tr>'
      elif s[j].find(' description ') == 0:
        desc = s[j][13:]
      else:
        host = 'unknown4: ' + s[j][1:]  #ignoring this stuff as it picks up extra, may mean we drop some stuff out though!
#        line3 = line3 + '<tr><td bgcolor="white" align="left" colspan="2"><font color="black">' + host + '</font></td></tr>'

    if desc <> '':
      line2 = '<tr><td bgcolor="gray" align="left" colspan="2"><font color="white">' + desc + '</font></td></tr>'
    else:
      line2 = ''

    line4 = '</table>> ];'

    line = line0 + line1 + line2 + line3 + line4

    y = line.find(' [')
    header = line[y:]
    y = header.find('<<')
    leftover = header[y+1:]
    header = header[0:y+1]
    y = leftover.find('>>')
    info = leftover[0:y+1]
    footer = leftover[y+1:]
    record = [name, header, info, footer, 0]
    objectgroupServiceRecords.append(record)

#    outDotFile.write(line + '\n')

  elif s[0].find('object service ') == 0:
    temp = s[0][15:]
    temp = temp.split()
    name = temp[0]
    if len(temp) > 1:
      proto = temp[1]
    else:
      proto = ''
    line0 = '"' + name + '" [ style = filled shape = "Mrecord" label = <<table border="1" cellborder="0" cellpadding="3" bgcolor="white">'
    line1 = '<tr><td bgcolor="purple" align="center" colspan="2"><font color="white">' + name + '</font></td></tr>'
    for j in range(1,x):
      if s[j].find(' service eq ') == 0:
        port = s[j][12:]
        if proto <> '':
          line3 = line3 + '<tr><td bgcolor="white" align="left" colspan="2"><font color="black">' + proto + ' - ' + port + '</font></td></tr>'
        else:
          line3 = line3 + '<tr><td bgcolor="white" align="left" colspan="2"><font color="black">' + port + '</font></td></tr>'
      elif s[j].find(' service range ') == 0:
        port = s[j][15:]
        if proto <> '':
          line3 = line3 + '<tr><td bgcolor="white" align="left" colspan="2"><font color="black">' + proto + ' - ' + port + '</font></td></tr>'
        else:
          line3 = line3 + '<tr><td bgcolor="white" align="left" colspan="2"><font color="black">' + port + '</font></td></tr>'
      elif s[j].find(' service tcp ') == 0:
        temp = s[j][13:]
        if temp.find(' eq ') <> -1:
          x = temp.find(' eq ')
          port = temp[x + 4:]
        elif temp.find(' range ') <> -1:
          x = temp.find(' range ')
          port = temp[x + 7:]
        else:
          port = temp
        line3 = line3 + '<tr><td bgcolor="white" align="left" colspan="2"><font color="black">tcp ' + port + '</font></td></tr>'
      elif s[j].find(' service udp ') == 0:
        temp = s[j][13:]
        if temp.find(' eq ') <> -1:
          x = temp.find(' eq ')
          port = temp[x + 4:]
        elif temp.find(' range ') <> -1:
          x = temp.find(' range ')
          port = temp[x + 7:]
        else:
          port = temp
        line3 = line3 + '<tr><td bgcolor="white" align="left" colspan="2"><font color="black">udp ' + port + '</font></td></tr>'
      elif s[j].find(' service tcp-udp ') == 0:
        temp = s[j][17:]
        if temp.find(' eq ') <> -1:
          x = temp.find(' eq ')
          port = temp[x + 4:]
        elif temp.find(' range ') <> -1:
          x = temp.find(' range ')
          port = temp[x + 7:]
        else:
          port = temp
        line3 = line3 + '<tr><td bgcolor="white" align="left" colspan="2"><font color="black">tcp-udp ' + port + '</font></td></tr>'
      elif s[j].find(' service icmp6') == 0:
        line3 = line3 + '<tr><td bgcolor="white" align="left" colspan="2"><font color="black">icmp6</font></td></tr>'
      elif s[j].find(' service icmp') == 0:
        line3 = line3 + '<tr><td bgcolor="white" align="left" colspan="2"><font color="black">icmp</font></td></tr>'
      elif s[j].find(' service ip6') == 0:
        line3 = line3 + '<tr><td bgcolor="white" align="left" colspan="2"><font color="black">ip6</font></td></tr>'
      elif s[j].find(' service ip') == 0:
        line3 = line3 + '<tr><td bgcolor="white" align="left" colspan="2"><font color="black">ip</font></td></tr>'
      elif s[j].find(' group-object ') == 0:
        port = s[j][14:]
        if proto <> '':
          line3 = line3 + '<tr><td bgcolor="white" align="left" colspan="2"><font color="black">' + proto + ' - ' + port + '</font></td></tr>'
        else:
          line3 = line3 + '<tr><td bgcolor="white" align="left" colspan="2"><font color="black">' + port + '</font></td></tr>'
      elif s[j].find(' description ') == 0:
        desc = s[j][13:]
      else:
        host = 'unknown5: ' + s[j][1:]  #ignoring this stuff as it picks up extra, may mean we drop some stuff out though!
#        line3 = line3 + '<tr><td bgcolor="white" align="left" colspan="2"><font color="black">' + host + '</font></td></tr>'

    if desc <> '':
      line2 = '<tr><td bgcolor="gray" align="left" colspan="2"><font color="white">' + desc + '</font></td></tr>'
    else:
      line2 = ''

    line4 = '</table>> ];'

    line = line0 + line1 + line2 + line3 + line4

    y = line.find(' [')
    header = line[y:]
    y = header.find('<<')
    leftover = header[y+1:]
    header = header[0:y+1]
    y = leftover.find('>>')
    info = leftover[0:y+1]
    footer = leftover[y+1:]
    record = [name, header, info, footer, 0]
    objectgroupServiceRecords.append(record)

#    outDotFile.write(line + '\n')

fwRuleRecords = [] 
end = 0 
for i in records[found]:
  if i.find('access-list') == 0:
    fwRuleRecords.append([i])

fwRules = []
for i,j in inside:
  rules = []
  for s in fwRuleRecords:
    if s[0].find(j) != -1:
      rules.append(s)
  fwRules.append([i, j, rules])

for name,command,rules in fwRules:
  #Outbound
  counter = 0
  for s in rules:
    if s[0].find(command) != -1:
      counter = counter + 1
      info = ruleProcess(command, s, counter)
      if info[0] <> '':

        src = info[0]
        port = info[1]
        dst = info[2]
        outbound = info[3]
        inactive = info[4]
        deny = info[5]
        debugging = info[6]
        log = info[7]
        timeRange = info[8]

        timeRange = findTimeRange(timeRange)

        desc = ''
        if log == 'true':
          desc = ' log,'
        if debugging == 'true':
          desc = ' debugging,'  #if it is in debugging it is in logging
        if timeRange != '':
          desc = desc + timeRange + ','
        if desc != '':
          desc = desc[:-1]

        if inactive == 'true':
          line = '"' + src + '" -> "' + port + '" -> "' + dst + '" [ penwidth = 1 fontsize = 14 fontcolor = "red" label ="Disabled ' + str(name) + '-' + str(outbound) + desc + '" style=dashed color=red];'
        elif deny == 'true':
          line = '"' + src + '" -> "' + port + '" -> "' + dst + '" [ penwidth = 1 fontsize = 14 fontcolor = "purple" label ="Deny ' + str(name) + '-' + str(outbound) + desc + '" color=purple];'
        elif ((log == 'true') | (debugging == 'true')):
          line = '"' + src + '" -> "' + port + '" -> "' + dst + '" [ penwidth = 1 fontsize = 14 fontcolor = "forestgreen" label ="' + str(name) + '-' + str(outbound) + desc + '" color=orange];'
        else:
          line = '"' + src + '" -> "' + port + '" -> "' + dst + '" [ penwidth = 1 fontsize = 14 fontcolor = "black" label ="' + str(name) + '-' + str(outbound) + desc + '" color=orange];'

        writeOut='true'
        if inactive == 'true' and args.ignore == True:
          writeOut='false'
        if writeOut == 'true':
          outDotFile.write(line + '\n')
          lookupDraw(src)
          lookupDraw(port)
          lookupDraw(dst)




fwRules = []
for i,j in outside:
  rules = []
  for s in fwRuleRecords:
    if s[0].find(j) != -1:
      rules.append(s)
  fwRules.append([i, j, rules])

for name,command,rules in fwRules:
  #inbound
  counter = 0
  for s in rules:
    if s[0].find(command) != -1:
      counter = counter + 1
      info = ruleProcess(command, s, counter)
      if info[0] <> '':

        src = info[0]
        port = info[1]
        dst = info[2]
        inbound = info[3]
        inactive = info[4]
        deny = info[5]
        debugging = info[6]
        log = info[7]
        timeRange = info[8]

        timeRange = findTimeRange(timeRange)

        desc = ''
        if log == 'true':
          desc = ' log,'
        if debugging == 'true':
          desc = ' debugging,'  #if it is in debugging it is in logging
        if timeRange != '':
          desc = desc + ' ' + timeRange + ','
        if desc != '':
          desc = desc[:-1]

        if inactive == 'true':
          line = '"' + src + '" -> "' + port + '" -> "' + dst + '" [ penwidth = 1 fontsize = 14 fontcolor = "red" label ="Disabled ' + str(name) + '-' + str(inbound) + desc + '" style=dashed color=red];'
        elif deny == 'true':
          line = '"' + src + '" -> "' + port + '" -> "' + dst + '" [ penwidth = 1 fontsize = 14 fontcolor = "purple" label ="Deny ' + str(name) + '-' + str(inbound) + desc + '" color=purple];'
        elif ((log == 'true') | (debugging == 'true')):
          line = '"' + src + '" -> "' + port + '" -> "' + dst + '" [ penwidth = 1 fontsize = 14 fontcolor = "forestgreen" label ="' + str(name) + '-' + str(inbound) + desc + '" ];'
        else:
          line = '"' + src + '" -> "' + port + '" -> "' + dst + '" [ penwidth = 1 fontsize = 14 fontcolor = "black" label ="' + str(name) + '-' + str(inbound) + desc + '" ];'

        writeOut='true'
        if inactive == 'true' and args.ignore == True:
          writeOut='false'
        if writeOut == 'true':
          outDotFile.write(line + '\n')
          lookupDraw(src)
          lookupDraw(port)
          lookupDraw(dst)



if args.unused == True:
  outDotFile.write('\n\n\n#Unused Stuff that can probably be removed\n\n')
  lookupUnused()

footer = '}'
outDotFile.write(footer)
