#-*- coding: utf-8 -*-
#
# :author(s): SiNA Rabbani (sina redteam net)
# feel free to use, copy, modify without restrictions - NO WARRANTY
import commands
import os
from stem.descriptor import parse_file
from fabric.operations import local
import multiprocessing


total_guard_w = 0
total_exit_w = 0

guard_count = 0
exit_count = 0


def touch(fname):
    """touch function"""
    if os.path.exists(fname):
        os.utime(fname, None)
    else:
        open(fname, 'a').close()

def guard_worker(d):
    """Guard worker function"""
    # make sure relay is not whitelisted
    if desc.fingerprint in open('db/notbleeding.db', 'r').read():
    	print desc.fingerprint + "should be ok."
    else:
   	# pass ip:port to the perl heartbleed check
        result = ""
        result = commands.getoutput("./bin/check-ssl-heartbleed.pl " + str(desc.address) + ":" + str(desc.or_port))
       	if result.find("BAD!") != -1:
        	bw_percent = str(float(desc.bandwidth)/float(total_guard_w)*100)
                with open("db/bleedingguard.db", "a") as text_file2:
                	text_file2.write(str(desc.bandwidth) + " | "  + bw_percent  +" | <a href=\"https://atlas.torproject.org/#details/"+desc.fingerprint+"\">"+desc.fingerprint +"</a>\r\n")
        elif result.find("probably not vulnerable") != -1:
        	if result.find("received alert") != -1:
                	with open("db/notbleeding.db", "a") as text_file:
                        	text_file.write(desc.fingerprint+"\r\n")
        else:
        	print result


def exit_worker(d):
	""" Exit worker function """
        # make sure relay is not whitelisted
        if desc.fingerprint in open('db/bleedingexit.db', 'r').read():
        	print desc.fingerprint + "should be ok."
        else:
        	result = ""
                result = commands.getoutput("./bin/check-ssl-heartbleed.pl " + str(desc.address) + ":" + str(desc.or_port))
		if result.find("BAD!") != -1:
                	bw_percent = str(float(desc.bandwidth)/float(total_exit_w)*100)
                        with open("db/bleedingexit.db", "a") as text_file2:
               			text_file2.write(str(desc.bandwidth) + " | "  + bw_percent +" | <a href=\"https://atlas.torproject.org/#details/"+desc.fingerprint+"\">"+desc.fingerprint +"</a>\r\n")

		elif result.find("probably not vulnerable") != -1:
                	if result.find("received alert") != -1:
                        	with open("db/notbleeding.db", "a") as text_file:
                                	text_file.write(desc.fingerprint+"\r\n")
                else:
                	print result


# create cache files / verify their existence
touch('db/notbleeding.db')
touch('db/bleedingexit.db')
touch('db/bleedingguard.db')


# get guard and exit bandwidth weights
# verify /var/lib/tor/cached-consensus exists
if os.path.exists('/var/lib/tor/cached-consensus'):
	for desc in parse_file(open("/var/lib/tor/cached-consensus")):
		for d in desc.flags:
        		if d == "Guard":	
				total_guard_w = total_guard_w + desc.bandwidth
				guard_count = guard_count + 1;
			elif d =="Exit":
				total_exit_w = total_exit_w + desc.bandwidth
				exit_count = exit_count + 1

print "Total # of Guards: " + str(guard_count)
print "Total Bandwidth of Guards: " + str(total_guard_w)
print "Total # of Exits: " + str(exit_count)
print "Total Bandwidth of Exits: " + str(total_exit_w)

# loop thourgh guards and check the ones we have not marked as
# notbleeding by appending their fingerprint to notbleeding.db
for desc in parse_file(open("/var/lib/tor/cached-consensus")):
	for d in desc.flags:
		if d == "Guard":
			jobs = []
			p = multiprocessing.Process(target=guard_worker, args=(d,))
    			jobs.append(p)
    			p.start()

	for d in desc.flags:
                if d == "Exit":
                        jobs = []
                        p = multiprocessing.Process(target=exit_worker, args=(d,))
                        jobs.append(p)
                        p.start()
