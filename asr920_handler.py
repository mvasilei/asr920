#! /usr/bin/env python
import time, signal, sys, subprocess, datetime
import multiprocessing as mp
from optparse import OptionParser
from itertools import izip_longest

def signal_handler(sig, frame):
    print('Exiting gracefully Ctrl-C detected...')
    sys.exit(0)

def grouper(iterable, n, fillvalue=None):
   args = [iter(iterable)] * n
   return izip_longest(*args, fillvalue=fillvalue)

def send_command(host, command, result_queue):
   response = subprocess.Popen(['runcmd ' + host + ' "' + command +'"'],
                               stdout=subprocess.PIPE,
                               shell=True)

   if response.returncode == None:
      result_queue.put({host: {command: response.communicate()[0]}})
   else:
      print ('An error occurred', response.returncode)

def multi_send_command(hosts_list, command, timestamp, check_type):
   pool = []
   count = 0
   result_queue = mp.Queue()

   for host in hosts_list:
      pool.append(mp.Process(target=send_command, args=(host.strip('\n'), command, result_queue)))

   for prc in pool:
      prc.start()
      count += 1

   for prc in pool:
      prc.join()

   for prc in pool:
      dict = result_queue.get()
      for key in dict:
         with open(check_type + '_' + key + '_' + timestamp + '.txt', 'a+') as outfile:
            outfile.write(str(dict[key])+'\n')

def run_checks(host_list, check_type):
   commands = ['show platform',
               'show version | include [0-9][0-9]\.+[0-9].+[a-z,A-Z]']

   now = datetime.datetime.now()
   timestamp = str(now.strftime('%Y')) + str(now.strftime('%m')) + str(now.strftime('%d')) + str(now.strftime('%H'))\
               + str(now.strftime('%M')) + str(now.strftime('%S'))
   for cmd in commands:
      multi_send_command(host_list, cmd, timestamp, check_type)

def run_os_command(host, command, result_queue):
   response = subprocess.Popen([command], stdout=subprocess.PIPE, shell=True)

   if response.returncode == None:
      result_queue.put({host:response.communicate()[0]})
   else:
      print('An error occurred', response.returncode)

def multi_ping(hosts_list, unreachable):
   pool = []
   reachable_hosts = []
   count = 0
   result_queue = mp.Queue()

   for host in hosts_list:
      if host == '':
         continue
      else:
         pool.append(mp.Process(target=run_os_command, args=(host.strip('\n'),
                                                             'ping ' + host.strip('\n') + ' 2',
                                                              result_queue)))

   for prc in pool:
      print('Testing reachability for host ' + hosts_list[count])
      prc.start()
      count += 1

   for prc in pool:
      prc.join()

   for prc in pool:
      item = result_queue.get()
      for key in item:
         if 'alive' in item[key]:
            reachable_hosts.append(key)
         else:
            unreachable.append(key)
            print(key + ' is unreachable and won''t be processed further')

   return reachable_hosts, unreachable

def file_upload(hosts_list):
   pool = []
   count = 0
   result_queue = mp.Queue()

   for host in hosts_list:
      command = 'sshpass -p \'yourpassword\' ssh -o StrictHostKeyChecking=no yourusername@' + host
      pool.append(mp.Process(target=run_os_command, args=(host.strip('\n'), command, result_queue)))

   for prc in pool:
      print ('Starting file transfer on host ' + hosts_list[count])
      prc.start()
      count += 1

   for prc in pool:
      prc.join()

   for prc in pool:
      dict = result_queue.get()
      for key in dict:
         print dict[key]



def main():
   unreachable = []
   usage = 'usage: %prog [options] arg'
   parser = OptionParser(usage)
   parser.add_option('-c', '--prechecks', action='store_true', dest='prechecks',
                     help='Run prechecks on device/s')
   parser.add_option('-d', '--device', dest='device',
                     help='Specify device name')
   parser.add_option('-f', '--file', dest='filename',
                     help='Read data from FILENAME')
   parser.add_option('-l', '--upload', action='store_true', dest='upload',
                     help='Upload image files on device/s')
   parser.add_option('-p', '--postchecks', action='store_true', dest='postchecks',
                     help='Run postchecks on device/s')
   parser.add_option('-r','--rollback', dest='rollback',
                     help='Rollback device/s to previous IOS version provide absolute path to image file')
   parser.add_option('-u', '--upgrade', dest='upgrade',
                     help='Perform device/s upgrade IOS version')

   (options, args) = parser.parse_args()

   if options.filename and options.device:
      parser.error('Options device and filename are mutually exclusive')
   if (options.filename or options.device) and not (options.prechecks or options.postchecks or options.upload \
                                                    or options.upgrade or options.rollback):
      parser.error('Options filename/device should be given with any of prechecks, postchecks, upload,\
                    upgrade, rollback')
   if options.prechecks and (options.postchecks or options.upload):
      parser.error('Options prechecks, postchecks, upload are mutually exclusive')
   if (options.upgrade or options.rollback) and (options.prechecks or options.postchecks or options.upload):
      parser.error('Options upgrade/downgrade and prechecks/postchecks/upload are mutually exclusive')

   if options.prechecks:
      if options.filename:
         try:
            with open(options.filename, 'r') as infile:
               for lines in grouper(infile, mp.cpu_count()/4, ''):
                  reachable_hosts, unreachable = multi_ping(lines, unreachable)
                  run_checks(reachable_hosts, 'PRE')
         except IOError as e:
            print(e)
      else:
         pass
   if options.postchecks:
      if options.filename:
         try:
            with open(options.filename, 'r') as infile:
               for lines in grouper(infile, mp.cpu_count()/4, ''):
                  reachable_hosts, unreachable = multi_ping(lines, unreachable)
                  run_checks(reachable_hosts, 'POST')
         except IOError as e:
            print(e)
      else:
         pass
   if options.upgrade:
      if options.filename:
         try:
            with open(options.filename, 'r') as infile:
               for lines in grouper(infile, mp.cpu_count()/4, ''):
                  reachable_hosts, unreachable = multi_ping(lines, unreachable)

         except IOError as e:
            print(e)
      else:
         pass
   if options.upload:
      if options.filename:
         try:
            with open(options.filename, 'r') as infile:
               for lines in grouper(infile, mp.cpu_count()/4, ''):
                  reachable_hosts, unreachable = multi_ping(lines, unreachable)
                  file_upload(reachable_hosts)
         except IOError as e:
            print(e)
      else:
         pass

   print('The following hosts could not be reached: ' + str(unreachable))

if __name__ == '__main__':
   signal.signal(signal.SIGINT, signal_handler)  # catch ctrl-c and call handler to terminate the script
   main()
