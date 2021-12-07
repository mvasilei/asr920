#! /usr/bin/env python
import time, signal, sys, subprocess, datetime, getpass, paramiko
import multiprocessing as mp
from optparse import OptionParser
from itertools import izip_longest

def signal_handler(sig, frame):
    print('Exiting gracefully Ctrl-C detected...')
    sys.exit(0)

def grouper(iterable, n, fillvalue=None):
   args = [iter(iterable)] * n
   return izip_longest(*args, fillvalue=fillvalue)

def connection_establishment(USER, PASS, host):
   try:
      print('Processing HOST: ' + host)
      client = paramiko.SSHClient()
      client.load_system_host_keys()
      client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
      client.connect(host, 22, username=USER, password=PASS)
      channel = client.invoke_shell()
      while not channel.recv_ready():
         time.sleep(1)

      channel.recv(65535)
      channel.send('term len 0\n')
   except paramiko.AuthenticationException as error:
      print ('Authentication Error')
      exit()

   return (channel, client)

def get_user_password():
   USER = raw_input("Username:")
   PASS = getpass.getpass(prompt='Enter User password: ')
   return USER, PASS


def execute_command(command, channel, wait):
   channel.send(command)
   while not channel.recv_ready():
      time.sleep(1)

   out = channel.recv(65535)
   return (out)

def connection_teardown(client):
   client.close()

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
   result_queue = mp.Queue()

   for host in hosts_list:
      pool.append(mp.Process(target=send_command, args=(host.strip('\n'), command, result_queue)))

   for prc in pool:
      prc.start()

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

def run_os_command(host, command, result_queue=None):
   response = subprocess.Popen([command], stdout=subprocess.PIPE, shell=True)

   if response.returncode == None:
      if result_queue != None:
         result_queue.put({host:response.communicate()[0]})
      else:
         return {host: response.communicate()[0]}
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

def wait_till_up(host):
   isup = False
   print('Pausing for 5 minutes for host ' + host + 'reload')
   time.sleep(300)
   for i in range(2):
      print('Checking device ' + host)
      out = run_os_command(host, 'ping ' + host + ' 2')
      if 'alive' not in out:
         print('Waiting for' + host + ' to respond for 2 more minutes')
      else:
         isup = True
         pass

   return isup

def upgrade(user, password, host):
   failed_hosts = []
   user, password = get_user_password()
   erros = ['Invalid','Incomplete','Ambiguous']
   channel, client = connection_establishment(user, password, host)
   out = execute_command('show run | i boot system', channel, 1)
   execute_command('upgrade rom-monitor filename bootflash:asr920igp-15_6_43r_s_rommon.pkg all', channel, 1)
   execute_command('conf t\n', channel, 1)
   execute_command('boot system bootflash:asr920igp-universalk9_npe.17.03.03.SPA.bin\n', channel, 1)
   execute_command('copy run start\n\n', channel, 3)
   execute_command('reload\n\n', channel, 1)
   connection_teardown(client)

   isup = wait_till_up(host)
   if isup == False:
      print(host + ' didn''t recover for over 9 minutes, aborting process')
      return failed_hosts.append(host)
      pass
   else:
      channel, client = connection_establishment(user, password, host)
      out = execute_command('show version | include [0-9][0-9]\\.+[0-9].+[a-z,A-Z]', channel, 1)
      if '17.03.03' in out:
         print(host + ' host upgraded successfully')

def multi_upgrade(user, password, hosts_list, file_list):
   pool = []
   failed = []
   #result_queue = mp.Queue()

   for host in hosts_list:
      pool.append(mp.Process(target=upgrade, args=(user, password, host)))

   for prc in pool:
      prc.start()

   for prc in pool:
      prc.join()

   return failed

def progress(filename, size, sent):
   sys.stdout.write("%s's upload progress: %.2f%%   \r" % (filename, float(sent) / float(size) * 100))

def file_upload(host, file):
   failed = []
   user, password = get_user_password()
   try:
      client = paramiko.SSHClient()
      client.load_system_host_keys()
      client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
      client.connect(host, 22, username=user, password=password)
   except paramiko.AuthenticationException as error:
      print ('Authentication Error on host ' + host + '\n' + error)
      return failed.append(host)

   scp_client = SCPClient(client.get_transport(),progress=progress)
   scp_client.put('venv/bin/python', 'bootflash:/python')
   scp_client.close
   return failed

def multi_file_upload(hosts_list):
   pool = []
   for host in hosts_list:
      pool.append(mp.Process(target=file_upload, args=(host)))

   for prc in pool:
      prc.start()

   for prc in pool:
      prc.join()

   #return failed

def main():
   unreachable = []
   upload_failed = []
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
         reachable_hosts, unreachable = multi_ping(options.device.split(), unreachable)
         run_checks(reachable_hosts, 'PRE')
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
         reachable_hosts, unreachable = multi_ping(options.device.split(), unreachable)
         run_checks(reachable_hosts, 'POST')
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
               for lines in grouper(infile, mp.cpu_count()/8, ''):
                  reachable_hosts, unreachable = multi_ping(lines, unreachable)
                  #upload_failed = file_upload(reachable_hosts)
         except IOError as e:
            print(e)
      else:
         reachable_hosts, unreachable = multi_ping(options.device.split(), unreachable)
         upload_failed = file_upload(reachable_hosts)

   if len(unreachable)>0:
      print('The following hosts could not be reached: ' + str(unreachable))
   if len(upload_failed)>0:
      print('File upload failed on: ' + str(upload_failed))


if __name__ == '__main__':
   signal.signal(signal.SIGINT, signal_handler)  # catch ctrl-c and call handler to terminate the script
   main()
