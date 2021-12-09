#! /usr/bin/env python
import time, signal, sys, subprocess, datetime, getpass, paramiko, os, re
import hashlib
import multiprocessing as mp
from optparse import OptionParser
from itertools import izip_longest
from scp import SCPClient

def signal_handler(sig, frame):
     print('Exiting gracefully Ctrl-C detected...')
     sys.exit()

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
        channel.send('term len 0\n')
        while not channel.recv_ready():
            time.sleep(1)

        channel.recv(65535)
    except paramiko.AuthenticationException as error:
        print ('Authentication Error on host: ' + host)
        return (None, None)

    return (channel, client)

def get_user_password():
    USER = raw_input("Username:")
    PASS = getpass.getpass(prompt='Enter User password: ')
    return USER, PASS

def execute_command(command, channel):
    channel.send(command)
    interval = 0.1
    maxseconds = 10
    maxcount = maxseconds / interval
    bufsize = 1024

    # Poll until completion or timeout
    # Note that we cannot directly use the stdout file descriptor
    # because it stalls at 64K bytes (65536).
    input_idx = 0
    timeout_flag = False
    start = datetime.datetime.now()
    start_secs = time.mktime(start.timetuple())
    output = ''
    channel.setblocking(0)
    while True:
        if channel.recv_ready():
            data = channel.recv(bufsize).decode('ascii')
            output += data

        if channel.exit_status_ready():
            break

        # Timeout check
        now = datetime.datetime.now()
        now_secs = time.mktime(now.timetuple())
        et_secs = now_secs - start_secs
        if et_secs > maxseconds:
            timeout_flag = True
            break

        rbuffer = output.rstrip(' ')
        if len(rbuffer) > 0 and (rbuffer[-1] == '#' or rbuffer[-1] == '>'):  ## got a Cisco command prompt
            break

        time.sleep(0.200)

    if channel.recv_ready():
        data = session.recv(bufsize)
        output += data.decode('ascii')

    return output

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
                    'show version']

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
        print('An error occurred: ', response.returncode)

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
    print('Pausing for 5 minutes for host ' + host + ' reload')
    time.sleep(300)
    for i in range(2):
        print('Checking device ' + host)
        out = run_os_command(host, 'ping ' + host + ' -c 1')
        if (' 0%') not in out[host]:
            print('Waiting for ' + host + ' to respond for 2 more minutes')
            time.sleep(120)
        else:
            isup = True
            break

    return isup

def upgrade(user, password, host, failed_hosts):
    channel, client = connection_establishment(user, password, host)
    if channel == None:
        failed_hosts.put({host: 'Connection'})
        return None

    execute_command('upgrade rom-monitor filename bootflash:asr920igp-15_6_43r_s_rommon.pkg all', channel)
    execute_command('conf t\n', channel)
    execute_command('boot system bootflash:asr920igp-universalk9_npe.17.03.03.SPA.bin\n', channel)
    execute_command('copy run start\n\n', channel)
    execute_command('reload\n\n', channel)
    connection_teardown(client)

    isup = wait_till_up(host)
    if isup == False:
        print(host + ' didn''t recover for over 9 minutes, aborting process')
        failed_hosts.put({host: 'notup'})
    else:
        channel, client = connection_establishment(user, password, host)
        out = execute_command('show version\n', channel)
        if '16.12.07' in out:
            print(host + ' host upgraded successfully')
            failed_hosts.put({host: 'success'})
        else:
            failed_hosts.put({host: 'version'})

def multi_upgrade(hosts_list, user, password):
    pool = []
    failed_hosts = []
    unrecovered_hosts = []
    connection_error = []
    failed_queue = mp.Queue()

    for host in hosts_list:
        pool.append(mp.Process(target=upgrade, args=(user, password, host, failed_queue)))

    for prc in pool:
        prc.start()

    for prc in pool:
        prc.join()

        item = failed_queue.get()
        for key in item:
            if item[key] == 'version':
                failed_hosts.append(key)
            elif item[key] == 'notup':
                unrecovered_hosts.append(key)
            elif item[key] == 'Connection':
                connection_error.append(key)

    return failed_hosts, unrecovered_hosts

def progress(filename, size, sent):
    sys.stdout.write("%s's upload progress: %.2f%%    \r" % (filename, float(sent) / float(size) * 100))

def open_scp_channel(host, user, password, failed):
     failed = []
     try:
          client = paramiko.SSHClient()
          client.load_system_host_keys()
          client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
          client.connect(host, 22, username=user, password=password)
     except paramiko.AuthenticationException as error:
          print ('Authentication Error on host ' + host + '\n' + error)
          return client, failed.append({host : 'Authentication'})

     return client, failed

def calculate_hash(filename):
   md5_hash = hashlib.md5()
   with open(filename, 'rb') as f:
      # Read and update hash in chunks of 4K
      for byte_block in iter(lambda: f.read(4096), b''):
         md5_hash.update(byte_block)

      return md5_hash.hexdigest()

def file_upload(host, user, password, failed):
    total_size = 0
    file_list = []
    failed_connection = []
    md5 = {}
    free_space = re.compile(r'\(.*?(\d+).*\)')
    md5_hash = re.compile(r'(?<=\=).*')

    sshchannel, sshclient = connection_establishment(user, password, host)

    if sshchannel == None:
        failed.put({host: 'Connection'})
        return None

    for filename in os.listdir('/tmp/asr920/images/'):
        file_list.append('/tmp/asr920/images/' + filename)
        total_size += os.path.getsize('/tmp/asr920/images/' + filename)
        md5[filename] = calculate_hash('/tmp/asr920/images/' + filename)

    out = execute_command('dir bootflash:/ | i bytes\n', sshchannel)
    m = free_space.search(out)

    if int(total_size) >= (m.group(1)):
        print ('Not enough space on host: ' + host)
        connection_teardown(sshclient)
        failed.put({host: 'Space'})
        return None

    for file in file_list:
        client, failed_connection = open_scp_channel(host, user, password, failed_connection)

        if len(failed_connection) == 0:
            sort_file = file.split('/')[-1]
            scp_client = SCPClient(client.get_transport(), progress=progress)
            scp_client.put(file, 'bootflash:/' + sort_file)
            scp_client.close

            out = execute_command('verify /md5 bootflash:/' + sort_file + '\n', sshchannel)
            m = md5_hash.search(out)

            if m.group(0).strip() != md5[sort_file]:
               print ('Wrong md5sum for ' + sort_file + ' on host: ' + host)
               failed.put({host: 'MD5'})

        else:
            failed.put({host: 'Connection'})
            scp_client.close

    connection_teardown(sshclient)

def multi_file_upload(hosts_list, user, password):
    pool = []
    auth_failed = []
    space_error = []
    md5_error = []
    failed = mp.Queue()

    #Create pool of processes to run
    for host in hosts_list:
        pool.append(mp.Process(target=file_upload, args=(host, user, password, failed)))

    #Spawn the processes
    for prc in pool:
        prc.start()

    #Join processes and get the results from the multiprocess queue
    for prc in pool:
        prc.join()

        item = failed.get()
        for key in item:
           if item[key] == 'Connection':
              auth_failed.append(key)
           elif item[key] == 'Space':
              space_error.append(key)
           else:
              md5_error.append(key)

    return auth_failed, space_error, md5_error

def main():
    unreachable = []
    reachable_hosts = []
    md5_error = []
    space_error = []
    upload_failed = []
    upgrade_failed = []
    unrecovered = []

    #create command line options menu
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
    parser.add_option('-u', '--upgrade', action='store_true', dest='upgrade',
                            help='Perform device/s upgrade IOS version')

    (options, args) = parser.parse_args()

    #layout the rules of usage
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
        user, password = get_user_password()
        if options.filename:
            try:
                with open(options.filename, 'r') as infile:
                    for lines in grouper(infile, mp.cpu_count()/4, ''):
                        reachable_hosts, unreachable = multi_ping(lines, unreachable)
                        upgrade_failed, unrecovered = multi_upgrade(reachable_hosts, user, password)
            except IOError as e:
                print(e)
        else:
            reachable_hosts, unreachable = multi_ping(lines, unreachable)
            upgrade_failed, unrecovered = multi_upgrade(reachable_hosts, user, password)
    if options.upload:
        user, password = get_user_password()
        if options.filename:
            try:
                with open(options.filename, 'r') as infile:
                    for lines in grouper(infile, 5, ''):
                        reachable_hosts, unreachable = multi_ping(lines, unreachable)
                        upload_failed, space_error, md5_error = multi_file_upload(reachable_hosts, user, password)
            except IOError as e:
                print(e)
        else:
            reachable_hosts, unreachable = multi_ping(options.device.split(), unreachable)
            upload_failed, space_error, md5_error = multi_file_upload(reachable_hosts, user, password)

    #print lists for hosts processed with error
    if len(unreachable)>0:
        print('The following hosts could not be reached: ' + str(unreachable))
    if len(upload_failed)>0:
        print('Authentication failed on: ' + str(upload_failed))
    if len(space_error)>0:
        print('Not enough space on: ' + str(space_error))
    if len(md5_error)>0:
        print('MD5 verification failed on: ' + str(md5_error))
    if len(upgrade_failed)>0:
        print('Devices not in the right code version:' + str(upgrade_failed))
    if len(unrecovered)>0:
        print('Host unreachable after upgrade:' + str(unrecovered))

if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)  #catch ctrl-c and call handler to terminate the script
    main()
