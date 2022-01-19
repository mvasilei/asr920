#! /usr/bin/env python2.7
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
        channel.send('enable\n')
        channel.send(PASS + '\n')
        channel.send('term len 0\n')
        while not channel.recv_ready():
           time.sleep(0.5)

        output = channel.recv(8192)
    except paramiko.AuthenticationException as error:
        print ('Authentication Error on host: ' + host)
        return (None, None)

    return (channel, client)

def get_user_password():
    sys.stdin = open('/dev/tty')
    USER = raw_input("Username:")
    PASS = getpass.getpass(prompt='Enter user password: ')
    return USER, PASS

def execute_command(command, channel):
    cbuffer = []
    data = ''

    channel.send(command)
    while True:
        if channel.recv_ready():
            data = channel.recv(1000)
            cbuffer.append(data)

        time.sleep(0.5)
        data_no_trails = data.strip()

        if len(data_no_trails) > 0: #and
            if (data_no_trails[-1] == '#'):
                break

    if channel.recv_ready():
        data = channel.recv(1000)
        cbuffer.append(data)

    rbuffer = ''.join(cbuffer)
    return rbuffer

def connection_teardown(client):
    client.close()

def multi_send_command(hosts_list, check_type, user, password):
    pool = []
    connection_error = []
    result_queue = mp.Queue()

    for host in hosts_list:
        pool.append(
                mp.Process(target=run_checks, args=(host.strip('\n'), check_type, user, password, result_queue)))

    for prc in pool:
        prc.start()

    for prc in pool:
        dict = result_queue.get()
        for key in dict:
            if dict[key] != 'Connection':
                with open(check_type + '_' + key + '.txt', 'a+') as outfile:
                    outfile.write(str(dict[key]))
            else:
               connection_error.append(key)
        prc.join()
    return connection_error

def run_checks(host, check_type, user, password,result_queue):
    output = ''
    commands = ['show platform\n',
                'show version\n',
                'show redundancy\n',
                'show interfaces\n',
                'show cef interface brief\n',
                'show isis nei detail\n',
                'show mpls interfaces\n',
                'show ip bgp all summary\n',
                'show ntp status\n',
                'show ntp associations\n',
                'show platform ptp all\n',
                'show ptp port dataset port\n',
                'show ptp clock dataset parent\n',
                'show esmc detail\n',
                'show ptp clock running\n',
                'show network-clocks synchronization\n',
                'show ip int brief | exc admin\n',
                'show ip bgp vpnv4 all summary\n',
                'show ethernet service instance\n',
                'show xconnect all\n',
                'show run\n',
                'show log\n']

    channel, client = connection_establishment(user, password, host)
    if channel != None:
        for cmd in commands:
            output += execute_command(cmd, channel)

        result_queue.put({host: output})
        connection_teardown(client)
    else:
        result_queue.put({host: 'Connection'})

def run_os_command(host, command, result_queue=None):
    response = subprocess.Popen([command], stdout=subprocess.PIPE, shell=True)

    if response.returncode == None:
        if result_queue != None:
            result_queue.put({host:response.communicate()[0]})
        else:
            return {host: response.communicate()[0]}
    else:
        print('An error occurred: ', response.returncode)

def multi_ping(hosts_list):
    pool = []
    unreachable = []
    reachable_hosts = []
    count = 0
    result_queue = mp.Queue()
    processed_hosts = []

    for host in hosts_list:
        if host == '':
            continue
        elif '_920_' not in host:
            print(host + ' not a valid host...skipping')
        else:
            pool.append(mp.Process(target=run_os_command, args=(host.strip('\n'),
                                                                'ping ' + host.strip('\n') + ' 2',
                                                                result_queue)))
            processed_hosts.append(host)

    for prc in pool:
        print('Testing reachability for host ' + processed_hosts[count])
        prc.start()
        count += 1

    for prc in pool:
        prc.join()
        item = result_queue.get()
        for key in item:
            if 'alive' in item[key]:  #change this from ' 0%' to 'alive' when  move to bastion
                reachable_hosts.append(key)
            else:
                unreachable.append(key)
                print(key + ' is unreachable and won''t be processed further')
    return reachable_hosts, unreachable

def wait_till_up(host):
    isup = False
    print('Device will go down in 1 minute, then pausing for 25 minutes for ' + host + ' to reload')
    time.sleep(1500)
    for i in range(2):
        print('Checking device ' + host)
        out = run_os_command(host, 'ping ' + host + ' 2')
        if ('alive') not in out[host]:  #change this from ' 0%' to 'alive' when  move to bastion
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
    run_output = execute_command('sho run | i boot system bootflash\n', channel)
    if 'Error' in execute_command('dir bootflash:asr920igp-15_6_43r_s_rommon.pkg\n', channel):
        print ('Image files are missing on ' + host)
        failed_hosts.put({host: 'FileMissing'})
        return None
    if 'Error' in execute_command('dir asr920igp-universalk9_npe.17.03.03.SPA.bin\n', channel):
        print ('Image files are missing on ' + host)
        failed_hosts.put({host: 'FileMissing'})
        return None

    print ('Upgrading ROMMON... please wait')
    execute_command('upgrade rom-monitor filename bootflash:asr920igp-15_6_43r_s_rommon.pkg all\n', channel)
    execute_command('conf t\n', channel)
    for boot in re.findall(r'boot system bootflash:.*', run_output):
        execute_command('no ' + boot + '\n', channel)
    execute_command('boot system bootflash:asr920igp-universalk9_npe.17.03.03.SPA.bin\n', channel)
    execute_command('end\n', channel)
    execute_command('copy run start\n\n', channel)
    execute_command('reload in 1 reason Software upgrade\n\n', channel)
    connection_teardown(client)

    isup = wait_till_up(host)
    if isup == False:
        print(host + ' didn''t recover for over 25 minutes, aborting process')
        failed_hosts.put({host: 'notup'})
    else:
        user, password = get_user_password() #remove
        channel, client = connection_establishment(user, password, host)
        out = execute_command('show version\n', channel)
        if '17.03.03' in out:
            print(host + ' host upgraded successfully')
            failed_hosts.put({host: 'success'})
            print('Configuring ' + host + ' post upgrade')
            execute_command('conf t\n', channel)
            execute_command('snmp-server view q iso included\n', channel)
            execute_command('snmp-server view q ciscoCefMIB excluded\n', channel)
            execute_command('snmp-server view IVView iso included\n', channel)
            execute_command('snmp-server view IVView ciscoCefMIB excluded\n', channel)
            execute_command('snmp-server view IVUserView iso included\n', channel)
            execute_command('snmp-server view IVUserView ciscoCefMIB excluded\n', channel)
            execute_command('snmp-server view SMARTSView iso included\n', channel)
            execute_command('snmp-server view SMARTSView ciscoCefMIB excluded\n', channel)
            execute_command('snmp-server view ScriptView iso included\n', channel)
            execute_command('snmp-server view ScriptView ciscoCefMIB excluded\n', channel)
            execute_command('no logging host 212.137.2.50 discriminator FAN+TEMP\n', channel)
            execute_command('no logging host 212.137.2.20 discriminator FAN+TEMP\n', channel)
            execute_command('no logging host 195.27.67.93 discriminator FAN+TEMP\n', channel)
            execute_command('no logging host 194.221.227.93 discriminator FAN+TEMP\n', channel)
            execute_command(
                'logging discriminator FAN+TEMP msg-body drops (Speed: [0-6]|Board.Temperature: [1-4]|compliance violation)\n',
                channel)
            execute_command('logging host 212.137.2.50 discriminator FAN+TEMP\n', channel)
            execute_command('logging host 212.137.2.20 discriminator FAN+TEMP\n', channel)
            execute_command('logging host 195.27.67.93 discriminator FAN+TEMP\n', channel)
            execute_command('logging host 194.221.227.93 discriminator FAN+TEMP\n', channel)
            execute_command('end\n', channel)
            execute_command('copy run start\n\n', channel)
        else:
            failed_hosts.put({host: 'version'})

def multi_upgrade(hosts_list, user, password):
    pool = []
    failed_hosts = []
    unrecovered_hosts = []
    connection_error = []
    file_missing = []
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
            elif item[key] == 'FileMissing':
                file_missing.append(key)

    return failed_hosts, unrecovered_hosts, connection_error, file_missing

def progress(filename, size, sent):
    sys.stdout.write("%s's upload progress: %.2f%%    \r" % (filename, float(sent) / float(size) * 100))
    sys.stdout.flush()

def open_scp_channel(host, user, password):
     failed = []
     try:
          user, password = get_user_password() #remove
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

    if not os.path.exists('/tmp/asr920/images/'):
        print ('Image directory doesn''t exist')
        failed.put({host: 'NoDir'})
        return None
    elif not os.listdir('/tmp/asr920/images/'):
        print ('Image directory is empty')
        failed.put({host: 'EmptyDir'})
        return None

    user, password = get_user_password() #remove
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

    connection_teardown(sshclient)

    for file in file_list:
         user, password = get_user_password()
         client, fc = open_scp_channel(host, user, password)

         failed_connection.extend(fc)
         if len(failed_connection) == 0:
              sort_file = file.split('/')[-1]
              scp_client = SCPClient(client.get_transport(), progress=progress)
              scp_client.put(file, 'bootflash:/' + sort_file)
              scp_client.close

              user, password = get_user_password() #remove
              sshchannel, sshclient = connection_establishment(user, password, host)
              out = execute_command('verify /md5 bootflash:/' + sort_file + '\n', sshchannel)
              connection_teardown(sshclient)

              m = md5_hash.search(out)
              if m.group(0).strip() != md5[sort_file]:
                   print ('Wrong md5sum for ' + sort_file + ' on host: ' + host)
                   failed.put({host: 'MD5'})
              else:
                   failed.put({host: 'Success'})
         else:
              failed.put({host: 'Connection'})
              scp_client.close

def multi_file_upload(hosts_list, user, password):
    pool = []
    auth_failed = []
    space_error = []
    md5_error = []
    mpQueue = mp.Queue()

    #Create pool of processes to run
    for host in hosts_list:
        pool.append(mp.Process(target=file_upload, args=(host, user, password, mpQueue)))

    #Spawn the processes
    for prc in pool:
        prc.start()

    for prc in pool:
        prc.join()
        item = mpQueue.get()
        for key in item:
           if item[key] == 'Connection':
              auth_failed.append(key)
           elif item[key] == 'Space':
              space_error.append(key)
           elif item[key] == 'MD5':
              md5_error.append(key)

    return auth_failed, space_error, md5_error

def rollback(user, password, host, failed_hosts):
    channel, client = connection_establishment(user, password, host)
    if channel == None:
        failed_hosts.put({host: 'Connection'})
        return None
    if 'Error' in execute_command('dir asr920igp-universalk9.V169_1A_ES04.SPA.bin\n', channel):
        print ('Image files are missing on ' + host)
        failed_hosts.put({host: 'FileMissing'})
        return None

    execute_command('conf t\n', channel)
    execute_command('no boot system bootflash:asr920igp-universalk9_npe.17.03.03.SPA.bin\n', channel)
    execute_command('boot system bootflash:asr920igp-universalk9.V169_1A_ES04.SPA.bin\n', channel)
    execute_command('end\n\n', channel)
    execute_command('copy run start\n\n', channel)
    execute_command('reload in 1 reason Software downgrade\n\n', channel)
    execute_command('show reload\n', channel)
    connection_teardown(client)

    isup = wait_till_up(host)
    if isup == False:
        print(host + ' didn''t recover for over 25 minutes, aborting process')
        failed_hosts.put({host: 'notup'})
    else:
        user, password = get_user_password() #remove
        channel, client = connection_establishment(user, password, host)
        out = execute_command('show version\n', channel)
        if 'V169_1A_ES04' in out:
            print(host + ' host rollbacked successfully')
            failed_hosts.put({host: 'success'})
        else:
            failed_hosts.put({host: 'version'})

def multi_rollback(hosts_list, user, password):
    pool = []
    failed_hosts = []
    unrecovered_hosts = []
    connection_error = []
    file_missing = []
    failed_queue = mp.Queue()

    for host in hosts_list:
        pool.append(mp.Process(target=rollback, args=(user, password, host, failed_queue)))

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
            elif item[key] == 'FileMissing':
                file_missing.append(key)

    return failed_hosts, unrecovered_hosts, connection_error, file_missing

def reboot_sequence(filename):
    print('Calculating reload sequence... this might take a while, depending on the number of devices you upgrade')
    print('This process consults csginfo which might raise error messages... you can ignore')
    try:
        with open(filename, 'r') as infile, open('temp.txt', 'w') as outfile:
            for line in infile:
                response = subprocess.Popen('csginfo ' + line.strip('\n') + ' | grep -i vodams.*_920_.*',
                                            stdout=subprocess.PIPE, shell=True)

                if response.returncode == None:
                    csginfo = response.communicate()[0]
                    if csginfo != '':
                        m = re.findall('vodams_\d+_920_\d+', csginfo.lower())
                        current_record = list(sorted(set(result for result in m)))
                        outfile.write(str(current_record) + '\n')

        #Remove duplicate entries
        with open('temp.txt', 'r') as infile, open('swap_asr920.txt', 'w') as outfile:
            uniq = set(infile.readlines())
            outfile.writelines(set(uniq))

        #Workaround csginfo not returning cluster information for some subtended csgs
        with open('tmp_asr920.txt', 'w') as outfile, open('swap_asr920.txt', 'r') as infile:
            data = infile.readlines()
            clean_data = str(data).replace('[', '').replace("'", '').replace(']', '').strip('\\n')
            infile.seek(0)
            for line in infile:
                if len(line.split(',')) == 1:
                    count = clean_data.count(line.replace('[', '').replace("'", '').replace(']', '').strip('\n').strip())
                    if count == 1:
                        outfile.write(line)
                else:
                    outfile.write(line)

        os.remove('temp.txt')
        os.remove('swap_asr920.txt')
    except IOError as e:
        print(e)

def reboot_proceed(user, password, unreachable, upgrade_failed, unrecovered,connection_error, file_missing, operation):
    host_list = []
    with open('tmp.txt', 'r') as infile:
        for lines in infile:
            host_list.extend(lines.replace('[', '').replace("'", '').replace(']', '').strip('\n').split(','))
            if len(host_list) >= 3:
                reachable_hosts, unreachable_hosts = multi_ping(host_list)
                unreachable.extend(unreachable_hosts)
                if len(reachable_hosts) > 0:
                    if operation == 'rollback':
                        ufailed, urevocered, cerror, fmissing = multi_rollback(reachable_hosts, user, password)
                        upgrade_failed.extend(ufailed)
                        unrecovered.extend(urevocered)
                        connection_error.extend(cerror)
                        file_missing.extend(fmissing)
                    else:
                        ufailed, urevocered, cerror, fmissing = multi_upgrade(reachable_hosts, user, password)
                        upgrade_failed.extend(ufailed)
                        unrecovered.extend(urevocered)
                        connection_error.extend(cerror)
                        file_missing.extend(fmissing)
                host_list = []
            else:
                continue
        else:
            if len(host_list) != 0:
                reachable_hosts, unreachable_hosts = multi_ping(host_list)
                unreachable.extend(unreachable_hosts)
                if len(reachable_hosts) > 0:
                    if operation == 'rollback':
                        ufailed, urevocered, cerror, fmissing = multi_rollback(reachable_hosts, user, password)
                        upgrade_failed.extend(ufailed)
                        unrecovered.extend(urevocered)
                        connection_error.extend(cerror)
                        file_missing.extend(fmissing)
                    else:
                        ufailed, urevocered, cerror, fmissing = multi_upgrade(reachable_hosts, user, password)
                        upgrade_failed.extend(ufailed)
                        unrecovered.extend(urevocered)
                        connection_error.extend(cerror)
                        file_missing.extend(fmissing)
            host_list = []
    return unreachable, upgrade_failed, unrecovered,connection_error, file_missing

def main():
    unreachable = []
    reachable_hosts = []
    md5_error = []
    space_error = []
    upload_failed = []
    upgrade_failed = []
    unrecovered = []
    connection_error = []
    file_missing = []

    #create command line options menu
    usage = 'usage: %prog options [arg]'
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
    parser.add_option('-r','--rollback', action='store_true', dest='rollback',
                            help='Rollback device/s to previous IOS version provide absolute path to image file')
    parser.add_option('-u', '--upgrade', action='store_true', dest='upgrade',
                            help='Perform device/s upgrade IOS version')
    parser.add_option('-n', '--number', action='store_true', dest='number',
                            help='Number of devices to be upgraded in parallel')

    (options, args) = parser.parse_args()

    if not len(sys.argv) > 1:
        parser.print_help()
        exit()

    #set out the rules of usage
    if options.filename and options.device:
        parser.error('Option device and filename are mutually exclusive')
    if options.prechecks and (options.postchecks or options.upload or options.rollback or options.upgrade):
        parser.error('Options prechecks and postchecks/upload/upgrade/rollback are mutually exclusive')
    if (options.upgrade or options.rollback) and (options.prechecks or options.postchecks or options.upload):
        parser.error('Options upgrade/downgrade and prechecks/postchecks/upload are mutually exclusive')
    if options.upgrade and options.rollback:
        parser.error('Option upgrade and rollback are mutually exclusive')
    if ((options.prechecks or options.postchecks or options.upload or options.upgrade or options.rollback)
            and not (options.filename or options.device)):
        parser.error('Option filename/device should be given with any of prechecks/postchecks/upload/upgrade/rollback')
    if (options.filename or options.device) and not (options.prechecks or options.postchecks or options.upload
                                                                     or options.upgrade or options.rollback):
        parser.error('Option filename/device should be given with any of prechecks/postchecks/upload/upgrade/rollback')

    user, password = get_user_password()

    if options.prechecks:
        if options.filename:
            try:
                with open(options.filename, 'r') as infile:
                    for lines in grouper(infile, mp.cpu_count()/4, ''):
                        reachable_hosts, unreachable_hosts = multi_ping(lines)
                        unreachable.extend(unreachable_hosts)
                        if len(reachable_hosts) > 0:
                            connection_error.extend(multi_send_command(reachable_hosts, 'PRE', user, password))
            except IOError as e:
                print(e)
        else:
            reachable_hosts, unreachable_hosts = multi_ping(options.device.split())
            if len(reachable_hosts) > 0:
                connection_error.extend(multi_send_command(reachable_hosts, 'PRE', user, password))
    if options.postchecks:
        if options.filename:
            try:
                with open(options.filename, 'r') as infile:
                    for lines in grouper(infile, mp.cpu_count()/4, ''):
                        reachable_hosts, unreachable_hosts = multi_ping(lines)
                        unreachable.extend(unreachable_hosts)
                        if len(reachable_hosts) > 0:
                            connection_error.extend(multi_send_command(reachable_hosts, 'POST', user, password))
            except IOError as e:
                print(e)
        else:
            reachable_hosts, unreachable_hosts = multi_ping(options.device.split())
            if len(reachable_hosts) > 0:
                connection_error.extend(multi_send_command(reachable_hosts, 'POST', user, password))
    if options.upgrade:
        if options.filename:
            try:
                reboot_sequence(options.filename)
                #unreachable, upgrade_failed, unrecovered, connection_error, file_missing = reboot_proceed(user, password,
                #                                                                           unreachable,
                #                                                                           upgrade_failed,
                #                                                                           unrecovered,
                #                                                                           connection_error,
                #                                                                           file_missing,
                #                                                                           'upgrade')
            except IOError as e:
                print(e)
        else:
            reachable_hosts, unreachable_hosts = multi_ping(options.device.split())
            if len(reachable_hosts) > 0:
                upgrade_failed, unrecovered, connection_error, file_missing = multi_upgrade(reachable_hosts, user, password)
                pass
    if options.rollback:
        if options.filename:
            try:
                reboot_sequence(options.filename)
                #unreachable, upgrade_failed, unrecovered,connection_error, file_missing = reboot_proceed(user, password,
                #                                                                           unreachable,
                #                                                                           upgrade_failed,
                #                                                                           unrecovered,
                #                                                                           connection_error,
                #                                                                           file_missing,
                #                                                                          'rollback')
            except IOError as e:
                print(e)
        else:
            reachable_hosts, unreachable_hosts = multi_ping(options.device.split())
            if len(reachable_hosts) > 0:
                upgrade_failed, unrecovered, connection_error, file_missing = multi_rollback(reachable_hosts, user, password)
                pass
    if options.upload:
        if options.filename:
            try:
                with open(options.filename, 'r') as infile:
                    for lines in grouper(infile, mp.cpu_count()/4, ''):
                        reachable_hosts, unreachable_hosts = multi_ping(lines)
                        unreachable.extend(unreachable_hosts)
                        if len(reachable_hosts) > 0:
                            upfailed, serror, md5error = multi_file_upload(reachable_hosts, user, password)
                            upload_failed.extend(upfailed)
                            space_error.extend(serror)
                            md5_error.extend(md5error)
            except IOError as e:
                print(e)
        else:
            reachable_hosts, unreachable_hosts = multi_ping(options.device.split())
            if len(reachable_hosts) > 0:
                upload_failed, space_error, md5_error = multi_file_upload(reachable_hosts, user, password)

    #print lists of hosts processed with error
    if len(connection_error)>0:
        print('Failed to connect on the following hosts: ' + str(connection_error))
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
    if len(file_missing)>0:
        print('Image files are missing on:' + str(file_missing))

if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)  #catch ctrl-c and call handler to terminate the script
    main()
