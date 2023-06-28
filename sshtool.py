#!/usr/bin/env python
# coding:utf-8

import configparser
# import commands
import datetime
import os
import socket
import subprocess
import sys
import threading
import time
from functools import cmp_to_key
import traceback

import paramiko

# import sysSetup
import paramiko as paramiko

from app.tools.batchping.batchping import Device
from app.tools.batchping.ping3 import ping
from config import basedir

from app.tools.systool import sysSetup
from ..comm import iputils, config

global sucesslist, failedlist, sucessResult, failedResult, devList
sucesslist = []
failedlist = []
sucessResult = {}
failedResult = {}
threadsCount = 0
devList = []


def clearAll():
    global sucesslist, failedlist, sucessResult, failedResult, devList
    sucesslist = []
    failedlist = []
    sucessResult = {}
    failedResult = {}
    devList = []
    return


def threadsControl(func):
    def _threadsControl(*args):
        global threadsCount
        try:
            lock = threading.RLock()
            func(*args)
        finally:
            lock.acquire()
            threadsCount -= 1
            lock.acquire()

    return _threadsControl


def initSSH():
    sshclient = paramiko.SSHClient()
    sshclient.load_system_host_keys()
    sshclient.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    lock = threading.RLock()
    return sshclient, lock


def initSock():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    lock = threading.RLock()
    return sock, lock


def sockConnectTestRun(ip, port):
    try:
        sock, lock = initSock()
        sys.stdout.write('.')
        sys.stdout.flush()
        sock.connect((ip, port))
        print('%s:%d open' % (ip, port))
        sucesslist.append(ip)
    except Exception as e:
        print(e.message)
        failedlist.append(ip)


@threadsControl
def patchPingConnectTestLinuxRun(address, id, name, interval, size, timeout, detail, count, start_time):
    lock = threading.RLock()
    sys.stdout.write('.')
    sys.stdout.flush()
    dev = Device(id, name, address)
    devList.append(dev)
    dev.ping(interval, size, timeout, detail, count)


@threadsControl
def pingConnectTestLinuxRun(ip):
    lock = threading.RLock()
    sys.stdout.write('.')
    sys.stdout.flush()
    cmds = 'ping -W2 -c2 %s' % ip
    status, output = subprocess.getstatusoutput(cmds)
    # print(status)
    if status == 0:
        lock.acquire()
        sucesslist.append(ip)
        lock.release()
    else:
        lock.acquire()
        failedlist.append(ip)
        lock.release()


@threadsControl
def ping6ConnectTestLinuxRun(ip):
    lock = threading.RLock()
    sys.stdout.write('.')
    sys.stdout.flush()
    cmds = 'ping6 -W2 -c2 %s' % ip
    status, output = subprocess.getstatusoutput(cmds)
    sys.stdout.write('ping6 {ipaddr}:{status}\n'.format(ipaddr=ip, status=status))
    sys.stdout.flush()
    if status == 0:
        lock.acquire()
        sucesslist.append(ip)
        lock.release()
    else:
        lock.acquire()
        failedlist.append(ip)
        lock.release()


@threadsControl
def pingConnectTestNtRun(ip):
    print('.')
    sys.stdout.flush()
    lock = threading.RLock()
    cmds = "ping -n 2 -w 1 %s" % ip
    output = os.popen(cmds)
    # print(output.read()
    if output.read().find('(0%') >= 0:
        lock.acquire()
        sucesslist.append(ip)
        lock.release()
    else:
        lock.acquire()
        failedlist.append(ip)
        lock.acquire()


@threadsControl
def sshConnectTestRun(ip, username='', password=''):
    try:
        sshclient, lock = initSSH()
        # print('Testing on %s' % ip
        start_time = time.time()
        sshclient.connect(ip, port=config.SSH_PORT, timeout=config.SSH_TIMEOUT, username=username, password=password,
                          allow_agent=False, look_for_keys=False)
        stop_time = time.time()
        print("sshConnectTestRun 执行时间为：====【{}】".format(stop_time - start_time))
        lock.acquire()
        sucesslist.append(ip)
        lock.release()

    except socket.timeout as e:
        # print(ip + e.message
        # print(type(e)
        lock.acquire()
        failedlist.append(ip)
        failedResult[ip] = '连接超时'
        lock.release()

    except socket.error as e:
        # print(ip + e.message
        # print(type(e)
        lock.acquire()
        failedlist.append(ip)
        failedResult[ip] = '连接失败'
        lock.release()

    except paramiko.ssh_exception.NoValidConnectionsError as e:
        # print(ip + e.message
        # print(type(e)
        lock.acquire()
        failedlist.append(ip)
        failedResult[ip] = '连接失败'
        lock.release()

    except paramiko.ssh_exception.AuthenticationException as a:
        # print(type(a)
        # print(ip + a.message
        lock.acquire()
        failedlist.append(ip)
        failedResult[ip] = '认证失败'
        lock.release()

    except Exception as a:
        print(ip)
        print(type(a))
        print(a.message)
        lock.acquire()
        failedlist.append(ip)
        failedResult[ip] = '连接失败'
        lock.release()

    finally:
        print('.')
        sys.stdout.flush()
        sshclient.close()


@threadsControl
def sshExecRun(ip, user, passwd, cmd):
    try:
        start_time = time.time()
        sshclient, lock = initSSH()
        stop_time = time.time()
        print("initSSH初始化 ===== {}".format(stop_time - start_time))
        start_time = time.time()
        sshclient.connect(ip, port=config.SSH_PORT, timeout=config.SSH_TIMEOUT, username=user, password=passwd)
        print(cmd)
        # sucessResult[ip]=''
        # failedResult[ip]=''
        if cmd:
            for c in str(cmd).split(';'):
                print(c)
                stdin, stdout, stderr = sshclient.exec_command(c)
                lock.acquire()
                stdoutmsg = stdout.read().decode('utf-8')
                stderrmsg = stderr.read().decode('utf-8')
                print("{}--------{}".format(stdoutmsg, stderrmsg))
                if len(stderrmsg) == 0:
                    sucessResult[ip] = stdoutmsg
                else:
                    sucesslist.remove(ip)
                    failedlist.append(ip)
                    failedResult[ip] = stderrmsg
            lock.release()
        stop_time = time.time()
        print("sshExecRun执行命令 ===== {}".format(stop_time - start_time))
    except Exception as e:
        traceback.print_exc()
        lock.acquire()
        sucesslist.remove(ip)
        failedlist.append(ip)
        failedResult[ip] = str(e)
        lock.release()
    finally:
        print('.')
        sys.stdout.flush()
        sshclient.close()


@threadsControl
def sshGetRun(ip, user, passwd, src, dst):
    getpath = os.path.join(basedir, 'app/static/sftp')
    try:
        sock, lock = initSock()
        sock.connect((ip, config.SSH_PORT))
        conn = paramiko.Transport(sock)
        conn.connect(username=user, password=passwd)
        sftp = paramiko.SFTP.from_transport(conn)

        e = conn.get_exception()
        if e is not None:
            sucesslist.remove(ip)
            del sucessResult[ip]
            print(str(e))
            raise e

        filename = ip + '.' + src.strip().split('/')[-1] + '.' + dst
        dst = getpath + '/' + filename
        print(src)
        print(dst)
        sftp.get(src, dst)
        lock.acquire()
        sucessResult[ip] = '<a href="/static/sftp/{filename}">{filename}</a>'.format(filename=filename)
        lock.release()
    except Exception as e:
        lock.acquire()
        print('Exception' + str(e))
        sucesslist.remove(ip)
        failedlist.append(ip)
        failedResult[ip] = str(e)
        lock.release()
        return
    finally:
        print('.')
        sys.stdout.flush()
        return


@threadsControl
def sshPutRun(ip, user, passwd, src, dst):
    global sucessResult, failedResult
    try:
        sock, lock = initSock()
        sock.connect((ip, config.SSH_PORT))
        conn = paramiko.Transport(sock)
        conn.connect(username=user, password=passwd)

        sftp = paramiko.SFTP.from_transport(conn)

        e = conn.get_exception()
        print("sftp exception: [{}]".format(e))
        if e is not None:
            sucesslist.remove(ip)
            del sucessResult[ip]
            raise e
        print("src : {}】，dst ：【{}】".format(src, dst))
        result = sftp.put(src, dst)
        print("sftp result: [{}]".format(result))
        lock.acquire()
        print("sftp result len: [{}]".format(len(result.__str__())))
        if len(result.__str__()) > 0:
            sucessResult[ip] = dst + '  ' + result.__str__()
        else:
            sucesslist.remove(ip)
            failedlist.append(ip)
            failedResult[ip] = '文件上传失败'
        lock.release()
        return
    except Exception as e:
        lock.acquire()
        print(str(e))
        sucesslist.remove(ip)
        failedlist.append(ip)
        failedResult[ip] = str(e)
        lock.release()
        return
    finally:
        print('.')
        sys.stdout.flush()
        conn.close()
        sock.close()
        return


def connectTest(iplist, func, username='', password=''):
    global threadsCount
    threadsCount = 0
    print('\nStarting connection test\n')
    start_time = time.time()
    sys.stdout.flush()
    threads = []
    for ip in iplist:
        threads.append(threading.Thread(target=func, args=(ip, username, password)))
    for t in threads:
        t.start()
        threadsCount += 1
        while threadsCount > config.THREADS_MAX:
            pass
    for t in threads:
        t.join()
    stop_time = time.time()
    print('connectTest 执行时间======【{}】'.format(stop_time - start_time))
    print('\nAll thread runing done\n')
    return sucesslist, failedlist


def sshConnectTest(iplist, username='', password=''):
    connectTest(iplist=iplist, func=sshConnectTestRun, username=username, password=password)
    return getExecOutput(commands='ssh连接测试')


def pingTest(iplist, func=pingConnectTestLinuxRun):
    global threadsCount
    threadsCount = 0
    print('Starting connection test')
    threads = []
    for ip in iplist:
        threads.append(threading.Thread(target=func, args=(ip,)))
    for t in threads:
        t.start()
        threadsCount += 1
        while threadsCount > config.THREADS_MAX:
            pass
    for t in threads:
        t.join()
    print('\nAll thread runing done\n')
    return getExecOutput(commands='ping')


def patchPingTest(iplist, start_time, interval=100, size=56, timeout=1, detail=False, count=10,
                  func=patchPingConnectTestLinuxRun):
    global threadsCount
    threadsCount = 0
    print('Starting connection test')
    threads = []
    id = 0
    for ip in iplist:
        id += 1
        name = '节点{id}'.format(id=id)
        threads.append(
            threading.Thread(target=func, args=(ip, id, name, interval, size, timeout, detail, count, start_time,)))
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    print('\nAll thread runing done\n')
    return getPatchOutput(commands='ping', start_time=start_time)


def ping6Test(iplist, func=ping6ConnectTestLinuxRun):
    global threadsCount
    threadsCount = 0
    print('Starting connection test')
    threads = []
    print(iplist)
    for ip in iplist:
        threads.append(threading.Thread(target=func, args=(ip,)))
    for t in threads:
        t.start()
        threadsCount += 1
        while threadsCount > config.THREADS_MAX:
            pass
    for t in threads:
        t.join()
    print('\nAll thread runing done\n')
    return getExecOutput(commands='ping6', cmp=iputils.ip6Cmp)


from concurrent.futures import ThreadPoolExecutor


def sshExec(iplist, user, passwd, cmd):
    global threadsCount
    threadsCount = 0
    runlist = []
    noRunlist = []
    threads = []
    tasks = []
    runlist, noRunlist = connectTest(iplist, sshConnectTestRun, username=user, password=passwd)

    print('\nStarting ssh thread\n')
    sys.stdout.flush()

    # print('Commands will execute on these server:'
    # for ip in sorted(runlist,cmp=iptools.ipCmp):print(ip
    # print('======================================================='
    # print('these servers cannot estbilish ssh connection:'
    # for ip in sorted(noRunlist,cmp=iptools.ipCmp):print(ip
    # print('======================================================='
    for ip in runlist:
        threads.append(threading.Thread(target=sshExecRun, args=(ip, user, passwd, cmd)))
    for t in threads:
        t.start()
        threadsCount += 1
        while threadsCount > config.THREADS_MAX:
            time.sleep(0.1)
    for t in threads:
        t.join()
    print('\nAll thread runing done\n')
    # getExecResult()
    return getExecOutput(commands=cmd)


@threadsControl
def nmapExecRun(ip, ports=''):
    lock = threading.RLock()
    if ports != '':
        status, output = subprocess.getstatusoutput(
            '/usr/bin/nmap {ip} -p {port}|grep -e open -e closed'.format(ip=ip, port=ports))
    else:
        status, output = subprocess.getstatusoutput(
            '/usr/bin/nmap {ip}|grep -e open'.format(ip=ip))
    print(output, status)
    lock.acquire()
    output = output.replace('open', '<font color="green">open</font>').replace('closed',
                                                                               '<font color="red">closed</font>').replace(
        '\n', '<br>')
    if status == 0:
        sucessResult[ip] = output
    else:
        sucesslist.remove(ip)
        failedlist.append(ip)
        failedResult[ip] = output
    lock.release()


@threadsControl
def nmap6ExecRun(ip, ports=''):
    lock = threading.RLock()
    if ports != '':
        status, output = subprocess.getstatusoutput(
            '/usr/bin/nmap -6 {ip} -p {port}|grep -e open -e closed'.format(ip=ip, port=ports))
    else:
        status, output = subprocess.getstatusoutput(
            '/usr/bin/nmap -6 {ip}|grep -e open'.format(ip=ip))
    print(output, status)
    lock.acquire()
    output = output.replace('open', '<font color="green">open</font>').replace('closed',
                                                                               '<font color="red">closed</font>').replace(
        '\n', '<br>')
    if status == 0:
        sucessResult[ip] = output
    else:
        sucesslist.remove(ip)
        failedlist.append(ip)
        failedResult[ip] = output
    lock.release()


def nmapExec(target, iplist, ports):
    global threadsCount, sucesslist
    threadsCount = 0
    runlist = []
    noRunlist = []
    threads = []
    sucesslist = iplist
    for ip in iplist:
        threads.append(threading.Thread(target=target, args=(ip, ports)))
    for t in threads:
        t.start()
        threadsCount += 1
        while threadsCount > config.THREADS_MAX:
            time.sleep(0.1)
    for t in threads:
        t.join()
    print('\nAll thread runing done\n')
    # getExecResult()
    return getExecOutput(commands='端口探测', cmp=iputils.ip6Cmp if target is nmap6ExecRun else iputils.ipCmp)


def sftpExec(func, iplist, user, passwd, src, dst):
    global threadsCount
    threadsCount = 0
    runlist = []
    noRunlist = []
    threads = []
    print('\nStarting ssh thread\n')
    runlist, noRunlist = connectTest(iplist, sshConnectTestRun, username=user, password=passwd)
    print("runlist=[{}], noRunlist=[{}]".format(runlist, noRunlist))
    # print('file will transport or receive these server:'
    # for ip in sorted(runlist,cmp=iptools.ipCmp):print(ip
    # print('======================================================='
    # print('these servers cannot estbilish ssh connection:'
    # for ip in sorted(noRunlist,cmp=iptools.ipCmp):print(ip
    # print('======================================================='
    for ip in runlist:
        print(ip)
        threads.append(threading.Thread(target=func, args=(ip, user, passwd, src, dst)))
    for t in threads:
        t.start()
        threadsCount += 1
        while threadsCount > config.THREADS_MAX:
            pass
    for t in threads:
        t.join()
    print(getExecResult())
    print('\nAll thread runing done\n')
    return getExecOutput('sftp {src} {dst}'.format(src=src, dst=dst))


def sshReplaceRun(ip, user, passwd, filename, srcstr, dststr, version):
    cmdstr = 'cp {filename} {filename}.{version} ;sed -i {filename} -e s/{srcstr}/{dststr}/g'.format(filename=filename,
                                                                                                     version=version,
                                                                                                     srcstr=srcstr,
                                                                                                     dststr=dststr)
    # print(cmdstr
    return sshExecRun(ip, user, passwd, cmdstr)


def sshReplaceExec(iplist, user, passwd, filename, srcstr, dststr, version):
    global threadsCount
    threadsCount = 0
    runlist = []
    noRunlist = []
    threads = []
    runlist, noRunlist = connectTest(iplist, sshConnectTestRun, username=user, password=passwd)
    # print('Commands will execute on these server:'
    # for ip in sorted(runlist,cmp=iptools.ipCmp):print(ip
    # print('======================================================='
    # print('these servers cannot estbilish ssh connection:'
    # for ip in sorted(noRunlist,cmp=iptools.ipCmp):print(ip
    # print('======================================================='
    for ip in runlist:
        threads.append(
            threading.Thread(target=sshReplaceRun, args=(ip, user, passwd, filename, srcstr, dststr, version)))
    for t in threads:
        t.start()
        threadsCount += 1
        while threadsCount > config.THREADS_MAX:
            time.sleep(0.1)
    for t in threads:
        t.join()
    return getExecOutput(
        commands='sed -i {filename} -e s/{srcstr}/{dststr}/g'.format(filename=filename, srcstr=srcstr, dststr=dststr))


def sshGetSysSN(ip, user, passwd):
    try:
        sshclient, lock = initSSH()
        sshclient.connect(ip, port=config.SSH_PORT, timeout=config.SSH_TIMEOUT, username=user, password=passwd)
        stdin, stdout, stderr = sshclient.exec_command(config.SERIALNO)
        return stdout.read().strip()
    except Exception as e:
        print(ip + ':' + str(e))
    finally:
        sshclient.close()


def sshGetSysMAC(ip, user, passwd):
    try:
        cmd = """ifconfig -a|grep -i -e HWaddr|awk -F' ' '{print($5}'"""
        sshclient, lock = initSSH()
        sshclient.connect(ip, port=config.SSH_PORT, timeout=config.SSH_TIMEOUT, username=user, password=passwd)
        stdin, stdout, stderr = sshclient.exec_command(cmd)
        return stdout.read().strip().split('\n')
    except Exception as e:
        print(ip + ':' + str(e))
    finally:
        sshclient.close()


def changeIPaddrRemoteRun(oldip, user, passwd, ifname, newip):
    ifcfgfile = '/etc/sysconfig/network-scripts/ifcfg-' + ifname
    return sshReplaceRun(oldip, user, passwd, ifcfgfile, oldip, newip)


def getExecResult(outputfile='', prompt='', time=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')):
    result = '''#=======================================
# Start time:%s
# commands:%s
# %d address in request ip manager,
# %d servers can be connected,
# %d servers can not be connected,
# %d servers sucsessed run command,
# %d servers failed run command
#=======================================

[ALIVE]
%s
[DOWN]
%s
[RUN_SUCESS]
%s
[RUN_FAILED]
%s''' % (time, prompt, len(sucesslist) + len(failedlist), len(sucesslist), len(failedlist), len(sucessResult),
         len(failedResult), iputils.getListIP(sucesslist), iputils.getListIP(failedlist),
         iputils.getDictIP(sucessResult),
         iputils.getDictIP(failedResult))
    if outputfile != '':
        with open(outputfile, 'ab') as f:
            f.write(result)
    print(result)
    return result


def getExecOutput(commands='', cmp=iputils.ipCmp):
    result = {}
    result['starttime'] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    result['commands'] = commands
    result['addrcount'] = len(sucesslist) + len(failedlist)
    result['succcount'] = len(sucesslist)
    result['faildcount'] = len(failedlist)
    result['succipaddr'] = sorted(list(set(sucesslist)), key=cmp_to_key(cmp))
    result['faildipaddr'] = sorted(list(set(failedlist)), key=cmp_to_key(cmp))
    result['succresult'] = sucessResult
    result['faildresult'] = failedResult
    clearAll()
    return result


def getPatchOutput(commands='', start_time=0, cmp=iputils.ipCmp):
    result = {}
    test_time = time.time()
    during = round(test_time - start_time)
    result['test_time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(test_time))
    result['during'] = during
    result['result'] = devList
    clearAll()
    return result


def sshSetupIPaddrRun(ip, user, passwd, niclist, ipmi_channel):
    for nic in niclist:
        if nic == None: continue
        if nic.name == 'ipmi':
            cmd = config.IPMI_LAN_SET % (ipmi_channel, nic.ip, ipmi_channel, nic.netmask, ipmi_channel, nic.gateway)
            # print(cmd
            sshExecRun(ip, user, passwd, cmd)
        elif nic.name.find('eth') == 0:
            sshExecRun(ip, user, passwd,
                       'echo "%s" >/etc/sysconfig/network-scripts/ifcfg-%s' % (
                           nic.getNICcfgStr(), nic.name) + ';cat /etc/sysconfig/network-scripts/ifcfg-%s' % nic.name)
            if nic.hostname != '':
                if nic.hostname[0] == '*':
                    hostip = nic.ip
                    hostname = nic.hostname[1:]
                    cmd = 'sed -i /%s/d /etc/hosts;echo "%s    %s">>/etc/hosts;sed -i "/^HOSTNAME/d" /etc/sysconfig/network;' \
                          'echo "HOSTNAME=%s">>/etc/sysconfig/network;hostname %s' % (
                              hostip, hostip, hostname, hostname, hostname)
                else:
                    hostip = nic.ip
                    hostname = nic.hostname
                    cmd = 'sed -i /%s/d /etc/hosts;echo "%s    %s">>/etc/hosts;' % (hostip, hostip, hostname)
                sshExecRun(ip, user, passwd, cmd)


def sshWriteFileRun(ip, user, passwd, filename, strings):
    cmd = 'echo "%s">%s;cat %s' % (strings, filename, filename)
    sshExecRun(ip, user, passwd, cmd)


def sshServiceCtrlRun(ip, user, passwd, service, enabled):
    if enabled:
        cmd = 'service %s start;chkconfig %s on' % (service, service)
    else:
        cmd = 'service %s stop;chkconfig %s off' % (service, service)
    sshExecRun(ip, user, passwd, cmd)


def sshServiceListCtrlRun(ip, user, passwd, stoplist, startlist):
    if stoplist != None:
        for service in stoplist:
            sshServiceCtrlRun(ip, user, passwd, service, enabled=False)
    if startlist != None:
        for service in startlist:
            sshServiceCtrlRun(ip, user, passwd, service, enabled=True)


def sshSetupNtpRun(ip, user, passwd, ntpserver):
    sshWriteFileRun(ip, user, passwd, '/etc/ntp.conf', ntpserver)
    # sshExecRun(ip, user, passwd, 'ntpdate %s' % ((ntpserver.split('\n'))[0].split(' '))[0])
    # 上面这条命令执行起来非常慢,严重影响性能


def sshSetupDnsRun(ip, user, passwd, dnsserver):
    sshWriteFileRun(ip, user, passwd, '/etc/resolv.conf', dnsserver)


def sshSetupStaticRouteRun(ip, user, passwd, static_routes_list):
    static_route = ''
    for route in static_routes_list:
        if route == None:
            continue
        else:
            static_route += (route.getStaticRouteStr() + '\n')
    sshWriteFileRun(ip, user, passwd, '/etc/sysconfig/static-routes', static_route)


@threadsControl
def sshSetupRun(ip, user, passwd, cf):
    try:
        sections = cf.sections()
        if 'IPADDR' in sections:
            options = cf.options('IPADDR')
            channel = cf.get('IPADDR', 'ipmi-channel')
            if 'mac-ip-file' in options:
                mac2ipfile = cf.get('IPADDR', 'mac-ip-file')
                for mac in sshGetSysMAC(ip, user, passwd):
                    sshSetupIPaddrRun(ip, user, passwd, sysSetup.Nic.loadIPFromMac(mac2ipfile, mac), channel)
            if 'sn-ip-file' in options:
                sn = sshGetSysSN(ip, user, passwd)
                sshSetupIPaddrRun(ip, user, passwd, sysSetup.Nic.loadIPFromSN(cf.get('IPADDR', 'sn-ip-file'), sn),
                                  channel)
        if 'STATIC_ROUTE' in sections:
            sshSetupStaticRouteRun(ip, user, passwd, sysSetup.Static_Route.loadStaticRouteFromConfig(cf))
        if 'DNS' in sections:
            sshSetupDnsRun(ip, user, passwd, sysSetup.loadDNSServer(cf))
        if 'NTP' in sections:
            sshSetupNtpRun(ip, user, passwd, sysSetup.loadNtpServer(cf))
        if 'SERVICE' in sections:
            stoplist = cf.get('SERVICE', 'stop').strip().split(',')
            startlist = cf.get('SERVICE', 'start').strip().split(',')
            sshServiceListCtrlRun(ip, user, passwd, stoplist, startlist)
        if 'SELINUX' in sections:
            sshWriteFileRun(ip, user, passwd, '/etc/selinux/config', sysSetup.loadSElinuxConfig(cf))
        if 'REBOOT' in sections:
            if cf.get('REBOOT', 'reboot') == 'yes':
                sshExecRun(ip, user, passwd, 'shutdown -ry 0')
    except Exception as e:
        print(ip + ':' + str(e))


def sshSetupExec(iplist, user, passwd, configFile):
    try:
        cf = configparser.ConfigParser()
        cf.read(configFile)
        global threadsCount
        threadsCount = 0
        runlist = []
        noRunlist = []
        threads = []
        runlist, noRunlist = connectTest(iplist, sshConnectTestRun, username=user, password=passwd)

        print('\nStarting ssh thread\n')
        sys.stdout.flush()

        # print('Commands will execute on these server:'
        # for ip in sorted(runlist,cmp=iptools.ipCmp):print(ip
        # print('======================================================='
        # print('these servers cannot estbilish ssh connection:'
        # for ip in sorted(noRunlist,cmp=iptools.ipCmp):print(ip
        # print('======================================================='
        for ip in runlist:
            threads.append(threading.Thread(target=sshSetupRun, args=(ip, user, passwd, cf)))
        for t in threads:
            t.start()
            threadsCount += 1
            while threadsCount > config.THREADS_MAX:
                pass
        for t in threads:
            t.join()
        print('\nAll thread runing done\n')
        # getExecResult()
        return sucessResult, failedResult
    except Exception as e:
        print(str(e))


def sshSetupPXE(iplist, user, passwd):
    try:
        global threadsCount
        threadsCount = 0
        runlist = []
        noRunlist = []
        threads = []
        runlist, noRunlist = connectTest(iplist, sshConnectTestRun, username=user, password=passwd)
        for ip in runlist:
            cmd = "ipmitool -I lanplus -H " + str(ip) + " -U " + user.decode("utf-8") + "  -P  " + passwd.decode(
                "utf-8") + " chassis bootdev pxe;ipmitool -I lanplus -H " + str(ip) + " -U " + user.decode(
                "utf-8") + "  -P  " + passwd.decode("utf-8") + " power reset;"
            print(cmd)
            threads.append(threading.Thread(target=sshExecRun, args=(ip, user, passwd, cmd)))
        for t in threads:
            t.start()
            threadsCount += 1
            while threadsCount > config.THREADS_MAX:
                pass
        for t in threads:
            t.join()
        print('\nAll thread runing done\n')
        # getExecResult()
        return getExecOutput(commands="服务器PXE重启模式")
        print('\nStarting ssh thread\n')
        sys.stdout.flush()
    except Exception as e:
        traceback.print_exc()

# 服务器网卡绑定
def bondExec(iplist, user, passwd, cmd):
    global threadsCount
    threadsCount = 0
    runlist = []
    noRunlist = []
    threads = []
    tasks = []
    runlist, noRunlist = connectTest(iplist, sshConnectTestRun, username=user, password=passwd)

    print('\nStarting bond thread\n')
    sys.stdout.flush()

    # print('Commands will execute on these server:'
    # for ip in sorted(runlist,cmp=iptools.ipCmp):print(ip
    # print('======================================================='
    # print('these servers cannot estbilish ssh connection:'
    # for ip in sorted(noRunlist,cmp=iptools.ipCmp):print(ip
    # print('======================================================='
    for ip in runlist:
        threads.append(threading.Thread(target=bondExecRun, args=(ip, user, passwd, cmd)))
    for t in threads:
        t.start()
        threadsCount += 1
        while threadsCount > config.THREADS_MAX:
            time.sleep(0.1)
    for t in threads:
        t.join()
    print('\nAll thread runing done\n')
    # getExecResult()
    return getExecOutput(commands=cmd)

@threadsControl
def bondExecRun(ip, user, passwd, cmd):
    try:
        print("initSSH绑定逻辑初始化")
        start_time = time.time()
        sshclient, lock = initSSH()
        stop_time = time.time()
        print("initSSH绑定逻辑初始化 ===== {}".format(stop_time - start_time))
        start_time = time.time()
        sshclient.connect(ip, port=config.SSH_PORT, timeout=config.SSH_TIMEOUT, username=user, password=passwd)
        # sucessResult[ip]=''
        # failedResult[ip]=''
        if cmd:
            print("绑定各项参数 ===== {}".format(cmd))
            # ip地址
            ip_address = cmd['ip_address']
            # 物理网卡地址
            phy_nic = cmd['phy_nic']
            # 逻辑网卡地址
            logic_nic = cmd['logic_nic']
            # 绑定模式model
            model = cmd['model']
            # 子网掩码
            netmask = cmd['netmask']
            # 网关
            getway = cmd['getway']


            # 判断ifcfg-mg0文件是否存在
            ifcfg_name = 'if [ -f "/etc/sysconfig/network-scripts/ifcfg-%s"' % logic_nic+' ]; then echo "exist"; fi'
            print("ifcfg_name为==== {}".format(ifcfg_name))
            stdin3, stdout3, stderr3 = sshclient.exec_command(ifcfg_name)
            result = stdout3.read()
            print("返回的result==== {}".format(result.decode()))
            # 如果文件存在,删除文件
            if 'exist' in result.decode():
                print("文件存在，先删除文件")
                sshclient.exec_command('sudo rm /etc/sysconfig/network-scripts/ifcfg-%s' % logic_nic)
                print("文件存在，删除文件成功")

            # 创建空文件
            print("进入创建空文件")
            sshclient.exec_command('sudo touch /etc/sysconfig/network-scripts/ifcfg-%s' % logic_nic)

            # 重定向标准输入到ifcfg-eth0,用于写入
            stdin, stdout, stderr = sshclient.exec_command(
                f'sudo cat > /etc/sysconfig/network-scripts/ifcfg-{logic_nic}')
            stdin.channel.send_ready()  # 通知服务器准备输入
            print("开始写入")
            stdin.write('DEVICE=%s\n' % logic_nic.strip())
            stdin.write('TYPE=Bonding\n')
            stdin.write('BONDING_MASTER=yes\n')
            stdin.write('BOOTPROTO=static\n')
            stdin.write('IPADDR=%s\n' % ip_address.strip())
            stdin.write('NETMASK=%s\n' % netmask.strip())
            # 如果getway没有填写信息，那么网卡绑定时不需要执行此行命令
            if getway:
                stdin.write('GATEWAY=%s\n' % getway.strip())
            stdin.write('BONDING_OPTS="mode=%s miimon=100"' % model)
            print("逻辑网卡写入完成")

            # 需绑定的物理网卡 生成 类似 ['ens01', 'ens02']
            nics = phy_nic.split('#')
            for nic in nics:

                # 判断ifcfg-mg0文件是否存在
                stdin4, stdout4, stderr4 = sshclient.exec_command(
                    'if [ -f "/etc/sysconfig/network-scripts/ifcfg-%s"' % nic + ' ]; then echo "exist"; fi')
                result2 = stdout4.read()

                # 如果文件存在,删除文件
                if 'exist' in result2.decode():
                    sshclient.exec_command('sudo rm /etc/sysconfig/network-scripts/ifcfg-%s' % nic)

                # 如果文件不存在,创建空文件
                print("创建物理网卡绑定空文件")
                sshclient.exec_command('sudo touch /etc/sysconfig/network-scripts/ifcfg-%s' % nic)

                stdin2, stdout2, stderr2 = sshclient.exec_command(f'sudo cat > /etc/sysconfig/network-scripts/ifcfg-{nic}')
                stdin2.channel.send_ready()  # 通知服务器准备输入

                stdin2.write('DEVICE=%s\n' % nic.strip())
                stdin2.write('TYPE=Ethernet\n')
                stdin2.write('BOOTPROTO=none\n')
                stdin2.write('MASTER=%s\n' % logic_nic.strip())
                stdin2.write('SLAVE=yes\n')

            # stdin, stdout, stderr = sshclient.exec_command(c)
            lock.acquire()
            print('编写完成')
            #stdoutmsg = stdout.read().decode('utf-8')
            #stderrmsg = stderr.read().decode('utf-8')
            print('获取完成状态')
            # print("{}--------{}".format(stdoutmsg, stderrmsg))
            # if len(stderrmsg) == 0:
            #     sucessResult[ip] = stdoutmsg
            # else:
            #     sucesslist.remove(ip)
            #     failedlist.append(ip)
            #     failedResult[ip] = stderrmsg
            lock.release()
        stop_time = time.time()
        print("sshExecRun执行命令 ===== {}".format(stop_time - start_time))
    except Exception as e:
        traceback.print_exc()
        lock.acquire()
        sucesslist.remove(ip)
        failedlist.append(ip)
        failedResult[ip] = str(e)
        lock.release()
    finally:
        print('.')
        sys.stdout.flush()
        # 打印重启提示信息,等待3秒
        print("准备重启服务器......")
        time.sleep(1)
        sshclient.exec_command('sudo reboot')
        print("服务器已重启!")
        # sshclient.close()

# 设备信息采集（主动）
def deviceCollectExec(iplist, user, passwd, cmd):
    global threadsCount
    threadsCount = 0
    runlist = []
    noRunlist = []
    threads = []
    tasks = []
    runlist, noRunlist = connectTest(iplist, sshConnectTestRun, username=user, password=passwd)

    print('\nStarting deviceCollection thread\n')
    sys.stdout.flush()

    # print('Commands will execute on these server:'
    # for ip in sorted(runlist,cmp=iptools.ipCmp):print(ip
    # print('======================================================='
    # print('these servers cannot estbilish ssh connection:'
    # for ip in sorted(noRunlist,cmp=iptools.ipCmp):print(ip
    # print('======================================================='
    for ip in runlist:
        threads.append(threading.Thread(target=deviceExecRun, args=(ip, user, passwd, cmd)))
    for t in threads:
        t.start()
        threadsCount += 1
        while threadsCount > config.THREADS_MAX:
            time.sleep(0.1)
    for t in threads:
        t.join()
    print('\nAll thread runing done\n')
    # getExecResult()
    return getExecOutput(commands=cmd)


@threadsControl
def deviceExecRun(ip, user, passwd, cmd):
    try:
        start_time = time.time()
        sshclient, lock = initSSH()
        stop_time = time.time()
        print("initSSH初始化 ===== {}".format(stop_time - start_time))
        start_time = time.time()
        sshclient.connect(ip, port=config.SSH_PORT, timeout=config.SSH_TIMEOUT, username=user, password=passwd)
        print("开始执行设备信息采集（主动）逻辑代码")
        # sucessResult[ip]=''
        # failedResult[ip]=''
        if cmd:
            # 针对部分新安装服务器没有 /mnt/nfs目录问题，采用mkdir -p /mnt/nfs，递归创建文件夹方式，防止程序报错
            stdin2, stdout2, stderr2 = sshclient.exec_command('mkdir -p /mnt/nfs')
            lock.acquire()
            stdoutmsg = stdout2.read().decode('utf-8')
            stderrmsg = stderr2.read().decode('utf-8')
            print("{}--------{}".format(stdoutmsg, stderrmsg))
            lock.release()
            for c in str(cmd).split(';'):
                print(c)
                stdin, stdout, stderr = sshclient.exec_command(c)
                lock.acquire()
                stdoutmsg = stdout.read().decode('utf-8')
                stderrmsg = stderr.read().decode('utf-8')
                print("{}--------{}".format(stdoutmsg, stderrmsg))
                if len(stderrmsg) == 0:
                    sucessResult[ip] = stdoutmsg
                else:
                    sucesslist.remove(ip)
                    failedlist.append(ip)
                    failedResult[ip] = stderrmsg
                time.sleep(0.2) # 每条指令之间睡眠0.2秒
            lock.release()
        stop_time = time.time()
        print("sshExecRun执行命令 ===== {}".format(stop_time - start_time))
    except Exception as e:
        traceback.print_exc()
        lock.acquire()
        sucesslist.remove(ip)
        failedlist.append(ip)
        failedResult[ip] = str(e)
        lock.release()
    finally:
        print('.')
        sys.stdout.flush()
        sshclient.close()



if __name__ == '__main__':
    ssh = paramiko.SSHClient()
    transport = paramiko.Transport(('192.168.1.1', 22))
    transport.connect(username='root', password='111111')
    ssh._transport = transport

    # 执行远程命令
    cmd = 'hostname;date;'
    stdin, stdout, stderr = ssh.exec_command(cmd)
    print(stdout.read().decode())
    ssh = paramiko.SSHClient()
    transport = paramiko.Transport(('192.168.1.2', 22))
    transport.connect(username='root', password='111111')
    ssh._transport = transport

    # 执行远程命令
    cmd = 'hostname;date;'
    stdin, stdout, stderr = ssh.exec_command(cmd)
    print(stdout.read().decode())

    pass
    # sucesslist = []
    # failedlist = []
    # sucessResult = {}
    # failedResult = {}
    # sucess, faild = sshExec(iptools.toAddressList('192.168.236.130-132'),'root','111111',config.LINKSTAT)
    # # connectTest(iptools.toAddressList('192.168.1.1-254'), (pingConnectTestNtRun if platform.system()=='Windows' else pingConnectTestLinuxRun))
    # print(getExecResult()
    # niclist = sysSetup.Nic.loadIPFromSN('sn2ip.csv', '12345')
    # setSysIPaddr('192.168.236.131', 'root', '111111', niclist)
    #
    # print(getExecResult())
    # # pingConnectTestNtRun('192.168.1.254')

    # print(sshGetSysSN('192.168.23.131','root','111111')
    # print(sshGetSysMAC('192.168.23.131','root','111111')
