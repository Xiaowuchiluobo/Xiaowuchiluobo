#!/usr/bin/env python
# coding=utf-8

import commands
import getopt
import logging
import os
import platform
import sys
import time

OSVER = '7'
NFSCLIENTPATH = '/mnt/nfs/'
NFSSERVERPATH = '/var/kspost'
NFSSERVERADDR = '127.0.0.1'
LOGFILE = 'kspost.log'
CONFIGFILE = 'seriallist.csv'
SELFCHECKLOG = 'selfcheck.csv'




def timestamp(format='%Y%m%d%H%M%S'):
    return time.strftime(format, time.localtime(time.time()))


def bracket(input):
    """
    :param self:
    :param input:
    :return:
    """
    return '"{output}"'.format(output=str(input).replace('\n', '\r\n').strip('"').strip())


def initLogging():
    logginFormat = '%(asctime)s - %(levelname)s - Serial No:{serialno} - %(message)s'.format(
        serialno=Server.getSerialNo())
    logging.basicConfig(
        level=logging.INFO,
        format=logginFormat,
        datefmt='%m-%d %H:%M',
        filename=LOGFILE,
        filemode='a')
    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG)
    # set a format which is simpler for console use
    formatter = logging.Formatter(logginFormat)
    # tell the handler to use this format
    console.setFormatter(formatter)
    logging.getLogger('').addHandler(console)
    """
    if OSVER != platform.dist()[1].split('.')[0]:
        logging.error('The server is not runing on RHEL/CentOS 7.2 above OS!')
        exit()
    """


def Usage():
    print('%s <options> <commands>' % sys.argv[0])
    print ('''Options:
    -h,--help                                   print this help
    -l,--log==logfilename                       write a log file on localdisk

Commands:
    selfcheck   [selfchecklog.csv]              use ping commands to check the network connective in ip address list
    initsetup   [seriallist.csv]                check if the server open ssh service
''')

def mountNfs():
    if not os.path.exists(NFSCLIENTPATH):
        print('Making NFS mount point:{nfsclientpath}'.format(nfsclientpath=NFSCLIENTPATH))
        print(commands.getoutput('/usr/bin/mkdir -p {nfsclientpath}'.format(nfsclientpath=NFSCLIENTPATH)))
    print('Mounting NFS path ...: : server: {nfsserveraddr}:{nfsserverpath} client: {nfsclientpath}'.format(
        nfsserveraddr=NFSSERVERADDR, nfsserverpath=NFSSERVERPATH, nfsclientpath=NFSCLIENTPATH))
    print(commands.getoutput(
        '/usr/bin/mount -o nolock -t nfs {nfsserveraddr}:{nfsserverpath} {nfsclientpath}'.format(
            nfsserveraddr=NFSSERVERADDR,
            nfsserverpath=NFSSERVERPATH,
            nfsclientpath=NFSCLIENTPATH)))



NOTESTR = ('#Configed by kickstart post script\n'
           '#Script write by caoyu@ctsi.com.cn\n'
           '#Config date:{0:s}\n'.format(timestamp('%Y-%m-%d %H:%M:%S'))
           )

UDEVRULETEMPLATE = (NOTESTR +
                    'ACTION!="add", GOTO="net_name_slot_end"\n'
                    'SUBSYSTEM!="net", GOTO="net_name_slot_end"\n'
                    'NAME!="", GOTO="net_name_slot_end"\n'
                    '\r\n'
                    'IMPORT{cmdline}="net.ifnames"\n'
                    'ENV{net.ifnames}=="0", GOTO="net_name_slot_end"\n'
                    '\r\n'
                    )


class NIC(object):
    hosts = ''
    ifname = ''
    ipaddr = ''
    netmask = ''
    gateway = ''
    pathname = ''
    ifconfig = ''
    ifUdevRule = ''

    IFCFGFILE = '/etc/sysconfig/network-scripts/ifcfg-'

    @classmethod
    def getMacByNicPath(cls, pathname): 
        # 获取MAC地址
        macaddr = commands.getoutput("/sbin/ip link show %s  | grep ether | awk '{print $2}'" % pathname)
        return macaddr
    
    def __init__(self, ifname, ipaddr, netmask, gateway='', hosts='', pathname=''):
        self.ifname = ifname
        self.ipaddr = ipaddr
        self.netmask = netmask
        self.gateway = gateway
        self.hosts = hosts
        self.pathname = pathname
        self.IFCFGFILE += ifname
        self.ifUdevRule = 'NAME=="", ENV{{ID_NET_NAME_PATH}}=="{0:s}", NAME="{1:s}"\n'.format(pathname, ifname)
        self.ifconfig = (NOTESTR +
                         'DEVICE={0:s}\n'
                         'TYPE=Ethernet\n'
                         'ONBOOT=yes\n'
                         'BOOTPROTO=static\n'
                         ).format(ifname)

        if(ipaddr != ''):
            self.ifconfig += ('IPADDR={0:s}\n'
                              'NETMASK={1:s}\n').format(ipaddr, netmask)
            if (gateway != ''):
                self.ifconfig += 'GATEWAY=%s\n' % gateway
        
        self.macaddr = cls.getMacByNicPath(pathname) 
        if self.macaddr:
            self.ifconfig += 'HWADDR=%s\n' % self.macaddr



    def __str__(self):
        return '{ifname}({pathname}):{ipaddr}:{netmask}:{gateway}'.format(ifname=self.ifname, pathname=self.pathname,
                                                                          ipaddr=self.ipaddr, netmask=self.netmask,
                                                                          gateway=self.gateway)

    def setIfcfgFile(self):
        # backup ifcfg file
        logging.info('Configure interface {ifname} : "{config}"'.format(ifname=self.ifname, config=self.ifconfig))
        if (os.path.exists(self.IFCFGFILE)):
            status, output = commands.getstatusoutput(
                '/usr/bin/mv {0:s} {1:s}'.format(self.IFCFGFILE, self.IFCFGFILE + '.bak%s' % timestamp()))
            logging.debug(output)

        with open(self.IFCFGFILE, 'w') as ifcfgfile:
            ifcfgfile.write(self.ifconfig)

cls = NIC

class Server(object):
    hostname = ''
    ntpserver = ''
    serialNo = ''
    udevstr = ''
    HOSTNAMEFILE = '/etc/hostname'
    UDEVRULEFILE = '/etc/udev/rules.d/80-net-name-slot.rules'

    interfaces = None
    ipmichannel = 1
    ipmiInterfac = 'mg0'

    @staticmethod
    def getSerialNo():
        status, output = commands.getstatusoutput('/usr/sbin/dmidecode -t system|grep Serial|cut -d: -f2')
        if (status == 0) & ((output.strip() != 'None')):
            return output.strip()
        else:
            return None

    def initNTPService(self, service='chronyd.service'):
        if self.ntpserver is '':
            logging.error('{funName}: Configure is not been loaded!!!'.format(funName=sys._getframe().f_code.co_name))
            return
        ntpdConfig = '/etc/ntp.conf'
        chronydConfig = '/etc/chrony.conf'
        ntpServerStr = (NOTESTR +
                        'server {0:s} iburst'.format(self.ntpserver)
                        )
        logging.info('Configing ntp server... ntpserver:' + self.ntpserver)

        def modiNTPConfFile(confFile):
            if os.path.exists(confFile):
                status, output = commands.getstatusoutput(
                    '/usr/bin/cp %s %s' % (confFile, confFile + '.bak' + timestamp()))
                logging.debug(output)
                status, output = commands.getstatusoutput('/usr/bin/sed -i "s/^server/#server/g" %s' % confFile)
                logging.debug(output)
                status, output = commands.getstatusoutput('/usr/bin/echo "%s" >> "%s"' % (ntpServerStr, confFile))
                logging.debug(output)

        if self.ntpserver != '':
            modiNTPConfFile(ntpdConfig)
            modiNTPConfFile(chronydConfig)
            logging.info('Starting ntp service...')
            status, output = commands.getstatusoutput(
                '/usr/bin/systemctl restart {servicename}'.format(servicename=service))
            logging.debug(output)
            status, output = commands.getstatusoutput('/usr/bin/timedatectl set-ntp true')
            logging.debug(output)

    def initSNMPService(self, snmpComunity='nisac'):
        snmpConfig = '/etc/snmp/snmpd.conf'
        if os.path.exists(snmpConfig):
            logging.info('Writing {config} file...'.format(config=snmpConfig))
            status, output = commands.getstatusoutput(
                '/usr/bin/sed -i -e "s/public/%s/g" %s' % (snmpComunity, snmpConfig))
            logging.debug(output)
            status, output = commands.getstatusoutput('/usr/bin/systemctl enable snmpd.service')
            logging.debug(output)
            logging.info('Starting snmpd service...')
            status, output = commands.getstatusoutput('/usr/bin/systemctl start snmpd.service')
            logging.debug(output)
        else:
            logging.error('Snmpd service is not installed!!!')

    def initIPMIService(self, ifname='', username='', password=''):
        if self.interfaces is {}:
            logging.error('{funName}: Configure is not been loaded!!!'.format(funName=sys._getframe().f_code.co_name))
            return
        if ifname == '': ifname = self.ipmiInterfac
        try:
            ipaddr = self.interfaces[ifname].ipaddr
            netmask = self.interfaces[ifname].netmask
            gateway = self.interfaces[ifname].gateway
            if (ipaddr == '') | (netmask == '') | (gateway == ''):
                logging.error('IPMI IP address is not be configed! ')
                return
            logging.info((
                'Configing Server\'s IPMI interface... ipmi_ipaddr:{0:s} ipmi_netmask:{1:s} ipmi_gateway:{2:s}').format(
                ipaddr, netmask, gateway))
        except KeyError:
            logging.error('This server\'s interface have not been inited!')
            return

        if os.path.exists('/dev/ipmi0') | os.path.exists('/dev/ipmi/0') | os.path.exists('/dev/ipmidev/0'):
            status, output = commands.getstatusoutput('/usr/bin/rpm -q OpenIPMI')
            logging.debug(output)
            if status == 0:
                status, output = commands.getstatusoutput('/usr/bin/systemctl start ipmi')
                logging.debug(output)
                status, output = commands.getstatusoutput('/usr/bin/ipmitool -I open lan set %d ipsrc static' % (self.ipmichannel))
                logging.debug(output)
                status, output = commands.getstatusoutput(
                    '/usr/bin/ipmitool -I open lan set %d ipaddr %s' % (self.ipmichannel, ipaddr))
                logging.debug(output)
                status, output = commands.getstatusoutput(
                    '/usr/bin/ipmitool -I open lan set %d netmask %s' % (self.ipmichannel, netmask))
                logging.debug(output)
                status, output = commands.getstatusoutput(
                    '/usr/bin/ipmitool -I open lan set %d defgw ipaddr %s' % (self.ipmichannel, gateway))
                logging.debug(output)
                status, output = commands.getstatusoutput(
                    '/usr/bin/ipmitool -I open lan set %d access on' % (self.ipmichannel))
                logging.debug(output)
                #status, output = commands.getstatusoutput('/usr/bin/ipmitool -I open mc reset cold')
                logging.debug(output)
            else:
                logging.error('Could not found the ipmitool!')
        else:
            logging.error(
                'Could not open device at /dev/ipmi0 or /dev/ipmi/0 or /dev/ipmidev/0: No such file or directory')

    @staticmethod
    def getServerDisk():
        return commands.getoutput('/usr/sbin/parted -l;/usr/bin/df -h')

    @staticmethod
    def getServerSwap():
        swapInfo = commands.getoutput('/usr/bin/cat /proc/swaps')
        swapTotal = int(
            commands.getoutput('/usr/bin/cat /proc/meminfo|grep SwapTotal|cut -d: -f2').strip().split()[0]) / 1023
        return 'Total Swap: {totalSwap} MB \r\n'.format(totalSwap=swapTotal) + swapInfo, swapTotal

    @staticmethod
    def getServerMem():
        status, output = commands.getstatusoutput(
            '/usr/sbin/dmidecode -t memory|grep -e "Size"|grep -ve "No" -ve "Max" -ve "Installed" -ve "Enabled"')
        totolMem = 0
        for mem in output.split('\n'):
            if len(mem)>0:
                totolMem += int(mem.split()[1])
        return ('Totol Memery:%d MB\n' % totolMem) + output, totolMem

    @staticmethod
    def getServerCPU():
        status, output = commands.getstatusoutput('/usr/bin/cat /proc/cpuinfo | grep "model name"')
        cpuName = output.split('\n')[0].split(':')[1].strip()
        cores = output.split('\n').__len__()
        return cpuName + ' %d Cores' % cores, cores

    @staticmethod
    def getServerNIC():
        status, output = commands.getstatusoutput('/usr/bin/nmcli device |grep -ve DEVICE -ve lo -ve vir|cut -d" " -f1')
        nicdevlist = output.strip().split('\n')
        niclist = {}
        for nic in nicdevlist:
            mac = ''
            ipaddr = ''
            gateway = ''
            niclist[nic] = {}
            status, output = commands.getstatusoutput('/usr/bin/nmcli device show %s' % nic)
            for line in output.split('\n'):
                if ('HWADDR' in line) & (len(line.split()) > 1):
                    mac = line.split()[1].strip()
                if ('IP4.ADDRESS[1]' in line) & (len(line.split()) > 1):
                    ipaddr = line.split()[1].strip()
                if ('IP4.GATEWAY' in line) & (len(line.split()) > 1):
                    gateway = line.split()[1].strip()
            niclist[nic]['ipaddr'] = ipaddr
            niclist[nic]['mac'] = mac
            niclist[nic]['gateway'] = gateway
        result = ''
        for nic in nicdevlist:
            result += (nic + ':' + ' mac:' + niclist[nic]['mac'] + ' ipaddr:' + niclist[nic]['ipaddr'] + ' gateway:' +
                       niclist[nic]['gateway'] + '\r\n')
        return result

    @staticmethod
    def getServerIPMI():
        if os.path.exists('/dev/ipmi0') | os.path.exists('/dev/ipmi/0') | os.path.exists('/dev/ipmidev/0'):
            status, output = commands.getstatusoutput('/usr/bin/rpm -q ipmitool')
            logging.debug(output)
            if status == 0:
                status, output = commands.getstatusoutput('/usr/bin/ipmitool -I open lan print')
                return output
            else:
                logging.error('Can not find the ipmitool!')
        else:
            logging.error(
                'Could not open device at /dev/ipmi0 or /dev/ipmi/0 or /dev/ipmidev/0: No such file or directory')
        return ''

    @staticmethod
    def getServerDetail():
        return (NOTESTR +
                '================================================================================\r\n'
                'CPU INFO'
                '\n================================================================================\r\n'
                + Server.getServerCPU()[0] +
                '\n================================================================================\r\n'
                'MEM INFO'
                '\n================================================================================\r\n'
                + Server.getServerMem()[0] +
                '\n================================================================================\r\n'
                'SWAP INFO'
                '\n================================================================================\r\n'
                + Server.getServerSwap()[0] +
                '\n================================================================================\r\n'
                'DISK INFO'
                '\n================================================================================\r\n'
                + Server.getServerDisk() +
                '\n================================================================================\r\n'
                'NETWORK INTERFACE INFO'
                '\n================================================================================\r\n'
                + Server.getServerNIC() +
                '================================================================================\r\n'
                'IPMI INTERFACE INFO'
                '\n================================================================================\r\n'
                + Server.getServerIPMI() +
                '\n================================================================================\r\n'
                'SERVICE STATUS'
                '\n================================================================================\r\n'
                + Server.getServiceStatus() +
                '================================================================================\r\n'
                'SELINUX STATUS'
                '\n================================================================================\r\n'
                + Server.getSELINUXStatus() +
                '\n================================================================================\r\n'
                'DEFAULT RUN LEVEL'
                '\n================================================================================\r\n'
                + Server.getDefaultTarget() +
                '\n================================================================================\n\n'
                )

    def initHostname(self):
        if self.hostname is '':
            logging.error('{funName}: Configure is not been loaded!!!'.format(funName=sys._getframe().f_code.co_name))
            return
        if os.path.exists(self.HOSTNAMEFILE):
            logging.info('Configing server hostname: {hostname}'.format(hostname=self.hostname))
            status, output = commands.getstatusoutput(
                '/usr/bin/mv %s %s' % (self.HOSTNAMEFILE, self.HOSTNAMEFILE + '.bak%s' % timestamp()))
            logging.debug(output)
        #status, output = commands.getstatusoutput('/usr/bin/hostname {0:s}'.format(self.hostname))
        status, output = commands.getstatusoutput('/usr/bin/hostnamectl set-hostname --static {0:s}'.format(self.hostname))
        logging.debug(output)
        
        with open(self.HOSTNAMEFILE, 'w') as hostnamefile:
            hostnamefile.write(self.hostname + '\r\n')
        

    def initUdevRule(self):
        if (self.udevstr is '') | (self.interfaces is None):
            logging.error('{funName}: Configure is not been loaded!!!'.format(funName=sys._getframe().f_code.co_name))
            return
        # if os.path.exists(self.UDEVRULEFILE):
        #   status, output = commands.getstatusoutput(
        #        '/usr/bin/mv %s %s' % (self.UDEVRULEFILE, self.UDEVRULEFILE + '.bak%s' % timestamp()))
        #    logging.debug(output)
        logging.info('Configure udev rule file: {udevrule}'.format(udevrule=self.udevstr))
        with open(self.UDEVRULEFILE, 'w') as udevfile:
            udevfile.write(self.udevstr)

    def initIfCfgFile(self):
        if self.interfaces is None:
            logging.error('{funName}: Configure is not been loaded!!!'.format(funName=sys._getframe().f_code.co_name))
            return
        logging.info('Clear current network configure file...')
        ifcfglist = commands.getoutput('/usr/bin/ls /etc/sysconfig/network-scripts/ifcfg-*').strip('\n').split()
        for cfgfile in ifcfglist:
            if 'ifcfg-lo' in cfgfile: continue
            output = commands.getoutput('/usr/bin/rm -f {cfgfile}'.format(cfgfile=cfgfile))
            logging.debug(output)
        for interface in self.interfaces.values():
            interface.setIfcfgFile()

    def disableSELINUX(self):
        logging.info('Disabling SELINUX...')
        status, output = commands.getstatusoutput('/usr/sbin/getenforce')
        if output != 'Disabled':
            status, output = commands.getstatusoutput(
                '/usr/bin/sed -i "s/SELINUX=enforcing/SELINUX=disabled/g" /etc/selinux/config')
            logging.debug(output)

    def disableService(self, servicelist=None):
        if servicelist is None:
            servicelist = ['iptables', 'firewalld', 'kdump', 'bluetooth', 'cups']
        for service in servicelist:
            logging.info('Disabling service: {servicename}'.format(servicename=service))
            status, output = commands.getstatusoutput(
                '/usr/bin/systemctl stop {servicename}'.format(servicename=service))
            logging.debug(output)
            status, output = commands.getstatusoutput(
                '/usr/bin/systemctl disable {servicename}'.format(servicename=service))
            logging.debug(output)

    @staticmethod
    def getServiceStatus(servicelist=None):
        if servicelist is None:
            servicelist = ['iptables', 'firewalld', 'kdump', '^NetworkManager.service']
        result = ''
        for service in servicelist:
            status, output = commands.getstatusoutput(
                '/usr/bin/systemctl list-unit-files --type=service|grep -e {servicename}'.format(servicename=service))
            result += output + '\n'
        return result

    @staticmethod
    def getSELINUXStatus():
        return commands.getoutput('/usr/sbin/getenforce')

    @staticmethod
    def getDefaultTarget():
        return commands.getoutput('/usr/bin/systemctl get-default')

    @staticmethod
    def getNIClist():
        status, output = commands.getstatusoutput('/usr/bin/nmcli device |grep -ve DEVICE -ve lo -ve vir|cut -d" " -f1')
        nicdevlist = output.strip().split('\n')
        niclist = {}
        for nic in nicdevlist:
            mac = ''
            niclist[nic] = {}
            status, output = commands.getstatusoutput('/usr/bin/nmcli device show %s' % nic)
            for line in output.split('\n'):
                if ('HWADDR' in line) & (len(line.split()) > 1):
                    mac = line.split()[1].strip()
            niclist[nic]['mac'] = mac
        result = ''
        for nic in nicdevlist:
            result += (' {nicname}({mac})').format(nicname=nic, mac=niclist[nic]['mac'])
        return result

    @staticmethod
    def getServerAddr(ifname='eth0'):
        return Server.getNICFiled(filedname='IP4.ADDRESS', ifname=ifname)

    @staticmethod
    def getIfMac(ifname):
        return Server.getNICFiled(filedname='GENERAL.HWADDR', ifname=ifname)

    @staticmethod
    def getNICFiled(filedname, ifname):
        status, output = commands.getstatusoutput('/usr/bin/nmcli device show %s' % ifname)
        for line in output.split('\n'):
            if (filedname in line) & (len(line.split()) > 1):
                return line.split()[1].strip()

    @staticmethod
    def getHostname():
        return commands.getoutput('/usr/bin/hostname').strip()

    def initDefaultSystemTarget(self, target='multi-user'):
        '''
        setup system default running level
        :param target: multi-user(text-mode) or graphical, default is multi-user
        :return: None
        '''
        if target in ['multi-user', 'graphical']:
            logging.info('Configure defualt run-level to :{targetname}'.format(targetname=target))
            status, output = commands.getstatusoutput(
                '/usr/bin/systemctl set-default {targetname}'.format(targetname=target))
            logging.debug(output)
        else:
            logging.error('Wrong target name')

    def initSetup(self):
        self.initHostname()
        #self.initNTPService()
        #self.initSNMPService()
        self.initUdevRule()
        self.initIfCfgFile()
        self.initDefaultSystemTarget('multi-user')
        #self.initIPMIService()
        self.disableSELINUX()
        self.disableService()

    @staticmethod
    def selfCheck(selfcheckfile=SELFCHECKLOG):
        logging.info('Generating self check result ...')
        result = (bracket(timestamp('%Y/%m/%d %H:%M:%S')) + ','
                  + bracket(Server.getSerialNo()) + ','
                  + bracket(Server.getServerAddr()) + ','
                  + bracket(Server.getHostname()) + ','
                  + bracket(platform.platform()) + ','
                  + bracket(Server.getServerNIC()) + ','
                  + bracket(Server.getServerIPMI()) + ','
                  + bracket(Server.getServerCPU()[0]) + ','
                  + bracket(Server.getServerMem()[0]) + ','
                  + bracket(Server.getServerSwap()[0]) + ','
                  + bracket(Server.getServerDisk()) + ','
                  + bracket(Server.getDefaultTarget()) + ','
                  + bracket(Server.getSELINUXStatus()) + ','
                  + bracket(Server.getServiceStatus()) + '\r\n'
                  )
        logging.debug(result)
        with open(selfcheckfile, 'a') as f:
            f.write(result)
            logging.info('Self check result had been write to file:{filename}'.format(filename=selfcheckfile))
        return result

    def __init__(self, configFile=CONFIGFILE):
        self.serialNo = self.getSerialNo()
        self.interfaces = {}
        if os.path.exists(configFile):
            found = False
            with open(configFile, 'r') as f:
                for line in f.readlines():
                    if line.strip() == '': continue
                    if line[0] == '#':
                        continue
                    items = line.strip().split(',')
                    if self.serialNo in items[0]:
                        try:
                            if self.hostname is '':
                                self.hostname = items[1]
                            if self.ntpserver is '':
                                self.ntpserver = items[2]
                            self.interfaces[items[4]] = NIC(ifname=items[4], ipaddr=items[5], netmask=items[6],  
                                                    gateway=items[7], pathname=items[3])  
                            found = True
                        except Exception as e:
                            logging.error(e.message)
                            continue
                if not found:
                    logging.error('CAN NOT FOUND THE SERVER CONFIG!!!')
                    exit()
            self.udevstr = UDEVRULETEMPLATE
            for interface in self.interfaces.values():
                self.udevstr += interface.ifUdevRule

            msg = 'NIC:{niclist} - HOSTNAME:{hostname} - NTPSERVER:{ntpserver}'.format(niclist=self.getNIClist(),
                                                                                       hostname=self.hostname,
                                                                                       ntpserver=self.ntpserver)
            for interface in self.interfaces.values():
                msg += ' - ' + interface.__str__()
            logging.info('LOAD SERVICE CONFIG DONE - ' + msg)
        else:
            logging.error('CAN NOT FOUND THE Config file: {configfile}'.format(configfile=configFile))
            exit()



    def __str__(self):
        result = self.getServerDetail()
        # for interface in self.interfaces.values():
        #     result += interface.__str__()
        return result


if __name__ == '__main__':

    initLogging()
    try:
        options, cmd = getopt.getopt(sys.argv[1:], "h",
                                     ['help'])
        for option, value in options:
            if (option in ('-h', '--help')) or cmd == []:
                Usage()
                sys.exit()
            elif (option in ('-l', '--log==')):
                LOGFILE = value

        if len(cmd) < 1:
            Usage()
            sys.exit(-1)

        if cmd[0] == 'selfcheck':
            if len(cmd) == 2:
                Server.selfCheck(cmd[1])
            else:
                Server.selfCheck()
        elif cmd[0] == 'initsetup':
            serv1 = Server()
            if len(cmd) == 2:
                serv1.initSetup(cmd[1])
            else:
                serv1.initSetup()

    except getopt.GetoptError:
        Usage()
        sys.exit(-1)
