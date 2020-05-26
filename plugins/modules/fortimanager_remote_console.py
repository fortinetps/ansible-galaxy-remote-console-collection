#!/usr/bin/python
#
# Ansible module to manage fortimanager devices through remote console access
# (c) 2019, Don Yao <@fortinetps>
# GNU General Public License v3.0+ (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: fortimanager_remote_console
short_description: FortiManager Remote Console Module
version_added: "2.7"
description:
    - "This is fortimanager_remote_console module, for FortiManager console access through remote console server (Cisco, Avocent, Raritan, MRV, ...)"
author:
    - Don Yao (@fortinetps)

notes:
    - Tested against FortiManager-501E v5.6.5 with Avocent ACS8000 and MRV LX4032
    - Only works with physical FortiManager appliance with serial console port
    - This module is good for FortiManager without network conneciton, but with remote console connection (OOB)
    - Or some action may cause FortiManager lose it is network connectivity, but OOB remote console connection stays
    - Use this module to factoryreset FortiManager
    - Use this module to bootstrap brand new FortiManager
    - Use this module to perform low level erase-disk

options:
    config:
        description:
            - Configuration to be backup
        required: true
        type: dict
        suboptions:
            filename:
                description:
                    - Configuration filename
                required: true
'''
EXAMPLES = '''
---
name: backup config
tags:
- hostname
fortios_api_system_config_restore:
  conn_params:
    fortimanager_username: admin
    fortimanager_password: test
    fortimanager_ip: 1.2.3.4
    verify: false
  config:
  - filename: /firmware/backup_config.conf

'''

RETURN = '''
result:
    description: k/v pairs of firmware upgrade result
    returned: always
    type: dict
'''

import re
import time
import pexpect
import datetime

from ansible.module_utils.basic import AnsibleModule


class fortimanager_remote_console():
    def __init__(self, rcs_ip, rcs_username, rcs_password, rcs_fmg_username='admin', rcs_fmg_password='',
                 rcs_fmg_port=None, rcs_fmg_cli=None, rcs_fmg_become=None, rcs_timeout=None):
        self.rcs_ip = rcs_ip
        self.rcs_username = rcs_username
        self.rcs_password = rcs_password
        self.rcs_fmg_port = rcs_fmg_port
        self.rcs_fmg_username = rcs_fmg_username
        self.rcs_fmg_password = rcs_fmg_password
        self.rcs_fmg_cli = rcs_fmg_cli
        self.rcs_fmg_become = rcs_fmg_become
        self.rcs_timeout = rcs_timeout

        self.rcs_prompt = None          # CLI prompt for remote console server (rcs) itself
        self.rcs_console = None         # Remote Console connection (for console access)
        self.rcs_fmg_prompt = None      # CLI prompt for device (FGT) connected to the remote console port

        self.serial = None
        self.version = None
        self.factorydefault = None

    ############################################################################
    def fortimanager_remote_console_cli(self):
        outputs = []
        rcs_result = {}
        rcs_result['status'] = 1
        rcs_result['changed'] = False

        try:
            output = self.fortimanager_remote_console_login()
            # outputs.append(output)
            if self.rcs_console.terminated:
                raise Exception("Problem with remote console connection, please check settings, and try 'ssh %s -p %s'.\n Error: %s"
                                % (self.rcs_ip, self.rcs_fmg_port, output))

            # for each command
            for command in self.rcs_fmg_cli[0].splitlines():
                self.rcs_console.sendline(command)
                time.sleep(len(command)*8*5/9600)
                index = self.rcs_console.expect(self.rcs_fmg_prompt)
                output = self.rcs_console.before.decode('utf8').splitlines()
                outputs.append(output)

                if index == 2:    # with this, it seems like hostname was changed in the middle of the command (mostly by set hostname)
                    hostname = self.rcs_console.before.decode('utf-8').splitlines()[-1].split(' ')[0]
                    # the first split find the last line, which contains the hostname
                    # the second split, in case FortiManager is inside configuration section or in global/vdom, FortiManager doesn't allow space in hostname
                    # update the hostname
                    self.rcs_fmg_prompt = ['dummy_placeholder', hostname + ' # ', ' # ', r'\(.+\)# ', ' login: ', 'to accept']

                elif index == 4 or index == 5:    # with this, it seems like password was changed in the middle of the command (mostly by set password)
                    # simple close the connection and return
                    outputs.append('It seems like password was changed in the middle of the console cli command execution')
                    self.rcs_console.close()
                    self.rcs_console = None
                    break

            rcs_result['status'] = 0
            rcs_result['changed'] = True

        except Exception as error:
            outputs.append(str(error).splitlines())

        finally:
            if self.rcs_console and not self.rcs_console.terminated:
                self.fortimanager_remote_console_logout()
            rcs_result['console_action_result'] = outputs
            return rcs_result

    ############################################################################
    def fortimanager_remote_console_reboot(self):
        outputs = []
        rcs_result = {}
        rcs_result['status'] = 1
        rcs_result['changed'] = False

        try:
            output = self.fortimanager_remote_console_login()
            # outputs.append(output)
            if self.rcs_console.terminated:
                raise Exception("Problem with remote console connection, please check settings, and try 'ssh %s -p %s'.\n Error: %s"
                                % (self.rcs_ip, self.rcs_fmg_port, output))

            self.rcs_console.sendline('config global')    # if FortiManager has VDOM enabled, if not, this will generate an message, but won't cause any problem
            self.rcs_console.expect(self.rcs_fmg_prompt)

            # send exec factoryreset command
            self.rcs_console.sendline('exec reboot')
            self.rcs_console.expect([r'Do you want to continue\? \(y\/n\)'])
            output = self.rcs_console.before.decode('utf8').splitlines()
            outputs.append(output)

            # send 'y' to confirm
            self.rcs_console.send('y')

            # factoryreset reboots device, and it could reboot more than once
            index = 0
            while index != 1 and index != 2:
                index = self.rcs_console.expect(['dummy_placeholder', 'to accept', ' login: ', 'System is starting', 'please wait for reboot'], timeout=1800)
                output = self.rcs_console.before.decode('utf8').splitlines()
                outputs.append(output)

                if index == 3:
                    wait_for_reboot = False     # reset wait_for_reboot flag
                if index == 4:
                    wait_for_reboot = True      # we received "please wait for reboot" message
                if index == 1 or index == 2:
                    if wait_for_reboot:         # skip this login prompt
                        index = 0   # reset the index
                        continue

            rcs_result['status'] = 0
            rcs_result['changed'] = True

        except Exception as error:
            outputs.append(str(error).splitlines())

        finally:
            if self.rcs_console and not self.rcs_console.terminated:
                self.fortimanager_remote_console_logout()
            rcs_result['console_action_result'] = outputs
            return rcs_result

    ############################################################################
    def fortimanager_remote_console_factoryreset(self):
        outputs = []
        rcs_result = {}
        rcs_result['status'] = 1
        rcs_result['changed'] = False

        try:
            output = self.fortimanager_remote_console_login()
            # outputs.append(output)
            if self.rcs_console.terminated:
                raise Exception("Problem with remote console connection, please check settings, and try 'ssh %s -p %s'.\n Error: %s"
                                % (self.rcs_ip, self.rcs_fmg_port, output))

            self.rcs_console.sendline('config global')    # if FortiManager has VDOM enabled, if not, this will generate an message, but won't cause any problem
            self.rcs_console.expect(self.rcs_fmg_prompt)

            # send exec factoryreset command
            if self.serial.find('FGVM') == 0:
                self.rcs_console.sendline('exec factoryreset keepvmlicense')
            else:
                self.rcs_console.sendline('exec factoryreset')
            self.rcs_console.expect([r'Do you want to continue\? \(y\/n\)'])
            output = self.rcs_console.before.decode('utf8').splitlines()
            outputs.append(output)

            # send 'y' to confirm
            self.rcs_console.send('y')

            # factoryreset reboots device, and it could reboot more than once
            index = 0
            wait_for_reboot = True
            while index != 1:
                index = self.rcs_console.expect(['dummy_placeholder', ' login: ', 'System is starting', 'please wait for reboot'], timeout=1800)
                output = self.rcs_console.before.decode('utf8').splitlines()
                outputs.append(output)

                if index == 2:
                    wait_for_reboot = False     # reset wait_for_reboot flag
                elif index == 3:
                    wait_for_reboot = True      # we received "please wait for reboot" message
                elif index == 1:
                    if wait_for_reboot:         # skip this login prompt
                        time.sleep(1)
                        index = 0   # reset the index
                        continue

            rcs_result['status'] = 0
            rcs_result['changed'] = True

        except Exception as error:
            outputs.append(str(error).splitlines())

        finally:
            if self.rcs_console and not self.rcs_console.terminated:
                self.fortimanager_remote_console_logout()
            rcs_result['console_action_result'] = outputs
            return rcs_result

    ############################################################################
    def fortimanager_remote_console_erasedisk(self):
        outputs = []
        rcs_result = {}
        rcs_result['status'] = 1    # preset rcs_outlet_port is invalid
        rcs_result['changed'] = False

        try:
            output = self.fortimanager_remote_console_login()
            # outputs.append(output)
            if self.rcs_console.terminated:
                raise Exception("Problem with remote console connection, please check settings, and try 'ssh %s -p %s'.\n Error: %s"
                                % (self.rcs_ip, self.rcs_fmg_port, output))

            self.rcs_console.sendline('config global')    # if FortiManager has VDOM enabled, if not, this will generate an message, but won't cause any problem
            self.rcs_console.expect(self.rcs_fmg_prompt)

            # send exec erase-disk command
            self.rcs_console.send('exec erase-disk ?')      # use send, not sendline here
            self.rcs_console.expect([r'exec erase\-disk'])   # the 1st time expects the command echo
            self.rcs_console.expect([r'exec erase\-disk'])   # the 2nd time expects the real outpout, which will prompot list of disks on your FGT system
            output = self.rcs_console.before.decode('utf8').splitlines()
            outputs.append(output)

            # logout here now
            self.fortimanager_remote_console_logout()

            # remove the empty line: if disk.strip()
            # remove the last line: output[0:-2], since the last line is cli prompt
            # remove the " (boot)": disk.strip().split(' ')[0]
            list_disk = [disk.decode('utf-8').strip().split(' ')[0] for disk in output[0:-2] if disk.strip()]

            # every erasedisk would reboot the FortiManager
            for disk in list_disk:
                self.fortimanager_remote_console_login()
                self.rcs_console.sendline('config global')  # if FortiManager has VDOM enabled, if not, this will generate an message, but won't cause any problem
                self.rcs_console.expect(self.rcs_fmg_prompt)

                self.rcs_console.sendline('exec erase-disk ' + disk)
                self.rcs_console.expect(r'Are you sure you want to proceed\? \(y\/n\)')
                output = self.rcs_console.before.decode('utf8').splitlines()
                outputs.append(output)

                # send 'y' to confirm
                self.rcs_console.sendline('y')
                self.rcs_console.expect(r'How many times do you wish to overwrite the media\?')
                output = self.rcs_console.before.decode('utf8').splitlines()
                outputs.append(output)

                # erase # of times
                # erase-disk could take few hours for each round, please adjust this number
                # this version will be hardcoded to 1 time, will make it adjustable in next release
                self.rcs_console.sendline('1')

                if disk == 'SYSTEM':
                    self.rcs_console.expect(r'Do you want to restore the image after erasing\? \(y\/n\)')
                    output = self.rcs_console.before.decode('utf8').splitlines()
                    outputs.append(output)
                    self.rcs_console.sendline('n')

                outputs.append('WARNING:')
                outputs.append('erase-disk starts running on ' + disk)
                outputs.append('This will permanently erase all data from the storage media.')
                outputs.append('Please do not unplug or turn off FortiManager and wait')

                start_time = datetime.datetime.now()

                if disk != 'SYSTEM':
                    # here we need to deal with some exception, sometime FortiManager doesn't like the erase-disk on data disk
                    # it will reboot and reformat the data disk, which multiple reboots could happend
                    # if we see "please wait for reboot" before the login prompt, we will skip the login prompt

                    # some remote console server also support remote power functions (poweron/poweroff/reset)
                    # for testing purpose, reboot FortiManager 20 seconds after erase-disk starts
                    # comment the follow lines in production
                    # outputs.append('for testing purpose, reboot FortiManager 20 seconds after erase-disk starts')
                    # time.sleep(20)
                    # self.rcs_outlet_reboot()

                    index = 0
                    while index != 1 and index != 2:
                        index = self.rcs_console.expect(['dummy_placeholder', 'to accept', ' login: ', 'System is starting', 'please wait for reboot'],
                                                        timeout=7200)
                        output = self.rcs_console.before.decode('utf8').splitlines()
                        outputs.append(output)

                        if index == 3:
                            wait_for_reboot = False     # reset wait_for_reboot flag
                        if index == 4:
                            wait_for_reboot = True      # we received "please wait for reboot" message
                        if index == 1 or index == 2:
                            if wait_for_reboot:         # skip this login prompt
                                index = 0   # reset the index
                                continue
                            else:
                                erase_time = datetime.datetime.now() - start_time
                                minutes = int(erase_time.total_seconds() / 60)
                                outputs.append('erase-disk finish running on ' + disk)
                                outputs.append('erase-disk finish in ' + str(minutes) + ' minutes')
                                rcs_result['changed'] = True
                else:
                    self.rcs_console.expect(['You must format the boot device'], timeout=7200)  # erase-disk could take few hours, please adjust this number
                    output = self.rcs_console.before.decode('utf8').splitlines()
                    outputs.append(output)

                    erase_time = datetime.datetime.now() - start_time
                    minutes = int(erase_time.total_seconds() / 60)
                    outputs.append('erase-disk finish running on ' + disk)
                    outputs.append('erase-disk finish in ' + str(minutes) + ' minutes')
                    rcs_result['changed'] = True

            rcs_result['status'] = 0

        except Exception as error:
            outputs.append(str(error).splitlines())

        finally:
            if self.rcs_console and not self.rcs_console.terminated:
                self.fortimanager_remote_console_logout()
            rcs_result['console_action_result'] = outputs
            return rcs_result

    ############################################################################
    def fortimanager_remote_console_diskformat(self):
        outputs = []
        rcs_result = {}
        rcs_result['status'] = 1    # preset rcs_outlet_port is invalid
        rcs_result['changed'] = False

        try:
            output = self.fortimanager_remote_console_login()
            # outputs.append(output)
            if self.rcs_console.terminated:
                raise Exception("Problem with remote console connection, please check settings, and try 'ssh %s -p %s'.\n Error: %s"
                                % (self.rcs_ip, self.rcs_fmg_port, output))

            self.rcs_console.sendline('config global')    # if FortiManager has VDOM enabled, if not, this will generate an message, but won't cause any problem
            self.rcs_console.expect(self.rcs_fmg_prompt)

            # send exec disk list command and parse the output
            self.rcs_console.sendline('exec disk list')
            self.rcs_console.expect(self.rcs_fmg_prompt)
            output = self.rcs_console.before.decode('utf8').splitlines()
            outputs.append(output)

            # logout for now
            self.fortimanager_remote_console_logout()

            # remove the empty line: if info.strip()
            # remove the last line: output[0:-2], since the last line is cli prompt
            list_info = [info.strip() for info in output[0:-1] if info.strip()]

            disks = []
            for info in list_info:
                disk_ref_search = re.search(r'^Disk (\S+) +ref: +(\d+) .+', info)
                part_ref_search = re.search(r'^partition ref: +(\d+) .+', info)
                if disk_ref_search is not None:     # found new disk
                    disk = {}
                    disk['name'] = disk_ref_search.group(1)
                    disk['ref'] = disk_ref_search.group(2)
                    disk['partition'] = []
                    disks.append(disk)
                elif part_ref_search is not None:   # found new partition
                    disk['partition'].append(part_ref_search.group(1))
            rcs_result['disks'] = disks

            # we need to format disk without any partition
            zero_partition_disk = []
            for disk in disks:
                if len(disk['partition']) == 0:
                    zero_partition_disk.append(disk)

            if len(zero_partition_disk) != 0:
                # every disk format would reboot the FortiManager, we only need to format those disk without partition
                for disk in zero_partition_disk:
                    self.fortimanager_remote_console_login()
                    # if FortiManager has VDOM enabled, if not, this will generate an message, but won't cause any problem
                    self.rcs_console.sendline('config global')
                    self.rcs_console.expect(self.rcs_fmg_prompt)

                    self.rcs_console.sendline('exec disk format ' + disk['ref'])
                    self.rcs_console.expect(r'Do you want to continue\? \(y\/n\)')
                    output = self.rcs_console.before.decode('utf8').splitlines()
                    outputs.append(output)

                    # send 'y' to confirm
                    self.rcs_console.send('y')
                    # print('disk format starts running on ' + disk['name'])

                    # diskformat will reboot the device, we are now waiting for the device comes back
                    index = 0
                    while index != 1 and index != 2:
                        index = self.rcs_console.expect(['dummy_placeholder', 'to accept', ' login: ', 'System is starting', 'please wait for reboot'],
                                                        timeout=7200)
                        output = self.rcs_console.before.decode('utf8').splitlines()
                        outputs.append(output)

                        if index == 3:
                            wait_for_reboot = False     # reset wait_for_reboot flag
                        if index == 4:
                            wait_for_reboot = True      # we received "please wait for reboot" message
                        if index == 1 or index == 2:
                            if wait_for_reboot:         # skip this login prompt
                                index = 0   # reset the index
                                continue
                            else:
                                # print('disk format finished on ' + disk['name'])
                                rcs_result['changed'] = True

            rcs_result['status'] = 0

        except Exception as error:
            outputs.append(str(error).splitlines())

        finally:
            if self.rcs_console and not self.rcs_console.terminated:
                self.fortimanager_remote_console_logout()
            rcs_result['console_action_result'] = outputs
            return rcs_result

    ############################################################################
    def fortimanager_remote_console_restoreimage(self):
        outputs = []
        rcs_result = {}
        rcs_result['status'] = 1    # preset rcs_outlet_port is invalid
        rcs_result['changed'] = False

        try:
            output = self.fortimanager_remote_console_login()
            # outputs.append(output)
            if self.rcs_console.terminated:
                raise Exception("Problem with remote console connection, please check settings, and try 'ssh %s -p %s'.\n Error: %s"
                                % (self.rcs_ip, self.rcs_fmg_port, output))

            self.rcs_console.sendline('config global')    # if FortiManager has VDOM enabled, if not, this will generate an message, but won't cause any problem
            self.rcs_console.expect(self.rcs_fmg_prompt)

            # send exec factoryreset command
            self.rcs_console.sendline('exec reboot')
            self.rcs_console.expect([r'Do you want to continue\? \(y\/n\)'])
            output = self.rcs_console.before.decode('utf8').splitlines()
            outputs.append(output)

            # send 'y' to confirm
            self.rcs_console.send('y')

            # then on remote console port, wait/expect see the boot menu for TFTP
            # the following are FGT specific, lots of hard coded params just for my lab
            # in order to make it work for production, we need to parameterize these settings
            self.rcs_console.expect([r'Press any key to display configuration menu\.\.\.'], timeout=300)
            output = self.rcs_console.before.decode('utf8').splitlines()
            outputs.append(output)
            time.sleep(1)

            self.rcs_console.sendline('')
            self.rcs_console.expect(['Enter .+:'])
            output = self.rcs_console.before.decode('utf8').splitlines()
            outputs.append(output)

            self.rcs_console.send('C')  # [C]:  Configure TFTP parameters.
            self.rcs_console.expect(['Enter .+:'])
            output = self.rcs_console.before.decode('utf8').splitlines()
            outputs.append(output)

            tftp_params = self.rcs_fmg_cli[0].splitlines()
            tftp_local_ip = tftp_params[0].replace('"', '')
            tftp_local_netmask = tftp_params[1].replace('"', '')
            tftp_local_gw = tftp_params[2].replace('"', '')
            tftp_server_ip = tftp_params[3].replace('"', '')
            tftp_image_file = tftp_params[4].replace('"', '')

            self.rcs_console.send('I')  # [I]:  Set local IP address.
            # self.rcs_console.sendline('192.168.210.'+str(int((int(self.rcs_fmg_port)/100))))
            self.rcs_console.sendline(tftp_local_ip)
            time.sleep(1)
            self.rcs_console.expect(['Enter .+:'])
            output = self.rcs_console.before.decode('utf8').splitlines()
            outputs.append(output)

            self.rcs_console.send('S')  # [S]:  Set local subnet mask.
            # self.rcs_console.sendline('255.255.255.0')
            self.rcs_console.sendline(tftp_local_netmask)
            time.sleep(1)
            self.rcs_console.expect(['Enter .+:'])
            output = self.rcs_console.before.decode('utf8').splitlines()
            outputs.append(output)

            self.rcs_console.send('G')  # [G]:  Set local gateway.
            # self.rcs_console.sendline('192.168.210.1')
            self.rcs_console.sendline(tftp_local_gw)
            time.sleep(1)
            self.rcs_console.expect(['Enter .+:'])
            output = self.rcs_console.before.decode('utf8').splitlines()
            outputs.append(output)

            self.rcs_console.send('T')  # [T]:  Set remote TFTP server IP address.
            # self.rcs_console.sendline('192.168.210.252')
            self.rcs_console.sendline(tftp_server_ip)
            time.sleep(1)
            self.rcs_console.expect(['Enter .+:'])
            output = self.rcs_console.before.decode('utf8').splitlines()
            outputs.append(output)

            self.rcs_console.send('F')  # [F]:  Set firmware image file name.
            time.sleep(1)
            # self.rcs_console.sendline('/firmware/FGT_501E-v5-build1600-FORTINET.out')
            self.rcs_console.sendline(tftp_image_file)
            time.sleep(2)
            self.rcs_console.expect(['Enter .+:'])
            output = self.rcs_console.before.decode('utf8').splitlines()
            outputs.append(output)

            self.rcs_console.send('R')  # [R]:  Review TFTP parameters.
            time.sleep(1)
            self.rcs_console.expect(['Enter .+:'])
            output = self.rcs_console.before.decode('utf8').splitlines()
            outputs.append(output)

            self.rcs_console.send('Q')  # [Q]:  Quit this menu.
            time.sleep(1)
            self.rcs_console.expect(['Enter .+:'])
            output = self.rcs_console.before.decode('utf8').splitlines()
            outputs.append(output)

            self.rcs_console.send('T')  # [T]:  Initiate TFTP firmware transfer.
            time.sleep(1)
            self.rcs_console.expect(r'Save as Default firmware\/Backup firmware\/Run image without saving:\[D\/B\/R\]\?', timeout=300)
            self.rcs_console.send('D')

            # after firmware image downloadeded and flashed, it reboots, and it could reboot more than once
            index = 0
            while index != 1:
                index = self.rcs_console.expect(['dummy_placeholder', ' login: ', 'System is starting', 'please wait for reboot'], timeout=1800)
                output = self.rcs_console.before.decode('utf8').splitlines()
                outputs.append(output)

                if index == 2:
                    wait_for_reboot = False     # reset wait_for_reboot flag
                if index == 3:
                    wait_for_reboot = True      # we received "please wait for reboot" message
                if index == 1:
                    if wait_for_reboot:         # skip this login prompt
                        index = 0   # reset the index
                        continue

            rcs_result['status'] = 0
            rcs_result['changed'] = True

        except Exception as error:
            outputs.append(str(error).splitlines())

        finally:
            if self.rcs_console and not self.rcs_console.terminated:
                self.fortimanager_remote_console_logout()
            rcs_result['console_action_result'] = outputs
            return rcs_result

    ############################################################################
    def fortimanager_remote_console_login(self):
        self.factorydefault = False
        outputs = []
        ssh_connection_string = 'ssh %s -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -l %s -p %d'\
                                % (self.rcs_ip, self.rcs_username, self.rcs_fmg_port)

        try:
            index = 1
            attempt = self.rcs_timeout
            while index and attempt:
                # try connect to remote console server
                # expect to see the password prompt
                self.rcs_console = pexpect.spawn(ssh_connection_string)
                index = self.rcs_console.expect(['assword: ', pexpect.EOF, pexpect.TIMEOUT], timeout=60)
                if index:
                    outputs.append('Failed to connect to remote console server ' + str(self.rcs_timeout + 1 - attempt))
                output = self.rcs_console.before.decode('utf8').splitlines()
                outputs.append(output)
                attempt = attempt - 1

            # pexpect.EOF - Raised when EOF is read from a child. This usually means the child has exited.
            # when test with MRV remote console server with max mirror connection = 1, (exclusive access to console port)
            # MRV won't even give you password prompt, it simply returns EOF when it sees another connection attempt
            # For Avocent remote console server, it handle this "non-simultaneous session" differently
            # Avocent remote console server will accept the login first then give user error message
            if index == 1:
                raise Exception('Attemtp to connect to remote console server ' + str(self.rcs_timeout) +
                                ' times, but all failed, please check if remote console port is being used by other user')

            # pexpect.TIMEOUT - Raised when a read time exceeds the timeout.
            # when disconnect remote console server (make it inaccessible) it returns TIMEOUT
            if index == 2:
                raise Exception('Attemtp to connect to remote console server ' + str(self.rcs_timeout) +
                                ' times, but all failed, please check if remote console server is accessible')

            # send remote console server password
            self.rcs_console.sendline(self.rcs_password)

            # in some test environment, I need to run command (rcs_fmg_become) to access the FortiManager context
            if self.rcs_fmg_become:
                # need to read and clear the buffer before we run become command
                self.rcs_console.expect(' # ')
                output = self.rcs_console.before.decode('utf8').splitlines()
                outputs.append(output)
                self.rcs_console.sendline(self.rcs_fmg_become)

            # now we should be in FortiManager context
            # As we tested some Cisco remote console server, they would accespt passowrd but then return message like
            # "This connection is in use. User(s) currently connected: XXXXXXXX."
            # "You need privilege to make a simultaneous session."
            # Then remote console server terminate the connection (EOF)
            index = 0
            while index != 3:
                # send "enter" to FortiManager, FortiManager should spit out something, try to figure out what status/context FortiManager is in
                self.rcs_console.sendline('')
                index = self.rcs_console.expect(['dummy_placeholder', 'to accept', ' login: ', ' # ', r'\(.+\)# ', pexpect.EOF, pexpect.TIMEOUT], timeout=15)
                output = self.rcs_console.before.decode('utf8').splitlines()
                outputs.append(output)
                # option#1(return 0) is not supposed to be matched
                # option#2(return 1) is when FortiManager display the pre-login banner
                # option#3(return 2) is when FortiManager display login (self.rcs_fmg_prompt)
                # option#4(return 3) is when FortiManager is already logged in
                # option#4(return 4) is when FortiManager is already logged in, but left inside some configuration mode (FMG CLI specific)
                # option#5(return 5) is something we are not sure (it seems happens to Cisco remote console server without simutaneous session enabled)
                if index == 1:
                    # see pre-login banner
                    self.rcs_console.sendline('a')                          # press 'a' to accept pre-login banner
                    self.rcs_console.expect(' login: ')
                    output = self.rcs_console.before.decode('utf8').splitlines()
                    outputs.append(output)
                elif index == 2:
                    # see FortiManager login
                    self.rcs_console.sendline(self.rcs_fmg_username)        # this is username for FortiManager login
                    self.rcs_console.expect('assword: ')
                    output = self.rcs_console.before.decode('utf8').splitlines()
                    outputs.append(output)

                    self.rcs_console.sendline(self.rcs_fmg_password)        # this is password for FortiManager login
                    login_index = self.rcs_console.expect([' # ', 'Login incorrect'])
                    output = self.rcs_console.before.decode('utf8').splitlines()
                    outputs.append(output)
                    if login_index:                                         # Login incorrect message
                        # Failed to first login attempt, try use blank password (this could be a factory reset device)
                        # Here we are not suppose to see the login bannder, but just in case
                        self.rcs_console.sendline('')
                        index = self.rcs_console.expect(['dummy_placeholder', 'to accept', ' login: ', ' # ', pexpect.EOF, pexpect.TIMEOUT], timeout=15)
                        output = self.rcs_console.before.decode('utf8').splitlines()
                        outputs.append(output)
                        if index == 1:
                            # see pre-login banner
                            self.rcs_console.sendline('a')                  # press 'a' to accept pre-login banner
                            self.rcs_console.expect(' login: ')
                            output = self.rcs_console.before.decode('utf8').splitlines()
                            outputs.append(output)
                        elif index == 2:
                            self.rcs_console.sendline(self.rcs_fmg_username)    # this is username for FortiManager login
                            self.rcs_console.expect('assword: ')
                            output = self.rcs_console.before.decode('utf8').splitlines()
                            outputs.append(output)
                        self.rcs_console.sendline('')                       # try black password for FortiManager login
                        # with FMG 6.0, factory default device take blank password and login
                        # with FMG 6.2, factory default device take blank password and prompt/force to change/set new password before login
                        index = self.rcs_console.expect([' # ', 'New Password:', pexpect.EOF, pexpect.TIMEOUT], timeout=15)
                        output = self.rcs_console.before.decode('utf8').splitlines()
                        outputs.append(output)
                        if index == 0:  # this is FMG 6.0 factory default behavior
                            self.factorydefault = True
                        elif index == 1:  # this is FMG 6.2 factory default behavior
                            self.rcs_console.sendline(self.rcs_fmg_password)
                            self.rcs_console.expect('Re-enter New Password:')
                            self.rcs_console.sendline(self.rcs_fmg_password)
                            self.rcs_console.expect(' # ')
                            self.factorydefault = True
                        elif index > 1:
                            raise Exception('Attemtp to login to FortiManager failed please check username/password for FortiManager')
                elif index == 4:                                        # with this, we want to figure out the hostname for FortiManager for better expect/match
                    prompt_index = 0
                    while prompt_index != 1:
                        self.rcs_console.sendline('end')
                        prompt_index = self.rcs_console.expect(['dummy_placeholder', ' # ', r'\(.+\)# ', pexpect.EOF, pexpect.TIMEOUT])
                        output = self.rcs_console.before.decode('utf8').splitlines()
                        outputs.append(output)
                elif index == 3:                                        # with this, we want to figure out the hostname for FortiManager for better expect/match
                    hostname = self.rcs_console.before.decode('utf-8').splitlines()[-1].split(' ')[0]
                    # the first split find the last line, which contains the hostname
                    # the second split, in case FortiManager is inside configuration section or in global/vdom, FortiManager doesn't allow space in hostname
                    self.rcs_fmg_prompt = ['dummy_placeholder', hostname + ' # ', ' # ', r'\(.+\)# ', ' login: ', 'to accept']
                # This is to handle Avocent's "non-simultaneous session" access issue
                elif index == 5:                                        # with this, raise exception
                    raise Exception('Attemtp to connect to remote console port but failed, please check if remote console port is being used by other user')
                elif index == 6:                                        # with this, raise exception
                    raise Exception('Attemtp to read/write remote console port but failed, please check if FortiManager is on and console port is connected')

            self.rcs_console.sendline('get system status')
            self.rcs_console.expect(self.rcs_fmg_prompt)
            for line in self.rcs_console.before.decode('utf8').splitlines():
                m = re.search(r'^Version\s+: ', line)
                if m:
                    _, end = m.span()
                    self.version = line[end:]
                    break

            for line in self.rcs_console.before.decode('utf8').splitlines():
                m = re.search(r'^Serial Number\s+: ', line)
                if m:
                    _, end = m.span()
                    self.serial = line[end:]
                    break

            output = self.rcs_console.before.decode('utf8').splitlines()
            outputs.append(output)

        except Exception as error:
            self.rcs_console.close()
            outputs.append(str(error).splitlines())

        finally:
            return outputs

    ############################################################################
    def fortimanager_remote_console_logout(self):
        outputs = []

        # in case FGT console is in the middle of something
        # hit enter first, then use abort to exit out if it is needed
        try:
            prompt_index = 0
            while prompt_index != 1:
                self.rcs_console.sendline('')
                prompt_index = self.rcs_console.expect(self.rcs_fmg_prompt)
                output = self.rcs_console.before.decode('utf8').splitlines()
                outputs.append(output)
                if prompt_index == 2:           # reset FortiManager back root level (self.rcs_fmg_prompt)
                    self.rcs_console.sendline('abort')
                    prompt_index = self.rcs_console.expect(self.rcs_fmg_prompt)
                    output = self.rcs_console.before.decode('utf8').splitlines()
                    outputs.append(output)
                elif prompt_index == 4:         # FGT is not logged in, no need to do anything
                    break

            # then exit to quit login
            if prompt_index == 1:
                self.rcs_console.sendline('exit')
                time.sleep(2)   # need to wait here for some reason

        except Exception as error:
            outputs.append(str(error).splitlines())

        finally:
            if self.rcs_console and not self.rcs_console.terminated:
                self.rcs_console.close()
                self.rcs_console = None
            return outputs


def run_module():
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        rcs_ip=dict(required=True),     # remote console server (rcs) IP address
        rcs_username=dict(type='str', required=True),   # remote console server (rcs) login username
        rcs_password=dict(type='str', required=True, no_log=True),  # remote console server (rcs) login password
        rcs_fmg_username=dict(type='str', required=True),   # FortiManager login username
        rcs_fmg_password=dict(type='str', required=True, no_log=True),  # FortiManager login password
        rcs_fmg_port=dict(type=int, required=True),   # remote console server port which maps to FortiManager console
        rcs_fmg_become=dict(type='str', required=False, default=''),  # some remote console server need to run special command in order to access FGT console
        rcs_fmg_action=dict(choices=['cli', 'factoryreset', 'reboot', 'erasedisk', 'diskformat', 'restoreimage'],
                            type='str', required=False, default='cli'),     # what action perform on FortiManager
        rcs_timeout=dict(type='int', required=False, default=5),  # remote console server (rcs) login timeout (in minute)
        rcs_fmg_cli=dict(type='list', required=False, default=['get system status'])   # which CLI action, put list of CLI (configuration) here
    )

    # seed the result dict in the object
    # we primarily care about changed and state
    # change is if this module effectively modified the target
    # state will include any data that you want your module to pass back
    # for consumption, for example, in a subsequent task
    result = dict(
        changed=False,
        rcs_fmg_action_result={}
    )

    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    # module params check
    # at least one outlet port or console port present
    if module.params['rcs_fmg_port'] is None:
        module.fail_json(msg='rcs_fmg_port needs to be specified', **result)

    _fortimanager_remote_console = fortimanager_remote_console(module.params['rcs_ip'], module.params['rcs_username'], module.params['rcs_password'],
                                                         module.params['rcs_fmg_username'], module.params['rcs_fmg_password'], module.params['rcs_fmg_port'],
                                                         module.params['rcs_fmg_cli'], module.params['rcs_fmg_become'], module.params['rcs_timeout'])
    if module.params['rcs_fmg_action'] is not None:
        # perform restore image on FortiManager, 1) reboot 2) interrupt BIOS 3) restore firmware from TFTP
        if module.params['rcs_fmg_action'] == 'restoreimage':
            console_result = _fortimanager_remote_console.fortimanager_remote_console_restoreimage()
            result['rcs_fmg_action_result'] = console_result['console_action_result']
            result['serial'] = _fortimanager_remote_console.serial
            result['version'] = _fortimanager_remote_console.version
            result['factorydefault'] = _fortimanager_remote_console.factorydefault
            if console_result['status']:
                module.fail_json(msg='Something wrong with rcs_fmg_restoreimage', **result)
                return
            result['changed'] = console_result['changed']
        # perform diskformat on FortiManager CLI
        elif module.params['rcs_fmg_action'] == 'diskformat':
            console_result = _fortimanager_remote_console.fortimanager_remote_console_diskformat()
            result['rcs_fmg_action_result'] = console_result['console_action_result']
            result['serial'] = _fortimanager_remote_console.serial
            result['version'] = _fortimanager_remote_console.version
            result['factorydefault'] = _fortimanager_remote_console.factorydefault
            if console_result['status']:
                module.fail_json(msg='Something wrong with rcs_fmg_diskformat', **result)
                return
            result['disks'] = console_result['disks']
            result['changed'] = console_result['changed']    # a reboot action is always has changed = True
        # perform factoryreset on FortiManager CLI
        elif module.params['rcs_fmg_action'] == 'factoryreset':
            console_result = _fortimanager_remote_console.fortimanager_remote_console_factoryreset()
            result['rcs_fmg_action_result'] = console_result['console_action_result']
            result['serial'] = _fortimanager_remote_console.serial
            result['version'] = _fortimanager_remote_console.version
            result['factorydefault'] = _fortimanager_remote_console.factorydefault
            if console_result['status']:
                module.fail_json(msg='Something wrong with rcs_fmg_factoryreset', **result)
                return
            result['changed'] = console_result['changed']
        # perform reboot on FortiManager CLI
        elif module.params['rcs_fmg_action'] == 'reboot':
            console_result = _fortimanager_remote_console.fortimanager_remote_console_reboot()
            result['rcs_fmg_action_result'] = console_result['console_action_result']
            result['serial'] = _fortimanager_remote_console.serial
            result['version'] = _fortimanager_remote_console.version
            result['factorydefault'] = _fortimanager_remote_console.factorydefault
            if console_result['status']:
                module.fail_json(msg='Something wrong with rcs_fmg_reboot', **result)
                return
            result['changed'] = console_result['changed']
        # perform erasedisk on FortiManager CLI
        elif module.params['rcs_fmg_action'] == 'erasedisk':
            console_result = _fortimanager_remote_console.fortimanager_remote_console_erasedisk()
            result['rcs_fmg_action_result'] = console_result['console_action_result']
            result['serial'] = _fortimanager_remote_console.serial
            result['version'] = _fortimanager_remote_console.version
            result['factorydefault'] = _fortimanager_remote_console.factorydefault
            if console_result['status']:
                module.fail_json(msg='Something wrong with rcs_fmg_erasedisk', **result)
                return
            result['changed'] = console_result['changed']
        # perform configuration on FortiManager CLI (do not support configuration require interactive yet)
        elif module.params['rcs_fmg_action'] == 'cli':
            console_result = _fortimanager_remote_console.fortimanager_remote_console_cli()
            result['rcs_fmg_action_result'] = console_result['console_action_result']
            result['serial'] = _fortimanager_remote_console.serial
            result['version'] = _fortimanager_remote_console.version
            result['factorydefault'] = _fortimanager_remote_console.factorydefault
            if console_result['status']:
                module.fail_json(msg='Something wrong with rcs_fmg_cli', **result)
                return
            result['changed'] = True

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
