![Fortinet logo|](https://upload.wikimedia.org/wikipedia/commons/thumb/6/62/Fortinet_logo.svg/320px-Fortinet_logo.svg.png)

## FortiGate Remote Console Access Ansible Collection
***

The collection is the FortiGate Remote Console Access Ansible Automation project. It includes the modules that are able to configure FortiGate through remote console to bootstrap FortiGate. 

## Installation
This collection is distributed via [ansible-galaxy](https://galaxy.ansible.com/), the installation steps are as follows:

1. Install or upgrade to Ansible 2.9+
2. Download this collection from galaxy: `ansible-galaxy collection install fortinetps.remote-console`

## Requirements
* Ansible 2.9+ is required to support the newer Ansible Collections format
* pexpect

## Supported FortiOS Versions
Tested with FOS v6.0.2

## Supported Remote Console Server
Tested with MRV LX4000 Series
Tested with Avocent ACS 8000 Series

## Modules
The collection provides the following modules:

* `fortigate_remote_console`  Manage/Configure FortiGate through remote console server

## Roles

## Usage
The following example is used to configure global attributes in Fortinet's FortiOS and FortiGate.

Create fw_global_set.yml with the following template:
```yaml
---
- hosts: localhost
  collections:
  - fortinetps.fortios
  vars:
   term_server: "remote console server hostname or ip address"
   term_user: "remote console server login username"
   term_password: "remote console server login password"
   term_ssh_port: "remote console server port which mapping to device(FortiGate) console port"
   dev_user: "device(FortiGate) login username"
   dev_password: "device(FortiGate) login password"
  tasks:
  - name: With remote console access, factory reset device (FortiGate)
    fortigate_remote_console:
      rcs_ip: "{{ term_server }}"
      rcs_username: "{{ term_user }}"
      rcs_password: "{{ term_password }}"
      rcs_fgt_username: "{{ dev_user }}"
      rcs_fgt_password: "{{ dev_password }}"
      rcs_fgt_port: "{{ term_ssh_port }}"
      rcs_fgt_action: "factoryreset"
```

Run the test:
```bash
ansible-playbook fgt_factoryreset.yml
```

This will factoryreset FortiGate through remote console access.