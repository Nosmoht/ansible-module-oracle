Oracle library for Ansible
==========
- [Introduction](#introduction)
- [Requiements](#requirements)

# Introduction
Handle Oracle stuff using Ansible with this library.

Supported objects and operations:
- Users: create, update, delete
- Roles: create
- System parameters: set, reset

# Requirements
- Python [cx_Oracle] must be installed on the Ansible controller node.

# Usage

## Common
For all modules the following parameters must be passed.

__NOTE__:  Connect as SYSDBA or using na SID is not yet implemented!

```yaml
oracle_host: <hostname or ip of database>
oracle_port: <port>
oracle_user: <username>
oracle_pass: <password>
oracle_service: <service_name>
```

## Users
__NOTE__: Password must be the hashed value from sys.user$.password.

```yaml
oracle_user:
- name: pinky
  password: 3D5E2F1H4D
  state: unlocked
- name: brain
  state: absent
```

## Role

```yaml
oracle_role:
- name: APP_ROLE
  state: present
```

## System parameters

Provided value is compared to column value AND display_value of v$system_parameter.

```yaml
oracle_system_parameter:
- name: db_create_file_dest
  value: /u01/app/oracle/oradata/ORCL
  state: present
- name: sga_max_size
  value: 128974848
  state: present
- name: sga_target
  value: 128M
- name: _some_underscore_value
  state: absent
```

# Author

[Thomas Krahn](mailto:ntbc@gmx.net)

[cx_Oracle]: https://pypi.python.org/pypi/cx_Oracle
