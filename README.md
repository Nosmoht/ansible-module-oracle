Oracle library for Ansible
==========
- [Introduction](#introduction)
- [Requiements](#requirements)
- [Usage](#usage)
 - [Common](#common)
 - [Directory](#directory)
 - [User](#user)
 - [Role](#role)
 - [System Parameters](#system-parameters)
- [Author](#author)

# Introduction

Handle Oracle stuff using Ansible with this library.

Supported objects and operations:
- Directory
  - create and delete
  - modify path
- Roles
  - create and delete
  - grant and revoke system privileges
  - grant and revoke roles
- System parameters
  - set and reset, even hidden parameters
- Users
  - create, update, delete
  - lock and unlock
  - grant and revoke roles
  - grant and revoke system privileges

# Requirements

- Python [cx_Oracle] 5.2 or greater must be installed on the Ansible controller node.

# Usage

## Common

For all modules the following parameters must be passed. On of either __oracle_sid__ and __oralce_service__
must be passed but not both. __oracle_pass__ can be omitted if defined in environment variable __ORACLE_PASS__.
To connect as SYSDBA or SYSOPER set __oracle_mode__ to the corresponding value, omit for normal connection.

```yaml
oracle_host: <hostname or ip of database>
oracle_port: <port>
oracle_user: <username>
oracle_pass: <password>
oracle_mode: <[SYSDBA|SYSOPER]>
oracle_sid: <SID>
oracle_service: <service_name>
```

## Directory

```yaml
- name: Ensure directory
  oracle_directory:
    name: DATA_PUMP_DIR
    path: /u01/app/oracle/admin/ORCL/dpdump
    oracle_host: db.example.com
    oracle_port: 1521
    oracle_user: system
    oracle_pass: manager
    oracle_sid: ORCL
```

## Role

```yaml
- oracle_role:
    name: APP_ROLE
    roles:
    - CONNECT
    - SELECT ANY DICTIONARY
    sys_privs:
    - CREATE TABLE
    - CREATE INDEX
    state: present
    oracle_host: db.example.com
    oracle_port: 1521
    oracle_user: system
    oracle_pass: manager
    oracle_sid: ORCL
```

## System parameters

Provided value is compared to column __value__ AND __display_value__ of v$system_parameter.

```yaml
- oracle_system_parameter:
    name: db_create_file_dest
    value: /u01/app/oracle/oradata/ORCL
    state: present
    oracle_host: db.example.com
    oracle_port: 1521
    oracle_user: system
    oracle_pass: manager
    oracle_sid: ORCL
```

## Users

__NOTE__: Password must be the hashed value from sys.user$.password.

```yaml
- oracle_user:
    name: pinky
    password: 225751978A87ED8E
    default_tablespace: DATA
    temporary_tablespace: TEMP
    roles:
    - CONNECT
    - SELECT ANY DICTIONARY
    sys_privs:
    - UNLIMITED TABLESPACE
    state: unlocked
    oracle_host: db.example.com
    oracle_port: 1521
    oracle_user: sys
    oracle_pass: topsecret
    oracle_mode: SYSDBA
    oracle_sid: ORCL
```

# Author

[Thomas Krahn](mailto:ntbc@gmx.net)

[cx_Oracle]: https://pypi.python.org/pypi/cx_Oracle
