Oracle library for Ansible
==========
- [Introduction](#introduction)
- [Requiements](#requirements)
- [Usage](#usage)
 - [Common](#common)
 - [Directory](#directory)
 - [Role](#role)
 - [System Parameters](#system-parameters)
 - [Tablespaces](#tablespaces)
 - [User](#user)
- [Return value](#return-value)
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
- Tablespaces
  - create and delete
  - add and modify datafiles
- Users
  - create, update, delete
  - lock and unlock
  - grant and revoke roles
  - grant and revoke system privileges
- Check mode
  All modules support Ansible's check mode. If check mode is enabled all SQL statements that would be executed are
  returned and can be checked. One can register the output of each module and check the results _sql_ variable to see
  all statements.

# Requirements

- Python [cx_Oracle] 5.2 or greater must be installed on the Ansible controller node.

# Usage

## Common

For all modules the following parameters must be passed. On of either __oracle_sid__ and __oralce_service__
must be passed but not both. __oracle_pass__ can be omitted if defined in environment variable __ORACLE_PASS__.
To connect as SYSDBA or SYSOPER set __oracle_mode__ to the corresponding value, omit for normal connection.

As [cx_Oracle] is required one should use local action to avoid the installation of cx_Oracle on all database systems.

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
    scope: both
    state: present
    oracle_host: db.example.com
    oracle_port: 1521
    oracle_user: system
    oracle_pass: manager
    oracle_sid: ORCL
```

## Tablespaces
Ensure tablespace USERS exist, can grow up to 2G in 16M steps. Tablespace will be created if it does not exist.
```yaml
- name: Ensure tablespace users is present
  oracle_tablespace:
    name: USERS
    state: present
    init_size: 100M
    autoextend: true
    next_size: 16M
    max_size: 2G
    oracle_host: db.example.com
    oracle_user: system
    oracle_pass: manager
    oracle_sid: ORCL
```

Ensure tablespace TEST does not exist.
```yaml
- name: Ensure tablespace users is present
  oracle_tablespace:
    name: TEST
    state: absent
    oracle_host: db.example.com
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
# Return value
Every module returns the object it handled as well as all SQL statements executed
so one can use Ansible's register function for further processing. The dict attribute is named like the object itself, like user in the oracle_user module.

Example for the result of a changed user
```json
{
    "_ansible_no_log": false,
    "changed": true,
    "invocation": {
        "module_args": {
            "_ansible_check_mode": true,
            "default_tablespace": "DATA",
            "name": "PINKY",
            "oracle_host": "db.example.com",
            "oracle_mode": "SYSDBA",
            "oracle_pass": "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER",
            "oracle_port": "1521",
            "oracle_service": null,
            "oracle_sid": "ORCL",
            "oracle_user": "sys",
            "password": "1234567890ABCDEF",
            "password_mismatch": false,
            "roles": [
              "DBA"
            ],
            "state": "present",
            "sys_privs": null,
            "temporary_tablespace": "TEMP"
        },
        "module_name": "oracle_user"
    },
    "item": {
        "default_tablespace": "DATA",
        "name": "PINKY",
        "password": "1234567890ABCDEF",
        "roles": [
            "DBA"
        ],
        "temporary_tablespace": "TEMP"
    },
    "sql": [
        "GRANT DBA TO PINKY",
    ],
    "user": {
        "account_status": "OPEN",
        "default_tablespace": "DATA",
        "name": "PINKY",
        "password": "1234567890ABCDEF",
        "roles": [
            "DBA"
        ],
        "sys_privs": null,
        "temporary_tablespace": "TEMP"
    }
}
```

# Author

[Thomas Krahn](mailto:ntbc@gmx.net)

[cx_Oracle]: https://pypi.python.org/pypi/cx_Oracle
