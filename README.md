Oracle library for Ansible
==========
- [Introduction](#introduction)
- [Requiements](#requirements)
- [Usage](#usage)
 - [Common](#common)
 - [User](#user)
 - [Role](#role)
 - [System Parameters](#system-parameters)
- [Author](#author)

# Introduction

Handle Oracle stuff using Ansible with this library.

Supported objects and operations:
- Users
  - create, update, delete
  - grant and revoke roles
- Roles
  - create and delete
  - grant and revoke system privileges
  - grant and revoke roles
- System parameters
 - set and reset

# Requirements

- Python [cx_Oracle] must be installed on the Ansible controller node.

# Usage

## Common

For all modules the following parameters must be passed.

__NOTE__:  Connect as SYSDBA is not yet implemented. Ensure to use an account
that has the required privileges.

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
- oracle_user:
    name: pinky
    password: 225751978A87ED8E
    default_tablespace: DATA
    temporary_tablespace: TEMP
    roles:
    - CONNECT
    - SELECT ANY DICTIONARY
    state: unlocked
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
```

## System parameters

Provided value is compared to column value AND display_value of v$system_parameter.

```yaml
- oracle_system_parameter:
    name: db_create_file_dest
    value: /u01/app/oracle/oradata/ORCL
    state: present
```

# Author

[Thomas Krahn](mailto:ntbc@gmx.net)

[cx_Oracle]: https://pypi.python.org/pypi/cx_Oracle
