#!/usr/bin/python
# -*- coding: utf-8 -*-

DOCUMENTATION = '''
---
module: oracle_directory
short_description: Manage Oracle DB directories
description:
- Create, update or delete Oracle directories.
options:
  name:
    description:
    - Directory name like in DBA_DIRECTORIES.DIRECTORY_NAME
    required: true
  path:
    description:
    - Directory path like in DBA_DIRECTORIES.DIRECTORY_PATH
    required: false
    default: None
  state:
    description:
    - Directory state
    required: false
    default: present
    choices: ["present", "absent"]
  oracle_host:
    description:
    - Hostname or IP address of Oracle DB
    required: False
    default: 127.0.0.1
  oracle_port:
    description:
    - Listener Port
    required: False
    default: 1521
  oracle_user:
    description:
    - Account to connect as
    required: False
    default: SYSTEM
  oracle_pass:
    description:
    - Password to be used to authenticate.
    - Can be omitted if environment variable ORACLE_PASS is set.
    required: False
    default: None
  oracle_mode:
    description:
    - Connection mode.
    - Can be SYSDBA or SYSOPER.
    - Omit for normal connection.
    required: False
    default: None
    choices: ['SYSDBA', 'SYSOPER']
  oracle_sid:
    description:
    - SID to connect to
    required: False
    default: None
  oracle_service:
    description:
    - Service name to connect to
    required: False
    default: None
notes:
- Requires cx_Oracle
author: "Thomas Krahn (@nosmoht)"
'''

EXAMPLES = '''
- name: Ensure directory
  oracle_directory:
    name: DATA_PUMP_DIR
    path: /u01/app/oracle/admin/ORCL/dpdump
    oracle_host: db.example.com
    oracle_port: 1521
    oracle_user: system
    oracle_pass: manager
    oracle_sid: ORCL
'''

try:
    import cx_Oracle

    oracleclient_found = True
except ImportError:
    oracleclient_found = False


def map_mode(mode):
    if mode == 'SYSDBA':
        return cx_Oracle.SYSDBA
    elif mode == 'SYSOPER':
        return cx_Oracle.SYSOPER
    else:
        return None


def create_connection(module, user, password, host, port, sid=None, service=None, mode=None):
    if sid:
        dsn = cx_Oracle.makedsn(host=host, port=port, sid=sid)
    else:
        dsn = cx_Oracle.makedsn(host=host, port=port, service_name=service)

    try:
        if mode:
            conn = cx_Oracle.connect(
                user=user, password=password, dsn=dsn, mode=map_mode(mode))
        else:
            conn = cx_Oracle.connect(user=user, password=password, dsn=dsn)
        return conn
    except cx_Oracle.DatabaseError as e:
        module.fail_json(msg='{dsn}: {err}'.format(dsn=dsn, err=str(e)))


def execute_sql(module, conn, sql):
    cur = conn.cursor()
    try:
        cur.execute(sql)
    except cx_Oracle.DatabaseError as e:
        module.fail_json(msg='{sql}: {err}'.format(sql=sql, err=e))
    cur.close()


def get_directory(module, conn, name):
    sql = 'SELECT directory_name, directory_path FROM dba_directories where directory_name = :name'
    cur = conn.cursor()
    data = None
    try:
        cur.prepare(sql)
        cur.execute(None, dict(name=name))
        data = cur.fetchone()
    except cx_Oracle.DatabaseError as e:
        module.fail_json(msg='{sql}: {err}'.format(sql=sql, err=str(e)))
    cur.close()

    return None if not data else dict(name=data[0], path=data[1])


def get_create_directory_sql(name, path):
    sql = "CREATE OR REPLACE DIRECTORY {name} AS '{path}'".format(name=name, path=path)
    return sql


def get_drop_directory_sql(name):
    sql = 'DROP DIRECTORY {name}'.format(name=name)
    return sql


def ensure(module, conn):
    name = module.params['name'].upper()
    path = module.params['path']
    state = module.params['state']
    sql = list()

    dir = get_directory(module, conn, name)

    if (not dir and state != 'absent') or (dir and dir.get('path') != path):
        sql.append(get_create_directory_sql(name=name, path=path))
    elif dir and state == 'absent':
        sql.append(get_drop_directory_sql(name=name))

    if len(sql) > 0:
        if module.check_mode:
            module.exit_json(msg='; '.join(sql))
        for stmt in sql:
            execute_sql(module, conn, stmt)
        return True, get_directory(module, conn, name)
    return False, dir


def main():
    module = AnsibleModule(
        argument_spec=dict(
            name=dict(type='str', required=True),
            path=dict(type='str', default=None),
            state=dict(type='str', default='present', choices=['present', 'absent']),
            oracle_host=dict(type='str', default='127.0.0.1'),
            oracle_port=dict(type='str', default='1521'),
            oracle_user=dict(type='str', default='SYSTEM'),
            oracle_pass=dict(type='str', default=None, no_log=True),
            oracle_sid=dict(type='str', default=None),
            oracle_service=dict(type='str', default=None),
        ),
        required_one_of=[['oracle_sid', 'oracle_service']],
        mutually_exclusive=[['oracle_sid', 'oracle_service']],
        supports_check_mode=True,
    )

    if not oracleclient_found:
        module.fail_json(
            msg='cx_Oracle not found. Needs to be installed. See http://cx-oracle.sourceforge.net/')

    oracle_host = module.params['oracle_host']
    oracle_port = module.params['oracle_port']
    oracle_user = module.params['oracle_user']
    oracle_pass = module.params['oracle_pass'] or os.environ['ORACLE_PASS']
    oracle_sid = module.params['oracle_sid']
    oracle_service = module.params['oracle_service']

    conn = get_connection(module=module,
                          user=oracle_user, password=oracle_pass,
                          host=oracle_host, port=oracle_port,
                          sid=oracle_sid, service=oracle_service)

    changed, role = ensure(module, conn)
    module.exit_json(changed=changed, role=role)


# import module snippets
from ansible.module_utils.basic import *

if __name__ == '__main__':
    main()
