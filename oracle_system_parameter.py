#!/usr/bin/python
# -*- coding: utf-8 -*-

DOCUMENTATION = '''
---
module: oracle_system_parameter
short_description: Manage Oracle system parameters
description:
- Modify Oracle system parameters
options:
  name:
    description:
    - Parameter name
    required: true
  value:
    description:
    - Parameter value
    required: true
  scope:
    description:
    - Parameter scope
    default: both
    choices: ["both", "memory", "spfile"]
  state:
    description:
    - Parameter state
    required: False
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
    - Can be either of SYSASM, SYSDBA or SYSOPER.
    - Omit for normal connection.
    required: False
    default: None
    choices: ['SYSASM', 'SYSDBA', 'SYSOPER']
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
- Requires cx_Oracle 5.2 or greate
#version_added: "2.0"
author: "Thomas Krahn (@nosmoht)"
'''

EXAMPLES = '''
- name: Ensure Oracle system parameter
  oracle_system_privilege:
    name: db_create_file_dest
    value: +DATA
    oracle_host: db.example.com
    oracle_port: 1523
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
    elif mode == 'SYSASM':
        return cx_Oracle.SYSASM
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
        conn = cx_Oracle.connect(user=user, password=password, dsn=dsn, mode=map_mode(mode))
        return conn
    except cx_Oracle.DatabaseError as e:
        module.fail_json(msg='{dsn}: {err}'.format(dsn=dsn, err=str(e)))


def execute_sql(module, conn, sql):
    cur = conn.cursor()
    try:
        cur.execute(sql)
        cur.close()
    except cx_Oracle.DatabaseError as e:
        module.fail_json(msg='{sql}: {err}'.format(sql=sql, err=e))


def get_system_parameter(module, conn, name):
    cur = conn.cursor()
    try:
        sql = 'select sp.name, sp.value, sp.display_value from v$system_parameter sp where sp.name = :name'
        cur.prepare(sql)
        cur.execute(None, dict(name=name))
        row = cur.fetchone()
        cur.close()
        if row:
            return dict(name=row[0], value=row[1], display_value=row[2])
        return None
    except cx_Oracle.DatabaseError as e:
        module.fail_json(msg='{sql}: {err}'.format(sql=sql, err=str(e)))


def get_alter_system_sql(name, value, scope, reset=False):
    action = 'RESET' if reset else 'SET'
    sql = "ALTER SYSTEM {action} \"{name}\"='{value}' SCOPE={scope}".format(action=action, name=name, value=value,
                                                                            scope=scope)
    return sql


def ensure(module, conn):
    name = module.params['name'].lower()
    value = module.params['value']
    scope = module.params['scope']
    state = module.params['state']

    data = get_system_parameter(module, conn, name)

    sql = list()
    if data:
        if state == 'absent' and data.get('value') != '':
            sql.append(get_alter_system_sql(name=name, scope=scope, reset=True))
        if value not in [data.get('value'), data.get('display_value')]:
            sql.append(get_alter_system_sql(name=name, value=value, scope=scope, reset=False))
    if len(sql) > 0:
        if module.check_mode:
            module.exit_json(changed=True, sql=sql)
        for stmt in sql:
            execute_sql(module, conn, stmt)
        return True, get_system_parameter(module=module, conn=conn, name=name)
    return False, data


def main():
    module = AnsibleModule(
            argument_spec=dict(
                    name=dict(type='str', required=True),
                    value=dict(type='str', required=False),
                    scope=dict(type='str', default='both', choices=['both', 'memory', 'spfile']),
                    state=dict(type='str', default='present', choices=['present', 'absent']),
                    oracle_host=dict(type='str', default='127.0.0.1'),
                    oracle_port=dict(type='str', default='1521'),
                    oracle_user=dict(type='str', default='SYSTEM'),
                    oracle_pass=dict(type='str', default=None, no_log=True),
                    oracle_mode=dict(type='str', required=None, default=None, choices=['SYSDBA', 'SYSASM', 'SYSOPER']),
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
    oracle_mode = module.params['oracle_mode']
    oracle_sid = module.params['oracle_sid']
    oracle_service = module.params['oracle_service']

    conn = create_connection(module=module,
                             user=oracle_user, password=oracle_pass,
                             host=oracle_host, port=oracle_port,
                             sid=oracle_sid, service=oracle_service, mode=oracle_mode)

    changed, system_parameter = ensure(module, conn)
    module.exit_json(changed=changed, system_parameter=system_parameter)


# import module snippets
from ansible.module_utils.basic import *

if __name__ == '__main__':
    main()
