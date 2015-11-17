#!/usr/bin/python
# -*- coding: utf-8 -*-

DOCUMENTATION = '''
---
module: oracle_role
short_description: Manage Oracle roles
description:
- Modify Oracle system parameters
options:
  name:
    description:
    - Role name
    required: true
  roles:
    description:
      - List of roles granted to the role.
      - If an empty list ([]) is specified all granted roles will be revoked.
      - All items will be converted using uppercase.
    required: false
    default: None
  sys_privs:
    description:
      - List of system privileges granted to the role.
      - If an empty list ([]) is specified all granted system privileges will be revoked.
      - All items will be converted using uppercase.
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
    default: manager
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
- name: Ensure Oracle role
  oracle_role:
    name: APP_ROLE
    roles:
    - PLUSTRACE
    sys_privs:
    - CONNECT
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


def get_role(module, conn, name):
    cur = conn.cursor()
    try:
        sql = 'SELECT role, password_required FROM DBA_ROLES WHERE role = :name'
        cur.prepare(sql)
        cur.execute(None, dict(name=name))
        row = cur.fetchone()
        if not row:
            return None
    except cx_Oracle.DatabaseError as e:
        module.fail_json(msg='{sql}: {err}'.format(sql=sql, err=str(e)))

    data = dict()
    data['name'] = row[0]
    data['password_required'] = row[1]

    try:
        sql = 'SELECT privilege FROM DBA_SYS_PRIVS WHERE grantee = :name'
        cur.prepare(sql)
        cur.execute(None, dict(name=name))
        row = cur.fetchall()
    except cx_Oracle.DatabaseError as e:
        module.fail_json(msg='{sql}: {err}'.format(sql=sql, err=str(e)))

    data['sys_privs'] = [item[0] for item in row]

    try:
        sql = 'SELECT granted_role FROM DBA_ROLE_PRIVS WHERE grantee = :name'
        cur.prepare(sql)
        cur.execute(None, dict(name=name))
        row = cur.fetchall()
    except cx_Oracle.DatabaseError as e:
        module.fail_json(msg='{sql}: {err}'.format(sql=sql, err=str(e)))

    data['roles'] = [item[0] for item in row]

    cur.close()
    return data


def get_create_role_sql(name, password_required=None):
    sql = 'CREATE ROLE {name}'.format(name=name)
    #   if password_required:
    #       sql='{sql}'
    return sql


def get_drop_role_sql(name):
    sql = 'DROP ROLE {name}'.format(name=name)
    return sql


def get_privilege_sql(action, name, priv):
    from_to = 'FROM' if action == 'REVOKE' else 'TO'
    sql = '{action} {priv} {from_to} {name}'.format(
        action=action, priv=priv, from_to=from_to, name=name)
    return sql


def get_grant_privilege_sql(name, priv):
    return get_privilege_sql(action='GRANT', priv=priv, name=name)


def get_revoke_privilege_sql(name, priv):
    return get_privilege_sql(action='REVOKE', priv=priv, name=name)


def ensure(module, conn):
    name = module.params['name'].upper()
    if module.params['roles'] is not None:
        roles = [item.upper() for item in module.params['roles']]
    else:
        roles = None
    state = module.params['state']
    if module.params['sys_privs'] is not None:
        sys_privs = [item.upper() for item in module.params['sys_privs']]
    else:
        sys_privs = None

    role = get_role(module, conn, name)

    sql = list()

    if not role and state != 'absent':
        sql.append(get_create_role_sql(name=name))
    elif role and state == 'absent':
        sql.append(get_drop_role_sql(name=name))

    if state != 'absent':
        # Roles
        if roles is not None:
            roles_to_grant = list(
                set(roles) - set(role.get('roles') if role else list()))
            for item in roles_to_grant:
                sql.append(get_grant_privilege_sql(priv=item, name=name))

            roles_to_revoke = list(
                set(role.get('roles') if role else list()) - set(roles))
            for item in roles_to_revoke:
                sql.append(get_revoke_privilege_sql(priv=item, name=name))

        # System privileges
        if sys_privs is not None:
            privs_to_grant = list(
                set(sys_privs) - set(role.get('sys_privs') if role else list()))
            for item in privs_to_grant:
                sql.append(get_grant_privilege_sql(priv=item, name=name))

            privs_to_revoke = list(
                set(role.get('sys_privs') if role else list()) - set(sys_privs))
            for item in privs_to_revoke:
                sql.append(get_revoke_privilege_sql(priv=item, name=name))

    if len(sql) > 0:
        if module.check_mode:
            module.exit_json(changed=True, msg='; '.join(sql), role=role)
        for stmt in sql:
            execute_sql(module, conn, stmt)
        return True, get_role(module, conn, name=name)

    return False, role


def main():
    module = AnsibleModule(
        argument_spec=dict(
            name=dict(type='str', required=True),
            roles=dict(type='list', default=None),
            state=dict(type='str', default='present',
                       choices=['present', 'absent']),
            sys_privs=dict(type='list', default=None),
            oracle_host=dict(type='str', default='127.0.0.1'),
            oracle_port=dict(type='str', default='1521'),
            oracle_user=dict(type='str', default='SYSTEM'),
            oracle_mode=dict(type='str', required=None, default=None, choices=[
                             'SYSDBA', 'SYSOPER']),
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
    oracle_mode = module.params['oracle_mode']
    oracle_sid = module.params['oracle_sid']
    oracle_service = module.params['oracle_service']

    conn = create_connection(module=module,
                             user=oracle_user, password=oracle_pass, mode=oracle_mode,
                             host=oracle_host, port=oracle_port,
                             sid=oracle_sid, service=oracle_service)

    changed, role = ensure(module, conn)
    module.exit_json(changed=changed, role=role)


# import module snippets
from ansible.module_utils.basic import *

if __name__ == '__main__':
    main()
