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
      - Roles granted to the role.
      - If an empty list ([]) is specified all granted roles will be revoked!
    required: false
    default: None
  sys_privs:
    description:
      - List of system privileges granted to the role
      - If an empty list ([]) is specified all granted system privileges will be revoked
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
except ImportError:
    oracleclient_found = False
else:
    oracleclient_found = True


def createConnection(module, user, password, host, port, sid=None, service=None, mode=None):
    if sid:
        dsn = cx_Oracle.makedsn(host=host, port=port, sid=sid)
    else:
        dsn = cx_Oracle.makedsn(host=host, port=port, service_name=service)

    try:
        conn = cx_Oracle.connect(user=user, password=password, dsn=dsn)
        return conn
    except cx_Oracle.DatabaseError as e:
        module.fail_json(msg='{dsn}: {err}'.format(dsn=dsn, err=str(e)))


def executeSQL(module, conn, sql):
    cur = conn.cursor()
    try:
        cur.execute(sql)
    except cx_Oracle.DatabaseError as e:
        module.fail_json(msg='{sql}: {err}'.format(sql=sql, err=e))
    cur.close()


def getRole(module, conn, name):
    cur = conn.cursor()
    try:
        sql = 'SELECT role, password_required FROM DBA_ROLES WHERE role = :name'
        cur.prepare(sql)
        cur.execute(None, dict(name=name))
        row = cur.fetchone()
    except cx_Oracle.DatabaseError as e:
        module.fail_json(msg='{sql}: {err}'.format(sql=sql, err=str(e)))

    if not row:
        return None

    data = dict()
    data['name'] = row[0]
    data['password_required'] = row[1]

    try:
        sql = 'SELECT privilege FROM DBA_SYS_PRIVS WHERE grantee = :name'
        cur.prepare(sql)
        cur.execute(None, dict(name=name))
        row = cur.fetchall()
        data['sys_privs'] = [item[0] for item in row]
    except cx_Oracle.DatabaseError as e:
        module.fail_json(msg='{sql}: {err}'.format(sql=sql, err=str(e)))

    try:
        sql = 'SELECT granted_role FROM DBA_ROLE_PRIVS WHERE grantee = :name'
        cur.prepare(sql)
        cur.execute(None, dict(name=name))
        row = cur.fetchall()
        data['roles'] = [item[0] for item in row]
    except cx_Oracle.DatabaseError as e:
        module.fail_json(msg='{sql}: {err}'.format(sql=sql, err=str(e)))

    cur.close()
    return data


def getCreateRoleSQL(name, password_required=None):
    sql = 'CREATE ROLE {name}'.format(name=name)
    #   if password_required:
    #       sql='{sql}'
    return sql


def getDropRoleSQL(name):
    sql = 'DROP ROLE {name}'.format(name=name)
    return sql


def getGrantPrivilegeSQL(name, priv):
    sql = 'GRANT {priv} TO {name}'.format(priv=priv, name=name)
    return sql


def getRevokePrivilegeSQL(name, priv):
    sql = 'REVOKE {priv} FROM {name}'.format(priv=priv, name=name)
    return sql


def ensure(module, conn):
    changed = False
    sql = list()

    name = module.params['name'].upper()
    roles = module.params['roles']
    state = module.params['state']
    sys_privs = module.params['sys_privs']

    role = getRole(module, conn, name)

    if not role and state != 'absent':
        sql.append(getCreateRoleSQL(name=name))
    elif role and state == 'absent':
        sql.append(getDropRoleSQL(name=name))

    if state != 'absent':
        # Roles
        if roles is not None:
            roles_to_grant = list(set(roles) - set(role.get('roles') if role else list()))
            for item in roles_to_grant:
                sql.append(getGrantPrivilegeSQL(priv=item, name=name))

            roles_to_revoke = list(set(role.get('roles') if role else list()) - set(roles))
            for item in roles_to_revoke:
                sql.append(getRevokePrivilegeSQL(priv=item, name=name))

        # System privileges
        if sys_privs is not None:
            privs_to_grant = list(set(sys_privs) - set(role.get('sys_privs') if sys_privs else list()))
            for item in privs_to_grant:
                sql.append(getGrantPrivilegeSQL(priv=item, name=name))

            privs_to_revoke = list(set(role.get('sys_privs') if sys_privs else list()) - set(sys_privs))
            for item in privs_to_revoke:
                sql.append(getRevokePrivilegeSQL(priv=item, name=name))

    if len(sql) > 0:
        for stmt in sql:
            executeSQL(module, conn, stmt)
        return True, getRole(module, conn, name=name)

    return False, role


def main():
    module = AnsibleModule(
        argument_spec=dict(
            name=dict(type='str', required=True),
            roles=dict(type='list', default=None),
            state=dict(type='str', default='present', choices=['present', 'absent']),
            sys_privs=dict(type='list', default=None),
            oracle_host=dict(type='str', default='127.0.0.1'),
            oracle_port=dict(type='str', default='1521'),
            oracle_user=dict(type='str', default='SYSTEM'),
            oracle_pass=dict(type='str', default=None, no_log=True),
            oracle_sid=dict(type='str', default=None),
            oracle_service=dict(type='str', default=None),
        ),
        required_one_of=[['oracle_sid', 'oracle_service']],
        mutually_exclusive=[['oracle_sid', 'oracle_service']],
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

    conn = createConnection(module=module,
                            user=oracle_user, password=oracle_pass,
                            host=oracle_host, port=oracle_port,
                            sid=oracle_sid, service=oracle_service)

    changed, role = ensure(module, conn)
    module.exit_json(changed=changed, role=role)

# import module snippets
from ansible.module_utils.basic import *

if __name__ == '__main__':
    main()
