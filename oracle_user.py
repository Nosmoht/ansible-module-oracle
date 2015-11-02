#!/usr/bin/python
# -*- coding: utf-8 -*-

DOCUMENTATION = '''
---
module: oracle_user
short_description: Manage Oracle user accounts
description:
- Create, update and delete Oracle user accounts.
- Grant and revoke system privileges and roles.
- Lock or unlock accounts.
options:
  name:
    description:
    - Account name
    required: true
  password:
    description:
    - Password hash as in SYS.USER$.PASSWORD
  roles:
    description:
    - List of roles granted to the user.
    - If an empty list ([]) is passed all roles will be revoked. If None roles will not be ensured.
    - All items will be converted using uppercase.
    required: false
    default: None
  sys_privs:
    description:
    - List of system privileges granted to the user.
    - If an empty list ([]) is passed all system privileges will be revoked. If None system privileges will not be ensured.
    - All items will be converted using uppercase.

  state:
    description:
    - Account state
    required: False
    default: present
    choices: ["present", "absent", "locked", "unlocked"]
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
    - Password to be used to authenticate
    required: False
    default: manager
  oracle_sid:
    description:
    - Oracle SID to use for connection
    required: False
    default: None
  oracle_service:
    description:
    - Oracle Service name to use for connection
    required: False
    default: None
notes:
- Requires cx_Oracle
#version_added: "2.0"
author: "Thomas Krahn (@nosmoht)"
'''

EXAMPLES = '''
- name: Ensure Oracle user accounts
  oracle_user:
    name: pinky
    default_tablespace: DATA
    temporary_tablespace: TEMP
    password: 975C9ABC52D157E5
    roles:
    - DBA
    sys_privs:
    - CONNECT
    - UNLIMITED TABLESPACE
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


def executeSQL(module, con, sql):
    cur = con.cursor()
    try:
        cur.execute(sql)
    except cx_Oracle.DatabaseError as e:
        module.fail_json(msg='{sql}: {err}'.format(sql=sql, err=e))
    cur.close()


def getUser(con, name):
    cur = con.cursor()
    try:
        cur.prepare(
            'select u.default_tablespace,u.temporary_tablespace,s.password,u.account_status from dba_users u join sys.user$ s on (s.name = u.username) where s.name = :name')
        cur.execute(None, dict(name=name))
        row = cur.fetchone()
    except cx_Oracle.DatabaseError as e:
        module.fail_json(msg='Error: {err}'.format(err=str(e)))

    if not row:
        return None

    data = dict()
    data['name'] = name
    data['default_tablespace'] = row[0]
    data['temporary_tablespace'] = row[1]
    data['password'] = row[2]
    data['account_status'] = row[3]

    try:
        cur.prepare(
            'select granted_role from dba_role_privs where grantee = :name')
        cur.execute(None, dict(name=name))
        rows = cur.fetchall()
        data['roles'] = [item[0] for item in rows]
    except cx_Oracle.DatabaseError as e:
        module.fail_json(msg='Error: {err}'.format(err=str(e)))

    try:
        cur.prepare('select privilege from dba_sys_privs where grantee = :name')
        cur.execute(None, dict(name=name))
        rows = cur.fetchall()

        data['sys_privs'] = [item[0] for item in rows]
    except cx_Oracle.DatabaseError as e:
        module.fail_json(msg='Error: {err}'.format(err=str(e)))

    cur.close()
    return data


def getCreateUserSQL(name, userpass, default_tablespace=None, temporary_tablespace=None, account_status=None):
    sql = "CREATE USER {name} IDENTIFIED BY VALUES '{userpass}'".format(
        name=name, userpass=userpass)
    if default_tablespace:
        sql = '{sql} DEFAULT TABLESPACE {default_tablespace}'.format(
            sql=sql, default_tablespace=default_tablespace)
    if temporary_tablespace:
        sql = '{sql} TEMPORARY TABLESPACE {temporary_tablespace}'.format(
            sql=sql, temporary_tablespace=temporary_tablespace)
    if account_status:
        sql = '{sql} ACCOUNT {account_status}'.format(
            sql=sql, account_status=account_status)
    return sql


def getDropUserSQL(name):
    sql = 'DROP USER "{name}" CASCADE'.format(name=name)
    return sql


def getUpdateUserSQL(name, userpass=None, default_tablespace=None, temporary_tablespace=None, account_status=None):
    sql = 'ALTER USER {name}'.format(name=name)
    if userpass:
        sql = "{sql} IDENTIFIED BY VALUES '{userpass}'".format(
            sql=sql, userpass=userpass)
    if default_tablespace:
        sql = '{sql} DEFAULT TABLESPACE {default_tablespace}'.format(
            sql=sql, default_tablespace=default_tablespace)
    if temporary_tablespace:
        sql = '{sql} TEMPORARY TABLESPACE {temporary_tablespace}'.format(
            sql=sql, temporary_tablespace=temporary_tablespace)
    return sql


def getGrantPrivilegeSQL(user, priv, admin=False):
    sql = 'GRANT {priv} TO {user}'.format(priv=priv, user=user)
    if admin:
        sql = '{sql} WITH ADMIN OPTION'.format(sql=sql)
    return sql


def getRevokePrivilegeSQL(user, priv):
    sql = 'REVOKE {priv} FROM {user}'.format(priv=priv, user=user)
    return sql


def mapState(state):
    if state in ['present', 'unlocked']:
        return 'UNLOCK'
    return 'LOCK'


def mapAccountStatus(account_status):
    if account_status == 'OPEN':
        return ['present', 'unlocked']
    return 'locked'


def ensure(module, conn):
    sql = list()

    name = module.params['name'].upper()
    default_tablespace = module.params['default_tablespace'].upper() if module.params['default_tablespace'] else None
    password = module.params['password']
    roles = [item.upper() for item in module.params['roles']]
    state = module.params['state']
    temporary_tablespace = module.params['temporary_tablespace'].upper() if module.params[
        'temporary_tablespace'] else None
    sys_privs = [item.upper() for item in module.params['sys_privs']]

    user = getUser(conn, name)

    if not user and state != 'absent':
        sql.append(getCreateUserSQL(name=name,
                                    userpass=password,
                                    default_tablespace=default_tablespace,
                                    temporary_tablespace=temporary_tablespace,
                                    account_status=mapState(state)))
    else:
        if state == 'absent':
            sql.append(getDropUserSQL(name=name))
        else:
            if state not in mapAccountStatus(user.get('account_status')):
                sql.append(getUpdateUserSQL(
                    name=name, account_status=mapState(state)))
            if password and user.get('password') != password:
                sql.append(getUpdateUserSQL(name=name, userpass=password))
            if default_tablespace and user.get('default_tablespace') != default_tablespace:
                sql.append(getUpdateUserSQL(
                    name=name, default_tablespace=default_tablespace))
            if temporary_tablespace and user.get('temporary_tablespace') != temporary_tablespace:
                sql.append(getUpdateUserSQL(
                    name=name, temporary_tablespace=temporary_tablespace))

    if state != 'absent':
        if roles is not None:
            priv_to_grant = list(
                set(roles) - set(user.get('roles') if user else list()))
            for priv in priv_to_grant:
                sql.append(getGrantPrivilegeSQL(user=name, priv=priv))
            priv_to_revoke = list(
                set(user.get('roles') if user else list()) - set(roles))
            for priv in priv_to_revoke:
                sql.append(getRevokePrivilegeSQL(user=name, priv=priv))

        # System privileges
        if sys_privs is not None:
            privs_to_grant = list(set(sys_privs) - set(user.get('sys_privs') if user else list()))
            for priv in privs_to_grant:
                sql.append(getGrantPrivilegeSQL(user=name, priv=priv))
            priv_to_revoke = list(
                set(user.get('sys_privs') if user else list()) - set(sys_privs))
            for priv in priv_to_revoke:
                sql.append(getRevokePrivilegeSQL(user=name, priv=priv))

    if len(sql) != 0:
        for stmt in sql:
            executeSQL(module, conn, stmt)
        return True, getUser(conn, name)
    return False, user


def main():
    module = AnsibleModule(
        argument_spec=dict(
            name=dict(type='str', required=True),
            password=dict(type='str', required=False),
            default_tablespace=dict(type='str', required=False),
            temporary_tablespace=dict(type='str', required=False),
            roles=dict(type='list', required=False),
            state=dict(type='str', default='present', choices=[
                'present', 'absent', 'locked', 'unlocked']),
            sys_privs=dict(type='list', required=False),
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

    changed, user = ensure(module, conn)
    module.exit_json(changed=changed, user=user)

# import module snippets
from ansible.module_utils.basic import *

if __name__ == '__main__':
    main()
