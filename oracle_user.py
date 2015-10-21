#!/usr/bin/python
# -*- coding: utf-8 -*-

DOCUMENTATION = '''
---
module: oracle_user
short_description: Manage Oracle user accounts
description:
- Create, modify and drop Oracle user accounts
options:
  name:
    description: Account name
    required: true
  state:
    description: Account state
    required: False
    default: present
    choices: ["present", "absent", "locked", "unlocked"]
  oracle_host:
    description: Hostname or IP address of Oracle DB
    required: False
    default: 127.0.0.1
  oracle_port:
    description: Listener Port
    required: False
    default: 1521
  oracle_user:
    description: Account to connect as
    required: False
    default: SYSTEM
  oracle_pass:
    description: Password to be used to authenticate
    required: False
    default: manager
  oracle_service:
    description: Service name to connect to
    required: False
    default: ORCL
notes:
- Requires cx_Oracle
#version_added: "2.0"
author: "Thomas Krahn (@nosmoht)"
'''

try:
    import cx_Oracle
except ImportError:
    oracleclient_found = False
else:
    oracleclient_found = True


def createConnection(username, userpass, host, port, service):
    return cx_Oracle.connect('{username}/{userpass}@{host}:{port}/{service}'.format(username=username, userpass=userpass, host=host, port=port, service=service))


def executeSQL(con, sql):
    cur = con.cursor()
    try:
        cur.execute(sql)
    except cx_Oracle.DatabaseError as e:
        module.fail_json(msg='{sql}: {err}'.format(sql=sql, err=e))
    cur.close()


def getUser(con, username):
    user = None
    cur = con.cursor()
    cur.prepare(
        'select default_tablespace,temporary_tablespace,password,account_status from dba_users where username = :username')
    cur.execute(None, dict(username=username))
    row = cur.fetchone()
    if row:
        user = dict()
        user['name'] = username
        user['default_tablespace'] = row[0]
        user['temporary_tablespace'] = row[1]
        user['account_status'] = row[3]
    cur.close()
    return user


def getCreateUserSQL(username, userpass, default_tablespace=None, temporary_tablespace=None, account_status=None):
    sql = 'CREATE USER "{username}" IDENTIFIED BY "{userpass}"'.format(
        username=username, userpass=userpass)
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


def getDropUserSQL(username):
    sql = 'DROP USER "{username}"'.format(username=username)
    return sql


def getUpdateUserSQL(username, userpass=None, default_tablespace=None, temporary_tablespace=None, account_status=None):
    sql = 'ALTER USER {username}'.format(username=username)
    if userpass:
        sql = '{sql} IDENTIFIED BY {userpass}'.format(
            sql=sql, userpass=userpass)
    if default_tablespace:
        sql = '{sql} DEFAULT TABLESPACE {default_tablespace}'.format(
            sql=sql, default_tablespace=default_tablespace)
    if temporary_tablespace:
        sql = '{sql} TEMPORARY TABLESPACE {temporary_tablespace}'.format(
            sql=sql, temporary_tablespace=temporary_tablespace)
    return sql


def ensure():
    changed = False
    name = module.params['name']
    state = module.params['state']
    default_tablespace = module.params['default_tablespace']
    temporary_tablespace = module.params['temporary_tablespace']
    user = getUser(conn, name)
    if not user:
        if state != 'absent':
            if state != 'locked':
                account_status = 'UNLOCK'
            else:
                account_status = 'LOCK'
            sql = getCreateUserSQL(
                username=name,
                userpass=module.params['password'],
                default_tablespace=default_tablespace,
                temporary_tablespace=temporary_tablespace,
                account_status=account_status)
            executeSQL(conn, sql)
            changed = True
    else:
        if state == 'absent':
            sql = getDropUserSQL(username=name)
            executeSQL(conn, sql)
            changed = True
        if default_tablespace and user.get('default_tablespace') != default_tablespace:
            sql = getUpdateUserSQL(
                username=name, default_tablespace=default_tablespace)
            executeSQL(conn, sql)
            changed = True
        if temporary_tablespace and user.get('temporary_tablespace') != temporary_tablespace:
            sql = getUpdateUserSQL(
                username=name, temporary_tablespace=temporary_tablespace)
            executeSQL(conn, sql)
            changed = True
    return changed, getUser(conn, username=name)


def main():
    global module
    global conn

    module = AnsibleModule(
        argument_spec=dict(
            name=dict(type='str', required=True),
            password=dict(type='str', required=False),
            default_tablespace=dict(type='str', required=False),
            temporary_tablespace=dict(type='str', required=False),
            state=dict(type='str', default='present', choices=[
                       'present', 'absent', 'locked', 'unlocked']),
            oracle_host=dict(type='str', default='127.0.0.1'),
            oracle_port=dict(type='str', default='1521'),
            oracle_user=dict(type='str', default='SYSTEM'),
            oracle_pass=dict(type='str', default='manager'),
            oracle_service=dict(type='str', default='ORCL'),
        ),
    )

    if not oracleclient_found:
        module.fail_json(
            msg='cx_Oracle not found. Needs to be installed. See http://cx-oracle.sourceforge.net/')

    oracle_host = module.params['oracle_host']
    oracle_port = module.params['oracle_port']
    oracle_user = module.params['oracle_user']
    oracle_pass = module.params['oracle_pass']
    oracle_service = module.params['oracle_service']

    conn = createConnection(username=oracle_user, userpass=oracle_pass,
                            host=oracle_host, port=oracle_port, service=oracle_service)

    changed, user = ensure()
    module.exit_json(changed=changed, user=user)

# import module snippets
from ansible.module_utils.basic import *

if __name__ == '__main__':
    main()
