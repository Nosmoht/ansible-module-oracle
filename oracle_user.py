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
  default_tablespace:
    description:
    - Name of default tablespace
    required: false
  password:
    description:
    - Password hash as in SYS.USER$.PASSWORD
  password_mismatch:
    description:
    - Boolean to define if a mismatch of current and specified password is allowed.
    - If I(true), the password will not be changed if it's different.
    - If I(false), password will be changed if possible.
    required: false
    default: false
  quotas:
    description:
    - List of tablespace quotas.
    required: false
  roles:
    description:
    - List of roles granted to the user.
    - If an empty list I([]) is passed all roles will be revoked. If I(None) roles will not be ensured.
    - All items will be converted using uppercase.
    required: false
    default: None
  sys_privs:
    description:
    - List of system privileges granted to the user.
    - If an empty list I([]) is passed all system privileges will be revoked. If I(None) system privileges will not be handled.
    - All items will be converted using uppercase.
    required: false
  state:
    description:
    - If I(present), I(locked) or I(unlocked) and the user does not exist it will be created.
    - If I(absent) and the user exists it first of all will be locked, afterwards all session will be disconnected immediate and finally the user gots dropped.
    required: False
    default: present
    choices: ["present", "absent", "locked", "unlocked"]
  tab_privs:
    description:
    - List od tablespace privileges
    required: False
  temporary_tablespace:
    description:
    - Name of temporary tablespace
    required: false
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
    quotas:
    - tablespace: DATA
      quota: UNLIMITED
    roles:
    - DBA
    sys_privs:
    - CONNECT
    - UNLIMITED TABLESPACE
    tab_privs:
    - owner: SYS
      tablename: USER$
      privileges:
      - SELECT
    oracle_host: oracle.example.com
    oracle_user: SYSTEM
    oracle_pass: manager
    oracle_sid: ORCL

- name: Ensure user brain is locked
  oracle_user:
    name: brain
    state: locked
    oracle_host: oracle.example.com
    oracle_user: SYSTEM
    oracle_pass: manager
    oracle_sid: ORCL

- name: Ensure user elvira is locked
  oracle_user:
    name: elvira
    state: absent
    oracle_host: oracle.example.com
    oracle_user: SYSTEM
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


def execute_sql(module, con, sql):
    cur = con.cursor()
    try:
        cur.execute(sql)
    except cx_Oracle.DatabaseError as e:
        module.fail_json(msg='{sql}: {err}'.format(sql=sql, err=e))
    cur.close()


def fetch_all(module, cur, sql, name):
    try:
        cur.prepare(sql)
        cur.execute(None, dict(name=name))
        rows = cur.fetchall()
    except cx_Oracle.DatabaseError as e:
        module.fail_json(msg='{sql}: {err}'.format(sql=sql, err=str(e)))
    return rows


def is_rac(module, con):
    sql = 'select parallel from v$instance'
    cur = con.cursor()
    try:
        cur.prepare(sql)
        cur.execute(None)
        row = cur.fetchone()
    except cx_Oracle.DatabaseError as e:
        module.fail_json(msg='{sql}: {err}'.format(sql=sql, err=str(e)))
    cur.close()
    return row == 'YES'


def get_user(module, conn, name, fetch_password=False):
    cur = conn.cursor()
    sql = 'select default_tablespace, temporary_tablespace, account_status from dba_users where username = :name'
    row = fetch_all(module, cur, sql, name)
    if not row:
        return None

    data = dict()
    data['name'] = name
    data['default_tablespace'] = row[0][0]
    data['temporary_tablespace'] = row[0][1]
    data['account_status'] = row[0][2]

    if fetch_password:
        sql = 'select password from sys.user$ where name = :name'
        row = fetch_all(module, cur, sql, name)
        data['password'] = row[0][0]
    else:
        data['password'] = None

    # Roles granted
    sql = 'select granted_role from dba_role_privs where grantee = :name'
    rows = fetch_all(module, cur, sql, name)
    data['roles'] = [item[0] for item in rows]

    # System privileges granted
    sql = 'select privilege from dba_sys_privs where grantee = :name'
    rows = fetch_all(module, cur, sql, name)
    data['sys_privs'] = [item[0] for item in rows]

    # Tablespace quotas
    sql = 'select tablespace_name, max_bytes from dba_ts_quotas where username = :name'
    rows = fetch_all(module, cur, sql, name)
    data['quotas'] = [{'tablespace': item[0], 'max_bytes': item[1]} for item in rows]

    # Table privileges granted
    sql = 'select owner, table_name, listagg(privilege, \',\') within group (order by privilege) from dba_tab_privs where grantee = :name and type = \'TABLE\' group by owner,table_name'
    rows = fetch_all(module, cur, sql, name)
    data['tab_privs'] = [{'owner': row[0], 'table_name': row[1], 'privileges': row[2].split(',')} for row in rows]

    cur.close()
    return data


def get_create_user_sql(name, userpass, default_tablespace=None, temporary_tablespace=None, account_status=None):
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


def get_drop_user_sql(name):
    sql = 'DROP USER "{name}" CASCADE'.format(name=name)
    return sql


def get_alter_user_sql(name, userpass=None, default_tablespace=None, temporary_tablespace=None, account_status=None):
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
    if account_status:
        sql = '{sql} ACCOUNT {account_state}'.format(
            sql=sql, account_state=account_status)
    return sql


def get_grant_privilege_sql(user, priv, admin=False):
    sql = 'GRANT {priv} TO {user}'.format(priv=priv, user=user)
    if admin:
        sql = '{sql} WITH ADMIN OPTION'.format(sql=sql)
    return sql


def get_revoke_privilege_sql(user, priv):
    sql = 'REVOKE {priv} FROM {user}'.format(priv=priv, user=user)
    return sql


def map_state(state):
    if state in ['present', 'unlocked']:
        return 'UNLOCK'
    return 'LOCK'


def map_account_state(account_status):
    if account_status == 'OPEN':
        return ['present', 'unlocked']
    return 'locked'


def get_disconnect_sessions_sql(name, rac=False):
    if rac:
        sql = """
        declare
          cursor c is select sid, serial#, inst_id from gv$session where username = '{name}';
        begin
          for s in c loop
            execute immediate 'alter system disconnect session ''' || s.sid || ',' || s.serial# || ',@' || s.inst_id || ''' immediate';
          end loop;
        end;
        """
    else:
        sql = """
        declare
          cursor c is select sid, serial# from v$session where username = '{name}';
        begin
          for s in c loop
            execute immediate 'alter system disconnect session ''' || s.sid || ',' || s.serial# || ''' immediate';
          end loop;
        end;
        """
    return sql.format(name=name)


def get_alter_user_quota_sql(tablespace, username, quota):
    return 'ALTER USER {username} QUOTA {quota} ON {tablespace}'.format(username=username, quota=quota,
                                                                        tablespace=tablespace)


def get_factor(unit):
    units = ['K', 'M', 'G', 'T']
    factor = 1024
    for u in units:
        if u == unit:
            break
        factor = factor * 1024
    return factor


def get_max_bytes(quota):
    if quota is None:
        return None
    quota = quota.strip().upper()
    if quota == 'UNLIMITED':
        return -1
    match = re.match(r"([0-9]+)([A-Z]+)", quota, re.I)
    if match:
        items = match.groups()
        bytes = int(items[0])
        unit = items[1]
        return bytes * get_factor(unit)
    return quota


def get_quota_list(target, actual):
    data = []
    for target_quota in target:
        found = False
        quota = {}
        quota['tablespace'] = target_quota.get('tablespace')
        quota['target'] = target_quota.get('quota')
        for current_quota in actual:
            found = current_quota.get('tablespace') == target_quota.get('tablespace')
            if found:
                quota['actual'] = current_quota.get('quota')
                break
        data.append(quota)
    return data


def merge_table_privs(target, merge, name):
    for item in merge:
        found = False
        owner = item.get('owner')
        table_name = item.get('table_name')
        privileges = item.get('privileges')
        for index, t in enumerate(target):
            found = owner == t.get('owner') and table_name == t.get('table_name')
            if found:
                target[index][name] = privileges
                break
        if not found:
            target.append({'owner': owner, 'table_name': table_name, name: privileges})
    return target


def tab_privs_diff(target, actual):
    data = []
    data = merge_table_privs(data, target, 'target')
    data = merge_table_privs(data, actual, 'actual')

    for index, item in enumerate(data):
        data[index]['revoke'] = list(set(item.get('actual', [])) - set(item.get('target', [])))
        data[index]['grant'] = list(set(item.get('target', [])) - set(item.get('actual', [])))
    return data


def ensure(module, conn):
    sql = list()

    name = module.params['name'].upper()
    default_tablespace = module.params['default_tablespace'].upper() if module.params[
        'default_tablespace'] else None
    password = module.params['password']
    password_mismatch = module.params['password_mismatch']

    quotas = module.params['quotas']

    if module.params['roles'] is not None:
        roles = [item.upper() for item in module.params['roles']]
    else:
        roles = None

    state = module.params['state']

    temporary_tablespace = module.params['temporary_tablespace'].upper() if module.params[
        'temporary_tablespace'] else None

    if module.params['sys_privs'] is not None:
        sys_privs = [item.upper() for item in module.params['sys_privs']]
    else:
        sys_privs = None

    if module.params['tab_privs'] is not None:
        tab_privs = [{'owner': item.get('owner').strip().upper(),
                      'table_name': item.get('table_name').strip().upper(),
                      'privileges': [priv.upper() for priv in item.get('privileges')]}
                     for item in module.params['tab_privs']]
    else:
        tab_privs = None

    if password:
        fetch_password = True
    else:
        fetch_password = False
    user = get_user(module=module, conn=conn, name=name, fetch_password=fetch_password)

    # User doesn't exist
    if not user:
        # CREATE USER
        if state != 'absent':
            sql.append(get_create_user_sql(name=name,
                                           userpass=password,
                                           default_tablespace=default_tablespace,
                                           temporary_tablespace=temporary_tablespace,
                                           account_status=map_state(state)))
            # Sys privs
            if sys_privs is not None:
                for sys_priv in sys_privs:
                    sql.append(get_grant_privilege_sql(user=name, priv=sys_priv))
            # Roles
            if roles is not None:
                for role in roles:
                    sql.append(get_grant_privilege_sql(user=name, priv=role))
            # Quotas
            if quotas is not None:
                for quota in quotas:
                    sql.append(get_alter_user_quota_sql(tablespace=quota.get('tablespace'), username=name,
                                                        quota=quota.get('quota')))
            # Table privileges
            if tab_privs is not None:
                for tab_priv in tab_privs:
                    for priv in tab_priv.get('privileges', []):
                        sql.append(get_grant_privilege_sql(user=name,
                                                           priv='{privilege} ON "{owner}"."{table_name}"'.format(
                                                               privilege=priv,
                                                               owner=tab_priv.get('owner'),
                                                               table_name=tab_priv.get('table_name'))))
    else:
        # DROP USER
        if state == 'absent':
            if user:
                sql.append(get_alter_user_sql(name=name, account_status=map_state('locked')))
                sql.append(get_disconnect_sessions_sql(name=name, rac=is_rac(module=module, con=conn)))
                sql.append(get_drop_user_sql(name=name))
        else:
            if state not in map_account_state(user.get('account_status')):
                sql.append(get_alter_user_sql(
                    name=name, account_status=map_state(state)))
            if password and (user.get('password') != password and not password_mismatch):
                sql.append(get_alter_user_sql(name=name, userpass=password))
            if default_tablespace and user.get('default_tablespace') != default_tablespace:
                sql.append(get_alter_user_sql(
                    name=name, default_tablespace=default_tablespace))
            if temporary_tablespace and user.get('temporary_tablespace') != temporary_tablespace:
                sql.append(get_alter_user_sql(
                    name=name, temporary_tablespace=temporary_tablespace))

            if roles is not None:
                priv_to_grant = list(
                    set(roles) - set(user.get('roles') if user else list()))
                for priv in priv_to_grant:
                    sql.append(get_grant_privilege_sql(user=name, priv=priv))
                priv_to_revoke = list(
                    set(user.get('roles') if user else list()) - set(roles))
                for priv in priv_to_revoke:
                    sql.append(get_revoke_privilege_sql(user=name, priv=priv))

            # System privileges
            if sys_privs is not None:
                privs_to_grant = list(
                    set(sys_privs) - set(user.get('sys_privs') if user else list()))
                for priv in privs_to_grant:
                    sql.append(get_grant_privilege_sql(user=name, priv=priv))
                priv_to_revoke = list(
                    set(user.get('sys_privs') if user else list()) - set(sys_privs))
                for priv in priv_to_revoke:
                    sql.append(get_revoke_privilege_sql(user=name, priv=priv))

            # Quotas
            if quotas is not None:
                quotas_list = get_quota_list(target=quotas, actual=user.get('quotas'))
                for quota in quotas_list:
                    if quota.get('target') != quota.get('actual'):
                        sql.append(
                            get_alter_user_quota_sql(tablespace=quota.get('tablespace'), username=name,
                                                     quota=quota.get('target')))

            # Table privileges
            if tab_privs is not None:
                privs_diff = tab_privs_diff(target=tab_privs, actual=user.get('tab_privs'))
                for diff in privs_diff:
                    if diff.get('revoke') is not None:
                        for revoke in diff.get('revoke'):
                            sql.append(get_revoke_privilege_sql(user=name,
                                                                priv='{privilege} ON "{owner}"."{table_name}"'.format(
                                                                    privilege=revoke, owner=diff.get('owner'),
                                                                    table_name=diff.get('table_name'))))
                    if diff.get('grant') is not None:
                        for grant in diff.get('grant'):
                            sql.append(get_grant_privilege_sql(user=name,
                                                               priv='{privilege} ON "{owner}"."{table_name}"'.format(
                                                                   privilege=grant, owner=diff.get('owner'),
                                                                   table_name=diff.get('table_name'))))

    if len(sql) != 0:
        if module.check_mode:
            module.exit_json(changed=True, sql=sql, user=user)
        for stmt in sql:
            execute_sql(module, conn, stmt)
        return True, get_user(module, conn, name), sql
    return False, user, sql


def main():
    module = AnsibleModule(
        argument_spec=dict(
            name=dict(type='str', required=True),
            password=dict(type='str', required=False),
            password_mismatch=dict(type='bool', default=False),
            default_tablespace=dict(type='str', required=False),
            temporary_tablespace=dict(type='str', required=False),
            quotas=dict(type='list', required=False),
            roles=dict(type='list', required=False),
            state=dict(type='str', default='present', choices=[
                'present', 'absent', 'locked', 'unlocked']),
            sys_privs=dict(type='list', required=False),
            tab_privs=dict(type='list', required=False),
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
    oracle_mode = module.params['oracle_mode']
    oracle_pass = module.params['oracle_pass'] or os.environ['ORACLE_PASS']
    oracle_sid = module.params['oracle_sid']
    oracle_service = module.params['oracle_service']

    conn = create_connection(module=module,
                             user=oracle_user, password=oracle_pass, mode=oracle_mode,
                             host=oracle_host, port=oracle_port,
                             sid=oracle_sid, service=oracle_service)

    try:
        changed, user, sql = ensure(module, conn)
        module.exit_json(changed=changed, user=user, sql=sql)
    except Exception as e:
        module.fail_json(msg=traceback.format_exc())


# import module snippets
from ansible.module_utils.basic import *

if __name__ == '__main__':
    main()
