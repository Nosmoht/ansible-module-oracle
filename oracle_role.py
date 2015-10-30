#!/usr/bin/python

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


def getGrantRoleSQL(name, role):
    sql = 'GRANT {role} TO {name}'.format(role=role, name=name)
    return sql


def getRevokeRoleSQL(name, role):
    sql = 'REVOKE {role} FROM {name}'.format(role=role, name=name)
    return sql


def ensure(module, conn):
    changed = False
    sql = list()

    name = module.params['name'].upper()
    roles = module.params['roles']
    state = module.params['state']

    role = getRole(module, conn, name)

    if not role and state != 'absent':
        sql.append(getCreateRoleSQL(name=name))
    elif role and state == 'absent':
        sql.append(getDropRoleSQL(name=name))

    if state != 'absent':
        roles_to_grant = list(set(roles)-set(role.get('roles') if role else list()))
        for item in roles_to_grant:
            sql.append(getGrantRoleSQL(role=item, name=name))

        roles_to_revoke = list(set(role.get('roles') if role else list())-set(roles))
        for item in roles_to_revoke:
            sql.append(getRevokeRoleSQL(role=item, name=name))

    if len(sql) > 0:
        for stmt in sql:
            executeSQL(module, conn, stmt)
        return True, getRole(module, conn, name=name)

    return False, role


def main():
    module = AnsibleModule(
        argument_spec=dict(
            name=dict(type='str', required=True),
            roles=dict(type='list', default=list()),
            state=dict(type='str', default='present', choices=['present', 'absent']),
            oracle_host=dict(type='str', default='127.0.0.1'),
            oracle_port=dict(type='str', default='1521'),
            oracle_user=dict(type='str', default='SYSTEM'),
            oracle_pass=dict(type='str', default='manager'),
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
    oracle_pass = module.params['oracle_pass']
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
