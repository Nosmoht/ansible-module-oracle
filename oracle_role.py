#!/usr/bin/python

try:
    import cx_Oracle
except ImportError:
    oracleclient_found = False
else:
    oracleclient_found = True


def createConnection(username, userpass, host, port, service):
    return cx_Oracle.connect('{username}/{userpass}@{host}:{port}/{service}'.format(username=username, userpass=userpass, host=host, port=port, service=service))


def executeSQL(module, conn, sql):
    cur = conn.cursor()
    try:
        cur.execute(sql)
    except cx_Oracle.DatabaseError as e:
        module.fail_json(msg='{sql}: {err}'.format(sql=sql, err=e))
    cur.close()


def getRole(module, conn, name):
    try:
        sql = 'SELECT role, password_required FROM DBA_ROLES WHERE role = :name'
        cur = conn.cursor()
        cur.prepare(sql)
        cur.execute(None, dict(name=name))
        row = cur.fetchone()
        cur.close()
    except cx_Oracle.DatabaseError as e:
        module.fail_json(msg='{sql}: {err}'.format(sql=sql,err=str(e)))

    if not row:
        return None

    data = dict()
    data['name']=row[0]
    data['password_required']=row[1]

    try:
        sql = 'SELECT privilege FROM DBA_SYS_PRIVS WHERE grantee = :name'
        cur = conn.cursor()
        cur.prepare(sql)
        cur.execute(None, dict(name=name))
        row = cur.fetchall()
        cur.close()
    except cx_Oracle.DatabaseError as e:
        module.fail_json(msg='{sql}: {err}'.format(sql=sql,err=str(e)))

    data['sys_privs'] = [item[0] for item in row]

    return data


def getCreateRoleSQL(name, password_required=None):
    sql = 'CREATE ROLE {name}'.format(name=name)
    #if password_required:
    #    sql='{sql}'
    return sql


def getDropRoleSQL(name):
    sql = 'DROP ROLE {name}'.format(name=name)
    return sql


def ensure(module, conn):
    changed = False
    sql = None

    name = module.params['name'].upper()
    state = module.params['state']

    role = getRole(module, conn, name)

    if not role:
        if state != 'absent':
            sql = getCreateRoleSQL(name=name)
    else:
        if state == 'absent':
            sql = getDropRoleSQL(name=name)

    if sql:
        executeSQL(module, conn, sql)
        changed = True
    return changed, getRole(module, conn, name=name)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            name=dict(type='str', required=True),
            state=dict(type='str', default='present', choices=['present', 'absent']),
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

    changed, role = ensure(module, conn)
    module.exit_json(changed=changed, role=role)

# import module snippets
from ansible.module_utils.basic import *

if __name__ == '__main__':
    main()
