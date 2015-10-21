#!/usr/bin/python

try:
    import cx_Oracle
except ImportError:
    oracleclient_found = False
else:
    oracleclient_found = True


def createConnection(username, userpass, host, port, service):
    return cx_Oracle.connect('{username}/{userpass}@{host}:{port}/{service}'.format(username=username, userpass=userpass, host=host, port=port, service=service))


def ensure():
    name = module.params['name']
    state = module.params['state']


def main():
    global module
    global conn

    module = AnsibleModule(
        argument_spec=dict(
            name=dict(type='str', required=True),
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
        module.fail_json(msg='cx_Oracle not found. Needs to be installed.')

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
