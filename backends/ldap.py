# pip install python3-ldap

import ldap3
from ldap3 import Server, Connection, ALL, EXTERNAL, SASL, SUBTREE, MODIFY_ADD, MODIFY_DELETE
import ldap3.core.exceptions

import os, sys, re

import usermgmtlib.usermgmt as usermgmt
from usermgmtlib.backends import Backend

def sanitize_attribute(item, attr):
    try:
        return item['raw_attributes'][attr]
    except (KeyError, AttributeError):
        return None

class Role(usermgmt.Role):
    pass

class Group(usermgmt.Group):
    pass

class User(usermgmt.User):
    pass

class connection(Backend):
    def __init__(self):
        self.name = 'ldap'
        try:
            server = Server('ldapi:///var/lib/openldap/run/ldapi')
            conn = Connection(server, authentication=SASL, sasl_mechanism=EXTERNAL, sasl_credentials='')
            conn.bind()
            self.connection = conn
            self.domain = os.getenv('LDAP_DOMAIN', 'dc=localdomain')
            if not self.domain.startswith('dc='):
                self.domain = 'dc=' + self.domain
        except Exception as e:
            print('Could not connect to ldap server! (%s)' % (e))
            sys.exit(1)

    def search(self, filter, base=None, retrieve_attributes=['uid', 'userPassword', 'uidNumber', 'sshPublicKey', 'mail']):
        if not base:
            base = 'ou=People,' + self.domain
        try:
            scope = SUBTREE
            r = self.connection.search(search_base=base, search_scope=scope, search_filter=filter, attributes=retrieve_attributes)
            data = self.connection.response
        except ldap3.core.exceptions.LDAPNoSuchObjectResult:
            return False
        if len(data) > 0:
            return data
        else:
            return False

    def del_dn(self, dn):
        return self.connection.delete(dn)

    def get_user_groups(self):
        ldap_groups = self.search('(gidNumber=*)', base='ou=Groups,' + self.domain, retrieve_attributes=['cn', 'memberUid'])
        user_groups = {}
        if ldap_groups:
            for g in ldap_groups:
                if not g or 'memberUid' not in g['raw_attributes']: continue
                for member in g['raw_attributes']['memberUid']:
                    full_dn_match = re.match(r'uid=(.+?),ou=People,' + self.domain, member.decode(), re.I)
                    if full_dn_match:
                        member = full_dn_match.group(1)
                    if member not in user_groups: user_groups[member] = []
                    user_groups[member].append(g['raw_attributes']['cn'][0].decode())
        for user in user_groups.keys():
            user_groups[user] = set(user_groups[user])
        return user_groups

    def get_users(self):
        users = []
        ldap_users = self.search('(uid=*)')
        if not ldap_users: return []
        groups = self.get_user_groups()
        for u in ldap_users:
            pw = u['raw_attributes']['userPassword'][0].decode()
            user_groups = []
            if u['raw_attributes']['uid'][0].decode() in groups:
                user_groups = groups[u['raw_attributes']['uid'][0].decode()]
            keys = []
            if 'sshPublicKey' in u['raw_attributes']:
                for key in u['raw_attributes']['sshPublicKey']:
                    keys.append(key.decode())
                keys = set(keys)
            users.append(
                User(
                    username=u['raw_attributes']['uid'][0].decode(),
                    password=pw,
                    uid=u['raw_attributes']['uidNumber'][0].decode(),
                    email=u['raw_attributes']['mail'][0].decode(),
                    public_keys=keys,
                    groups=user_groups
                )
            )
        return users

    def get_groups(self):
        groups = []
        ldap_groups = self.search('(gidNumber=*)', base='ou=Groups,' + self.domain, retrieve_attributes=['cn', 'gidNumber'])
        if not ldap_groups: return []
        for g in ldap_groups:
            groups.append(
                Group(
                    groupname=g['raw_attributes']['cn'][0].decode(),
                    gid=g['raw_attributes']['gidNumber'][0].decode()
                )
            )
        return groups

    def add_group(self, g):
        dn = "cn=%s,ou=Groups,%s" % (g.groupname, self.domain)
        attrs = {}
        attrs['objectclass'] = ['top', 'posixGroup']
        attrs['cn'] = g.groupname
        attrs['gidNumber'] = g.gid
        result = self.connection.add(dn, attributes=attrs)
        if result:
            print('Added group [%s].' % (g.groupname))
        else:
            print(self.connection.result)
        return True

    def del_group(self, g):
        dn = "cn=%s,ou=Groups,%s" % (g.groupname, self.domain)
        try:
            if self.del_dn(dn):
                print('Deleted group: [%s].' % (dn))
        except ldap3.core.exceptions.LDAPNoSuchObjectResult:
            pass
        return True

    def add_user(self, u):
        dn = "uid=%s,ou=People,%s" % (u.username, self.domain)
        attrs = {}
        attrs['objectclass'] = ['top', 'inetOrgPerson', 'organizationalPerson', 'person', 'posixAccount', 'shadowAccount']
        attrs['uid'] = u.username
        attrs['cn'] = u.username
        attrs['gecos'] = u.username
        attrs['sn'] = u.username
        attrs['gidNumber'] = '100'
        attrs['loginShell'] = '/bin/bash'
        attrs['mail'] = u.email
        attrs['homeDirectory'] = "/home/ldap/%s" % u.username
        if u.public_keys:
            attrs['objectclass'].append('ldapPublicKey')
            attrs['sshPublicKey'] = [str(k) for k in list(u.public_keys)]
        attrs['userPassword'] = u.password
        attrs['uidNumber'] = u.uid
        result = self.connection.add(dn, attributes=attrs)
        if not result:
            print(self.connection.result)
        else:
            print('Added: [%s].' % (dn))

        self.add_user_to_groups(u)
        return True

    def add_user_to_groups(self, u):
        if not u.groups: return False
        added = []
        for group in u.groups:
            dn = "cn=%s,ou=Groups,%s" % (group, self.domain)
            attrs = {
                'memberUid': [( MODIFY_ADD, 'uid=%s,ou=People,%s' % (u.username, self.domain) )]
            }
            try:
                result = self.connection.modify(dn, attrs)
                if not result:
                    print(self.connection.result)
                else:
                    added.append(group)
            except:
                print("Couldn't add user to group: [%s]" % (group))
                pass
        print('Added user [%s] to [%s].' % (u.username, ', '.join(added)))

    def del_user(self, u):
        dn = "uid=%s,ou=People,%s" % (u.username, self.domain)
        self.del_user_from_groups(u)
        try:
            if self.del_dn(dn):
                print('Deleted user: [%s].' % (dn))
        except ldap3.core.exceptions.LDAPNoSuchObjectResult:
            pass
        return True

    def del_user_from_groups(self, u):
        if not u.groups: return False
        removed = []
        for group in u.groups:
            dn = "cn=%s,ou=Groups,%s" % (group, self.domain)
            attrs = {
                'memberUid': [( MODIFY_DELETE, 'uid=%s,ou=People,%s' % (u.username, self.domain) )]
            }
            try:
                result = self.connection.modify(dn, attrs)
                if not result:
                    print(self.connection.result)
                else:
                    removed.append(group)
            except (ldap3.core.exceptions.LDAPNoSuchAttributeResult, ldap3.core.exceptions.LDAPNoSuchObjectResult):
                pass
        print('Removed user [%s] from [%s].' % (u.username, ', '.join(removed)))
        return True
