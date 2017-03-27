import usermgmtlib.usermgmt as usermgmt
from usermgmtlib.backends import Backend, Singleton

from time import time

import google.auth
from google.cloud import datastore

def sanitize_attribute(item, attr):
    try:
        return item[attr]
    except (KeyError, AttributeError):
        return None


import time
def timeit(method):
    def timed(*args, **kw):
        ts = time.time()
        result = method(*args, **kw)
        te = time.time()
        print('%r (%r, %r) %2.2f sec' % \
              (method.__name__, args, kw, te-ts))
        return result
    return timed


class Role(usermgmt.Role):
    def refresh(self):
        conn = connection()
        r = conn.get_role(self.rolename)
        self.__dict__.update(r.__dict__)
        return True

    def save(self):
        conn = connection()
        conn.delete_role(rolename)
        ds_entity = conn.new_ds_entity('usermgmt_roles', self.rolename)
        ds_entity.update(self.get_dict())
        conn.client.put(ds_entity)
        return True

class Group(usermgmt.Group):
    def refresh(self):
        conn = connection()
        g = conn.get_group(self.groupname)
        self.__dict__.update(g.__dict__)
        return True

    def save(self):
        conn = connection()
        conn.delete_group(self.groupname)
        ds_entity = conn.new_ds_entity('usermgmt_groups', self.groupname)
        ds_entity.update(self.get_dict())
        conn.client.put(ds_entity)
        return True

class User(usermgmt.User):
    def set(self, attribute, value):
        self.refresh()
        attr = setattr(self, attribute, value)
        self.save()
        return True

    def refresh(self):
        conn = connection()
        u = conn.get_user(self.username)
        self.__dict__.update(u.__dict__)
        return True

    def save(self):
        conn = connection()
        conn.delete_user(self.username)
        ds_entity = conn.new_ds_entity('usermgmt_users', self.username)
        ds_entity.update(self.get_dict())
        conn.client.put(ds_entity)
        return True

class connection(Backend):
    __metaclass__ = Singleton

    @timeit
    def __init__(self):
        self.name = 'datastore'
        credentials, project = google.auth.default()
        self.client = datastore.Client(project)

    @timeit
    def get_kind_list(self, kind, order=None):
        query = self.client.query(kind=kind)
        if order:
            query.order = [order]
        return list(query.fetch())

    @timeit
    def delete_ds_key(self, kind, key):
        ds_key = self.client.key(kind, key)
        return self.client.delete(ds_key)

    @timeit
    def get_ds_entity(self, kind, key):
        ds_key = self.client.key(kind, key)
        ds_get = self.client.get(ds_key)
        if ds_get:
            return ds_get
        else:
            return False

    @timeit
    def new_ds_entity(self, kind, key):
        ds_key = self.client.key(kind, key)
        return datastore.Entity(key=ds_key)

    @timeit
    def get_users(self):
        ds_users = self.get_kind_list('usermgmt_users')
        if not ds_users: return []
        users = []
        for u in ds_users:
            users.append(
                User(
                    username=u.key.name,
                    hash_ldap=sanitize_attribute(u, 'hash_ldap'),
                    uidNumber=sanitize_attribute(u, 'uidNumber'),
                    email=sanitize_attribute(u, 'email'),
                    public_keys=sanitize_attribute(u, 'public_keys'),
                    groups=sanitize_attribute(u, 'groups')
                )
            )
        return users

    @timeit
    def get_groups(self):
        groups = []
        ds_groups = self.get_kind_list('usermgmt_groups')
        if not ds_groups: return []
        for g in ds_groups:
            groups.append(
                Group(
                    groupname=g.key.name,
                    gid=sanitize_attribute(g, 'gid')
                )
            )
        return groups

    @timeit
    def get_roles(self):
        roles = []
        ds_roles = self.get_kind_list('usermgmt_roles')
        for r in ds_roles:
            roles.append(
                Role(
                    rolename=r.key.name,
                    groups=sanitize_attribute(r, 'groups')
                )
            )
        return roles

    @timeit
    def get_user(self, username):
        ds_user = self.get_ds_entity('usermgmt_users', username)
        if not ds_user: return False
        return User(
            username=ds_user.key.name,
            hash_ldap=sanitize_attribute(ds_user, 'hash_ldap'),
            password_mod_date=sanitize_attribute(ds_user, 'password_mod_date'),
            email=sanitize_attribute(ds_user, 'email'),
            uidNumber=sanitize_attribute(ds_user, 'uidNumber'),
            public_keys=sanitize_attribute(ds_user, 'public_keys'),
            sshkey_mod_date=sanitize_attribute(ds_user, 'sshkey_mod_date'),
            groups=sanitize_attribute(ds_user, 'groups'),
            auth_code=sanitize_attribute(ds_user, 'auth_code'),
            auth_code_date=sanitize_attribute(ds_user, 'auth_code_date')
        )

    @timeit
    def get_role(self, rolename):
        ds_role = self.get_ds_entity('usermgmt_roles', rolename)
        if not ds_role: return False
        return Role(
            rolename=ds_role.key.name,
            groups=sanitize_attribute(ds_role, 'groups')
        )

    @timeit
    def get_group(self, groupname):
        ds_group = self.get_ds_entity('usermgmt_group', groupname)
        if not ds_group: return False
        return Group(
            groupname=ds_group.key.name,
            gid=sanitize_attribute(ds_group, 'gid')
        )

    @timeit
    def create_role(self, rolename, groups):
        r = Role(
            rolename=rolename,
            groups=groups
        )
        r.save()
        return r

    @timeit
    def create_group(self, groupname):
        g = Group(
            groupname=groupname,
            gid=str(self.get_max_gid())
        )
        g.save()
        return g

    @timeit
    def create_user(self, username, email, rolename):
        u = User(
            username=username,
            email=email,
            groups=self.get_role(rolename).groups,
            uidNumber=str(self.get_max_uidNumber())
        )
        u.save()
        return u

    @timeit
    def delete_role(self, rolename):
        return self.delete_ds_key('usermgmt_roels', rolename)

    @timeit
    def delete_user(self, username):
        return self.delete_ds_key('usermgmt_users', username)

    @timeit
    def delete_group(self, groupname):
        members = self.get_group_users(groupname)
        for member in members:
            self.remove_user_from_group(member, groupname)
        if self.get_group_users(groupname):
            return False
        return self.delete_ds_key('usermgmt_groups', groupname)

    @timeit
    def add_group_to_role(self, rolename, groupname):
        r = self.get_role(rolename)
        if groupname not in r.groups:
            r.groups.add(groupname)
            r.save()
            return True
        else:
            return False

    @timeit
    def remove_group_from_role(self, rolename, groupname):
        r = self.get_role(rolename)
        if groupname in r.groups:
            r.groups.remove(groupname)
            r.save()
            return True
        else:
            return False

    @timeit
    def add_user_to_group(self, username, groupname):
        u = self.get_user(username)
        if groupname not in u.groups:
            u.groups.add(groupname)
            u.save()
            return True
        else:
            return False

    @timeit
    def remove_user_from_group(self, username, groupname):
        u = self.get_user(username)
        if groupname in u.groups:
            u.groups.remove(groupname)
            u.save()
            return True
        else:
            return False

    @timeit
    def get_group_users(self, groupname):
        users = self.get_users()
        return [u.username for u in users if groupname in u.groups]

    @timeit
    def get_max_gid(self):
        return int(max([group.gid for group in self.get_groups()]))+1

    @timeit
    def get_max_uidNumber(self):
        return int(max([user.uidNumber for user in self.get_users()]))+1
