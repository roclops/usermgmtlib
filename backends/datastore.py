import usermgmtlib.usermgmt as usermgmt
from usermgmtlib.backends import Backend

import google.auth
from google.cloud import datastore

def sanitize_attribute(item, attr):
    try:
        return item[attr]
    except (KeyError, AttributeError):
        return None

class Role(usermgmt.Role):
    def refresh(self):
        conn = connection()
        r = conn.get_role(self.rolename)
        self.roles = sanitize_attribute(r, 'roles')
        return True

    def save(self):
        conn = connection()
        conn.delete_role(rolename)
        return conn.table_roles.put_item(Item=self.get_dict())

class Group(usermgmt.Group):
    def refresh(self):
        conn = connection()
        g = conn.get_group(self.groupname)
        self.groupname = sanitize_attribute(g, 'groupname')
        self.gid = sanitize_attribute(g, 'gid')
        return True

    def save(self):
        conn = connection()
        conn.delete_group(self.groupname)
        return conn.table_groups.put_item(Item=self.get_dict())

class User(usermgmt.User):
    def set(self, attribute, value):
        self.refresh()
        attr = setattr(self, attribute, value)
        self.save()
        return True

    def refresh(self):
        conn = connection()
        u = conn.table_users.get_item(Key={'username': self.username})['Item']
        self.hash_ldap = sanitize_attribute(u, 'hash_ldap')
        self.password_mod_date = sanitize_attribute(u, 'password_mod_date')
        self.email = sanitize_attribute(u, 'email')
        self.uidNumber = sanitize_attribute(u, 'uidNumber')
        self.public_keys = sanitize_attribute(u, 'public_keys')
        self.sshkey_mod_date = sanitize_attribute(u, 'sshkey_mod_date')
        self.groups = sanitize_attribute(u, 'groups')
        self.auth_code = sanitize_attribute(u, 'auth_code')
        self.auth_code_date = sanitize_attribute(u, 'auth_code_date')
        return True

    def save(self):
        values = {
            ':hash_ldap': str(self.hash_ldap),
            ':password_mod_date': str(self.password_mod_date),
            ':email': str(self.email),
            ':uidNumber': str(self.uidNumber),
            ':sshkey_mod_date': str(self.sshkey_mod_date),
            ':auth_code': str(self.auth_code),
            ':auth_code_date': str(self.auth_code_date)
        }

        remove_values = []
        if self.groups:
            values[':groups'] = self.groups
        else:
            remove_values.append('groups')

        if self.public_keys:
            values[':public_keys'] = self.public_keys
        else:
            remove_values.append('public_keys')

        set_params = []
        for k, v in values.items():
            set_params.append('%s = %s' % (k.lstrip(':'), k))

        set_expression = 'SET ' + ','.join(set_params)
        remove_expression = 'REMOVE ' + ','.join(remove_values)

        update_expression = set_expression
        if remove_values:
            update_expression = set_expression + ' ' + remove_expression

        conn = connection()
        conn.table_users.update_item(
            Key = {'username': self.username},
            UpdateExpression = update_expression,
            ExpressionAttributeValues = values,
            ReturnValues = 'UPDATED_NEW'
        )
        return True

class connection(Backend):
    def __init__(self):
        self.name = 'datastore'
        credentials, project = google.auth.default()
        self.client = datastore.Client(project)

    def get_kind_list(self, kind, order):
        query = self.client.query(kind=kind)
        query.order = [order]
        return = list(query.fetch())

    def get_ds_key(self, kind, key):
        with client.transaction():
            ds_key = self.client.key(kind, key)
            ds_get = self.client.get(ds_key)
            if ds_get:
                return ds_get
            else:
                return False

    def get_users(self):
        ds_users = self.get_kind_list('usermgmt_users')
        if not ds_users: return []
        users = []
        for u in ds_users:
            users.append(
                User(
                    username=sanitize_attribute(u, 'name'),
                    hash_ldap=sanitize_attribute(u, 'hash_ldap'),
                    uidNumber=sanitize_attribute(u, 'uidNumber'),
                    email=sanitize_attribute(u, 'email'),
                    public_keys=sanitize_attribute(u, 'public_keys'),
                    groups=sanitize_attribute(u, 'groups')
                )
            )
        return users

    def get_groups(self):
        groups = []
        ds_groups = self.get_kind_list('usermgmt_groups')
        if not ds_groups: return []
        for g in ds_groups:
            groups.append(
                Group(
                    groupname=sanitize_attribute(g, 'groupname'),
                    gid=sanitize_attribute(g, 'gid')
                )
            )
        return groups

    def get_roles(self):
        roles = []
        ds_roles = self.get_kind_list('usermgmt_roles')
        for r in ds_roles:
            roles.append(
                Role(
                    rolename=sanitize_attribute(r, 'rolename'),
                    groups=sanitize_attribute(r, 'groups')
                )
            )
        return roles

    def get_user(self, username):
        ds_user = self.get_ds_key('usermgmt_users', username)
        if not ds_user: return False
        return User(
            username=sanitize_attribute(ds_user, 'username'),
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

    def get_role(self, rolename):
        dynamo_role = self.get_dynamo_role(rolename)
        if not dynamo_role: return False
        return Role(
            rolename=sanitize_attribute(dynamo_role, 'rolename'),
            groups=sanitize_attribute(dynamo_role, 'groups')
        )

    def get_group(self, groupname):
        dynamo_group = self.get_dynamo_user(username)
        if not dynamo_group: return False
        return Group(
            groupname=sanitize_attribute(dynamo_group, 'groupname'),
            gid=sanitize_attribute(dynamo_group, 'gid')
        )

    def create_role(self, rolename, groups):
        r = Role(
            rolename=rolename,
            groups=groups
        )
        r.save()
        return r

    def create_group(self, groupname):
        g = Group(
            groupname=groupname,
            gid=str(self.get_max_gid())
        )
        g.save()
        return g

    def create_user(self, username, email, rolename):
        u = User(
            username=username,
            email=email,
            groups=self.get_role(rolename).groups,
            uidNumber=str(self.get_max_uidNumber())
        )
        u.save()
        return u

    def delete_role(self, rolename):
        return self.table_roles.delete_item(Key={'rolename': rolename})

    def delete_user(self, username):
        return self.table_users.delete_item(Key={'username': username})

    def delete_group(self, groupname):
        members = self.get_group_members(groupname)
        for member in members:
            self.remove_user_from_group(member, groupname)
        if self.get_group_members(groupname):
            return False
        return self.table_groups.delete_item(Key={'groupname': groupname})


    def add_group_to_role(self, rolename, groupname):
        r = self.get_role(rolename)
        if groupname not in r.groups:
            r.groups.add(groupname)
            r.save()
            return True
        else:
            return False

    def remove_group_from_role(self, rolename, groupname):
        r = self.get_role(rolename)
        if groupname in r.groups:
            r.groups.remove(groupname)
            r.save()
            return True
        else:
            return False

    def add_user_to_group(self, username, groupname):
        u = self.get_user(username)
        if groupname not in u.groups:
            u.groups.add(groupname)
            u.save()
            return True
        else:
            return False

    def remove_user_from_group(self, username, groupname):
        u = self.get_user(username)
        if groupname in u.groups:
            u.groups.remove(groupname)
            u.save()
            return True
        else:
            return False

    def get_group_users(groupname):
        users = self.get_users()
        return [u.username for u in users if groupname in u.groups]

    def get_max_gid(self):
        return int(max([group.gid for group in self.get_groups()]))+1

    def get_max_uidNumber(self):
        return int(max([user.uidNumber for user in self.get_users()]))+1
