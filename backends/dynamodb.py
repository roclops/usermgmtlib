import boto3
import usermgmtlib.usermgmt as usermgmt
from usermgmtlib.backends import Backend

def sanitize_attribute(item, attr):
    try:
        return item[attr]
    except (KeyError, AttributeError):
        return None

class Role(usermgmt.Role):
    def refresh(self):
        conn = connection()
        r = conn.get_role(rolename)
        return True

    def save(self):
        conn = connection()
        conn.delete_role(rolename)
        conn.table_roles.put_item(Item=self.get_dict())
        return True

class Group(usermgmt.Group):
    def refresh(self):
        g = self.table_groups.get_item(Key={'groupname': self.groupname})['Item']
        self.groupname = sanitize_attribute(g, 'groupname')
        self.gid = sanitize_attribute(g, 'gid')
        return True

    def save(self):
        conn = connection()
        conn.table_groups.delete_item(Key={'groupname': self.groupname})
        conn.table_groups.put_item(Item=self.get_dict())
        return True

class User(usermgmt.User):
    def set(self, attribute, value):
        self.refresh()
        attr = getattr(self, attribute)
        attr = value
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
        self.name = 'dynamodb'
        dynamodb = boto3.resource('dynamodb')
        self.table_users = dynamodb.Table('ldap_users')
        self.table_groups = dynamodb.Table('ldap_groups')
        self.table_roles = dynamodb.Table('ldap_roles')

    def get_users(self):
        users = []
        dynamo_users = list(self.table_users.scan()['Items'])
        if not dynamo_users: return []
        for u in dynamo_users:
            public_keys = []
            if 'public_keys' in u:
                public_keys = [str(k) for k in u['public_keys']]
            groups = []
            if 'groups' in u:
                groups = [g for g in u['groups']]
            users.append(
                User(
                    username=u['username'],
                    hash_ldap=u['hash_ldap'],
                    uidNumber=u['uidNumber'],
                    email=u['email'],
                    public_keys=public_keys,
                    groups=groups
                )
            )
        return users

    def get_groups(self):
        groups = []
        dynamo_groups = list(self.table_groups.scan()['Items'])
        if not dynamo_groups: return []
        for g in dynamo_groups:
            groups.append(
                Group(
                    groupname=g['groupname'],
                    gid=g['gid']
                )
            )
        return groups

    def get_roles(self):
        roles = []
        dynamo_roles = list(self.table_roles.scan()['Items'])
        for r in dynamo_roles:
            roles.append(
                Role(
                    rolename=sanitize_attribute(r, 'rolename'),
                    groups=sanitize_attribute(r, 'groups')
                )
            )
        return roles

    def get_user(self, username):
        dynamo_user = self.get_dynamo_user(username)
        if not dynamo_user: return False
        return User(
            username=sanitize_attribute(dynamo_user, 'username'),
            hash_ldap=sanitize_attribute(dynamo_user, 'hash_ldap'),
            password_mod_date=sanitize_attribute(dynamo_user, 'password_mod_date'),
            email=sanitize_attribute(dynamo_user, 'email'),
            uidNumber=sanitize_attribute(dynamo_user, 'uidNumber'),
            public_keys=sanitize_attribute(dynamo_user, 'public_keys'),
            sshkey_mod_date=sanitize_attribute(dynamo_user, 'sshkey_mod_date'),
            groups=sanitize_attribute(dynamo_user, 'groups'),
            auth_code=sanitize_attribute(dynamo_user, 'auth_code'),
            auth_code_date=sanitize_attribute(dynamo_user, 'auth_code_date')
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

    def get_dynamo_role(self, rolename):
        r = self.table_roles.get_item(Key={'rolename': rolename})
        if r:
            return r['Item']
        else:
            return False

    def get_dynamo_user(self, username):
        u = self.table_users.get_item(Key={'username': username})
        if u:
            return u['Item']
        else:
            return False

    def get_dynamo_group(self, groupname):
        g = self.table_groups.get_item(Key={'groupname': groupname})
        if g:
            return g['Item']
        else:
            return None

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
            gid=str(int(max([group.gid for group in self.get_groups()]))+1)
        )
        g.save()
        return g

    def create_user(self, username, email, rolename):
        u = User(
            username=username,
            email=email,
            groups=self.get_role(rolename).groups,
            uidNumber=str(int(max([user.uidNumber for user in self.get_dynamo_users()]))+1)
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
