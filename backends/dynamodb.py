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
        r = self.table_roles.get_item(Key={'rolename': self.rolename})['Item']
        self.groups = sanitize_attribute(u, 'groups')
        return True

    def save(self):
        self.table_roles.delete_item(Key={'rolename': self.rolename})
        self.table_roles.put_item(Item=self.get_dict())
        return True

class Group(usermgmt.Group):
    def refresh(self):
        g = self.table_groups.get_item(Key={'groupname': self.groupname})['Item']
        self.groupname = sanitize_attribute(g, 'groupname')
        self.gid = sanitize_attribute(g, 'gid')
        return True

    def save(self):
        self.table_groups.delete_item(Key={'groupname': self.groupname})
        self.table_groups.put_item(Item=self.get_dict())
        return True

class User(usermgmt.User):
    def refresh(self):
        u = table_users.get_item(Key={'username': self.username})['Item']
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

        table_users.update_item(
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
                    password=u['hash_ldap'],
                    uid=u['uidNumber'],
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

    def get_role(rolename):
        r = self.table_roles.get_item(Key={'rolename': rolename})
        if r:
            return Role(
                rolename=sanitize_attribute(r['Item'], 'rolename'),
                groups=sanitize_attribute(r['Item'], 'groups')
            )
        else:
            return None

