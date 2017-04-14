import usermgmtlib.usermgmt as usermgmt
from usermgmtlib.backends import Backend, Singleton

def sanitize_attribute(item, attr):
    try:
        return item[attr]
    except (KeyError, AttributeError):
        return None

class Role(usermgmt.Role):
    def refresh(self):
        return True

    def save(self):
        return True

class Group(usermgmt.Group):
    def refresh(self):
        return True

    def save(self):
        return True

class User(usermgmt.User):
    def set(self, attribute, value):
        return True

    def refresh(self):
        return True

    def save(self):
        return True

class connection(Backend):
    __metaclass__ = Singleton

    def __init__(self):
        self.name = 'dummy'

    def get_users(self):
        backend_users = []     # <---- populate from backend source
        users = []
        for u in backend_users:
            users.append(
                User(
                    username=sanitize_attribute(u, 'username'),
                    hash_ldap=sanitize_attribute(u, 'hash_ldap'),
                    uidNumber=sanitize_attribute(u, 'uidNumber'),
                    email=sanitize_attribute(u, 'email'),
                    public_keys=sanitize_attribute(u, 'public_keys'),
                    groups=sanitize_attribute(u, 'groups')
                )
            )
        return users

    def get_groups(self):
        backend_groups = []     # <---- populate from backend source
        groups = []
        for g in backend_groups:
            groups.append(
                Group(
                    groupname=sanitize_attribute(g, 'groupname'),
                    gid=sanitize_attribute(g, 'gid')
                )
            )
        return groups

    def get_roles(self):
        backend_roles = []     # <---- populate from backend source
        roles = []
        for r in backend_roles:
            roles.append(
                Role(
                    rolename=sanitize_attribute(r, 'rolename'),
                    groups=sanitize_attribute(r, 'groups')
                )
            )
        return roles

    def get_user(self, username):
        backend_user = {}      # <---- populate from backend source
        if not backend_user: return False
        return User(
            username=sanitize_attribute(backend_user, 'username'),
            hash_ldap=sanitize_attribute(backend_user, 'hash_ldap'),
            password_mod_date=sanitize_attribute(backend_user, 'password_mod_date'),
            email=sanitize_attribute(backend_user, 'email'),
            uidNumber=sanitize_attribute(backend_user, 'uidNumber'),
            public_keys=sanitize_attribute(backend_user, 'public_keys'),
            sshkey_mod_date=sanitize_attribute(backend_user, 'sshkey_mod_date'),
            groups=sanitize_attribute(backend_user, 'groups'),
            auth_code=sanitize_attribute(backend_user, 'auth_code'),
            auth_code_date=sanitize_attribute(backend_user, 'auth_code_date')
        )

    def get_role(self, rolename):
        backend_role = {}      # <---- populate from backend source
        if not backend_role: return False
        return Role(
            rolename=sanitize_attribute(backend_role, 'rolename')
            groups=sanitize_attribute(backend_role, 'groups')
        )

    def get_group(self, groupname):
        backend_group = {}      # <---- populate from backend source
        if not backend_group: return False
        return Group(
            groupname=sanitize_attribute(backend_group, 'gid')
            gid=sanitize_attribute(backend_group, 'gid')
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
        return True

    def delete_user(self, username):
        return True

    def delete_group(self, groupname):
        members = self.get_group_users(groupname)
        for member in members:
            self.remove_user_from_group(member, groupname)
        if self.get_group_users(groupname):
            return False
        return True

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

    def get_group_users(self, groupname):
        users = self.get_users()
        return [u.username for u in users if groupname in u.groups]

    def get_max_gid(self):
        return int(max([group.gid for group in self.get_groups()]))+1

    def get_max_uidNumber(self):
        return int(max([user.uidNumber for user in self.get_users()]))+1
