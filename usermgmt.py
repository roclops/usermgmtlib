from passlib.hash import ldap_salted_sha1
from passlib.hash import ldap_pbkdf2_sha256
from sshpubkeys import SSHKey
import datetime

class Usermgmt(object):
    def attrs(self):
        raise NotImplementedError

    def get_dict(self):
        return dict((key, value) for key, value in self.__dict__.items()
            if not callable(value) and not key.startswith('__'))

    def __values(self):
        return (getattr(self, attr) for attr in self.attrs())

    def __eq__(self, other):
        # print('self:\t' + str(self.get_dict()))
        # print('other:\t' + str(other.get_dict()))
        return self.get_dict() == other.get_dict()

    def __str__(self):
        return "<Usermgmt {0}>".format(self.get_dict())

    def refresh():
        raise NotImplementedError

    def save():
        raise NotImplementedError

class Role(Usermgmt):
    def __init__(self, rolename=None, groups=[]):
        self.rolename = str(rolename)
        if groups:
            self.groups = set(sorted(groups))
        else:
            self.groups = set()

    def __eq__(self, other):
        return self.rolename == other.rolename and \
            self.groups == other.groups

    def __str__(self):
        return "<Role {}>".format(self.rolename)

    def attrs(self):
        return ['rolename', 'roles']

class Group(Usermgmt):
    def __init__(self, groupname=None, gid=None):
        self.groupname = str(groupname)
        self.gid = str(gid)

    def __cmp__(self, other):
        return self.gid == other.gid and self.groupname == other.groupname

    def __eq__(self, other):
        return self.__cmp__(other)

    def attrs(self):
        return ['groupname', 'gid']

class User(Usermgmt):
    def __init__(self, username=None, hash_ldap=None, password_mod_date=None, email=None, uidNumber=None, public_keys=[], sshkey_mod_date=None, groups=[], auth_code=None, auth_code_date=None):
        self.username = str(username)
        self.hash_ldap = str(hash_ldap)
        self.password_mod_date = str(password_mod_date)
        self.email = str(email)
        self.uidNumber = str(uidNumber)
        if public_keys:
            self.public_keys = set(public_keys)
        else:
            self.public_keys = set()
        self.sshkey_mod_date = str(sshkey_mod_date)
        if groups:
            self.groups = set(sorted(groups))
        else:
            self.groups = set()
        self.auth_code= str(auth_code)
        self.auth_code_date = str(auth_code_date)

    def __eq__(self, other):
        return self.username == other.username and \
            self.hash_ldap == other.hash_ldap and \
            self.password_mod_date == other.password_mod_date and \
            self.email == other.email and \
            self.uidNumber == other.uidNumber and \
            self.public_keys == other.public_keys and \
            self.groups == other.groups and \
            self.auth_code == other.auth_code and \
            self.auth_code_date == other.auth_code_date

    def __cmp__(self, other):
        for a in self.attrs():
            self_a = getattr(self, a)
            other_a = getattr(other, a)
            if type(self_a) == list and type(other_a) == list or type(self_a) == set and type(other_a) == set:
                self_a = sorted(list(self_a))
                other_a = sorted(list(other_a))
            c = cmp(self_a, other_a)
            if c:
                return c
        return 0

    def attrs(self):
        return ['username', 'password', 'email', 'uidNumber', 'public_keys', 'groups', 'hash_ldap', 'password_mod_date', 'sshkey_mod_date', 'auth_code', 'auth_code_date']

    def set(self, attribute, value):
        attr = setattr(self, attribute, value)
        self.save()
        return True

    def check_password(self, password):
        return ( ldap_pbkdf2_sha256.identify(self.hash_ldap) and \
            ldap_pbkdf2_sha256.verify(password, self.hash_ldap) ) \
            or (ldap_salted_sha1.identify(self.hash_ldap) and \
            ldap_salted_sha1.verify(password, self.hash_ldap))

    def set_password(self, password):
        try:
            self.hash_ldap = ldap_pbkdf2_sha256.hash(password)
            self.password_mod_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
            self.auth_code = None
            self.auth_code_date = None
            self.save()
            return True
        except Exception as e:
            print("Exception: %s" % e)
            return False

    def validate_key(self, key):
        try:
            ssh = SSHKey(key)
            ssh.parse()
            return ssh
        except:
            return False

    def get_ssh_key_comment(self, key):
        ssh = SSHKey(key)
        ssh.parse()
        return ssh.comment

    def get_ssh_key_hash(self, key):
        ssh = SSHKey(key)
        ssh.parse()
        return ssh.hash_md5().split('MD5:').pop()

    def check_key_exist(self, key):
        for test_key in self.public_keys:
            if self.get_ssh_key_hash(key) == self.get_ssh_key_hash(test_key):
                return True
        return False

    def add_ssh_key(self, key):
        try:
            ssh = self.validate_key(key)
            if self.check_key_exist(key): return False
            self.public_keys.add(ssh.keydata)
            self.sshkey_mod_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
            self.save()
            return True
        except Exception as e:
            print(e)
            return False

    def remove_ssh_key(self, key):
        self.public_keys.discard(key)
        self.save()
        return True

    def remove_ssh_key_by_hash(self, hash_md5):
        key = self.find_key_by_hash(hash_md5)
        self.public_keys.discard(key)
        self.save()
        return True

    def find_key_by_hash(self, hash_md5):
        for key in self.public_keys:
            test_hash = self.get_ssh_key_hash(key)
            if hash_md5 == test_hash:
                return key
        return None

    def is_admin(self):
        return self.is_group_member('internal.admins') or self.is_group_member('unix.admins')

    def is_group_member(self, group):
        if group in self.groups:
            return True
        else:
            return False
