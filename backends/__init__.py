import usermgmtlib.backends
import usermgmtlib.backends
import importlib

def init_backend(name):
    return importlib.import_module("usermgmtlib.backends." + name).connection()

class Backend(object):
    def __init__(self):
        self.name = 'None'

    def __str__(self):
        return "<Backend {0}>".format(self.name)

    def get_users():
        raise NotImplementedError

    def get_groups():
        raise NotImplementedError
