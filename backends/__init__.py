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

class Singleton(type):
    def __init__(cls, name, bases, dict):
        super(Singleton, cls).__init__(name, bases, dict)
        cls.instance = None

    def __call__(cls,*args,**kw):
        if cls.instance is None:
            cls.instance = super(Singleton, cls).__call__(*args, **kw)
        return cls.instance
