from logilab.astng import MANAGER, scoped_nodes
from logilab.astng.builder import ASTNGBuilder

FAKE_SH = """
def basename(*args, **kwargs): pass
def cat(*args, **kwargs): pass
def grep(*args, **kwargs): pass
class sh(object):
    def bake(*args, **kwargs): pass
class git(sh):
    def strip(*args, **kwargs): pass
class ssh(sh): pass
class ErrorReturnCode_255(Exception): pass
"""

def sh_transform(module):
    if module.name == 'sh':
        for name, items in ASTNGBuilder(MANAGER).string_build(FAKE_SH).locals.items():
            for item in items:
                item.parent = module

            module.locals[name] = items

        for item in ('ErrorReturnCode_128',):
            module.locals[item] = [scoped_nodes.Class(item, None)]

def register(linter):
    """
    Called when loaded by pylint --load-plugins, register our tranformation
    function here
    """
    MANAGER.register_transformer(sh_transform)
