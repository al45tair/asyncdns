import sys

if sys.platform == 'darwin':
    from .darwin import SystemResolver
elif sys.platform == 'win32':
    from .win32 import SystemResolver
else:
    from .unix import SystemResolver
