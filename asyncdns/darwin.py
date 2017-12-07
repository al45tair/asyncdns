#
# A Darwin-specific SystemResolver implementation that watches the system
# configuration store to spot changes to the DNS server settings.
#
# Uses ctypes, rather than using C code, so this is still pure Python :-)
#
import ipaddress
from ctypes import *

from .resolver import Resolver, RoundRobinServer, RandomServer

sc = cdll.LoadLibrary('/System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration')
cf = cdll.LoadLibrary('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')
libSystem = cdll.LoadLibrary('/usr/lib/libSystem.dylib')

class _CFString(Structure):
    pass
class _CFDictionary(Structure):
    pass
class _CFArray(Structure):
    pass
class _CFAllocator(Structure):
    pass
class _CFType(Structure):
    pass

CFAllocatorRef = POINTER(_CFAllocator)
CFDictionaryRef = POINTER(_CFDictionary)
CFStringRef = POINTER(_CFString)
CFArrayRef = POINTER(_CFArray)
CFTypeRef = c_void_p
CFIndex = c_uint64

CFArrayRetainCallBack = POINTER(CFUNCTYPE(c_void_p, CFAllocatorRef, c_void_p))
CFArrayReleaseCallBack = POINTER(CFUNCTYPE(None, CFAllocatorRef, c_void_p))
CFArrayCopyDescriptionCallBack = POINTER(CFUNCTYPE(CFStringRef, c_void_p))
CFArrayEqualCallBack = POINTER(CFUNCTYPE(c_bool, c_void_p, c_void_p))

class CFArrayCallBacks(Structure):
    _fields_ = [("version", CFIndex),
                ("retain", CFArrayRetainCallBack),
                ("release", CFArrayReleaseCallBack),
                ("copyDescription", CFArrayCopyDescriptionCallBack),
                ("equal", CFArrayEqualCallBack)]

kCFTypeArrayCallBacks = CFArrayCallBacks.in_dll(cf, 'kCFTypeArrayCallBacks')

kCFStringEncodingUTF8 = 0x08000100

CFRetain = cf.CFRetain
CFRelease = cf.CFRelease
CFShow = cf.CFShow
CFRetain.argtypes = [c_void_p]
CFRelease.argtypes = [c_void_p]
CFShow.argtypes = [c_void_p]

CFStringCreateWithCString = cf.CFStringCreateWithCString
CFStringCreateWithCString.restype = CFStringRef
CFStringCreateWithCString.argtypes = [c_void_p, c_char_p, c_uint]

CFStringGetCStringPtr = cf.CFStringGetCStringPtr
CFStringGetCStringPtr.restype = c_char_p
CFStringGetCStringPtr.argtypes = [CFStringRef, c_uint]

CFStringGetCString = cf.CFStringGetCString
CFStringGetCString.restype = c_bool
CFStringGetCString.argtypes = [CFStringRef, c_char_p, c_size_t, c_uint]

CFArrayCreate = cf.CFArrayCreate
CFArrayCreate.restype = CFArrayRef
CFArrayCreate.argtypes = [CFAllocatorRef, POINTER(c_void_p), CFIndex,
                             POINTER(CFArrayCallBacks)]

CFArrayGetCount = cf.CFArrayGetCount
CFArrayGetCount.restype = CFIndex
CFArrayGetCount.argtypes = [CFArrayRef]

CFArrayGetValueAtIndex = cf.CFArrayGetValueAtIndex
CFArrayGetValueAtIndex.restype = CFTypeRef
CFArrayGetValueAtIndex.argtypes = [CFArrayRef, CFIndex]

CFDictionaryGetValue = cf.CFDictionaryGetValue
CFDictionaryGetValue.restype = CFTypeRef
CFDictionaryGetValue.argtypes = [CFDictionaryRef, CFTypeRef]

copyDescription_t = CFUNCTYPE(CFStringRef, c_void_p)
retain_t = CFUNCTYPE(c_void_p, c_void_p)
release_t = CFUNCTYPE(None, c_void_p)

class _SCDynamicStore(Structure):
    pass
SCDynamicStoreRef = POINTER(_SCDynamicStore)

class SCDynamicStoreContext(Structure):
    _fields_ = [("version", CFIndex),
                ("info", py_object),
                ("retain", POINTER(retain_t)),
                ("release", POINTER(release_t)),
                ("copyDescription", POINTER(copyDescription_t))]

SCDynamicStoreCallBack = CFUNCTYPE(None, SCDynamicStoreRef, CFArrayRef, c_void_p)

SCDynamicStoreCreate = sc.SCDynamicStoreCreate
SCDynamicStoreCreate.restype = SCDynamicStoreRef
SCDynamicStoreCreate.argtypes = [CFAllocatorRef, CFStringRef, SCDynamicStoreCallBack, POINTER(SCDynamicStoreContext)]

class _dispatch_queue(Structure):
    pass

dispatch_queue_t = POINTER(_dispatch_queue)

dispatch_get_global_queue = libSystem.dispatch_get_global_queue
dispatch_get_global_queue.restype = dispatch_queue_t
dispatch_get_global_queue.argtypes = [c_long, c_ulong]

DISPATCH_QUEUE_PRIORITY_LOW = -2

SCDynamicStoreSetDispatchQueue = sc.SCDynamicStoreSetDispatchQueue
SCDynamicStoreSetDispatchQueue.restype = c_bool
SCDynamicStoreSetDispatchQueue.argtypes = [SCDynamicStoreRef, dispatch_queue_t]

SCDynamicStoreSetNotificationKeys = sc.SCDynamicStoreSetNotificationKeys
SCDynamicStoreSetNotificationKeys.restype = c_bool
SCDynamicStoreSetNotificationKeys.argtypes = [SCDynamicStoreRef, CFArrayRef,
                                              CFArrayRef]

SCDynamicStoreCopyValue = sc.SCDynamicStoreCopyValue
SCDynamicStoreCopyValue.restype = CFTypeRef
SCDynamicStoreCopyValue.argtypes = [SCDynamicStoreRef, CFStringRef]

def CFSTR(s):
    return CFStringCreateWithCString(None, s.encode('utf8'),
                                     kCFStringEncodingUTF8)

_python_asyncdns = CFSTR('python-asyncdns')
_state_network_global_dns = CFSTR('State:/Network/Global/DNS')
_server_addresses = CFSTR('ServerAddresses')

def CFStringGetPythonString(cfstr):
    s = CFStringGetCStringPtr(cfstr, kCFStringEncodingUTF8)
    if s is None:
        tmp_size = 512
        tmp = create_string_buffer(tmp_size)
        if CFStringGetCString(cfstr, tmp, tmp_size, kCFStringEncodingUTF8):
            s = tmp.value
    return s

def _callback(store, changedKeys, context):
    resolver = cast(context, py_object).value
    resolver.servers_changed()

class SystemResolver(Resolver):

    def __init__(self):
        self._servers = None
        ctx = SCDynamicStoreContext(0, self, None, None, None)
        self._callback = SCDynamicStoreCallBack(_callback)
        self._dynamic_store = SCDynamicStoreCreate(None, _python_asyncdns,
                                                   self._callback,
                                                   byref(ctx))
        queue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_LOW, 0)
        SCDynamicStoreSetDispatchQueue(self._dynamic_store, queue)
        super(SystemResolver, self).__init__()
        self._start_watching()
        self._update_servers()

    def _start_watching(self):
        keys = (CFStringRef * 1)()
        keys[0] = _state_network_global_dns
        array = CFArrayCreate(None, cast(keys, POINTER(c_void_p)),
                              1, byref(kCFTypeArrayCallBacks))
        CFRelease(keys[0])
        SCDynamicStoreSetNotificationKeys(self._dynamic_store, array, None)
        CFRelease(array)

    def _stop_watching(self):
        SCDynamicStoreSetNotificationKeys(self._dynamic_store, None, None)

    def _update_servers(self):
        server_list = []
        dns = cast(SCDynamicStoreCopyValue(self._dynamic_store,
                                           _state_network_global_dns),
                   CFDictionaryRef)
        servers = cast(CFDictionaryGetValue(dns, _server_addresses),
                       CFArrayRef)
        count = CFArrayGetCount(servers)

        for n in range(0, count):
            server = cast(CFArrayGetValueAtIndex(servers, n), CFStringRef)
            s = CFStringGetPythonString(server)

            if s is not None:
                try:
                    s_ip = ipaddress.ip_address(s.decode('utf8'))
                    server_list.append((s_ip, 53))
                except ValueError:
                    pass

        CFRelease(dns)

        self._servers = RoundRobinServer(server_list)

    def __del__(self):
        CFRelease(self._dynamic_store)

    def servers_changed(self):
        self._update_servers()

    def lookup(self, query, should_cache=True, recursive=False,
               prefer_ipv6=False):
        return super(SystemResolver, self).lookup(query, self._servers,
                                                  should_cache,
                                                  recursive, prefer_ipv6)
