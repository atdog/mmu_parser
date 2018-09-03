#!/usr/bin/env python

from pwn import *

pid = 57564
start = 0x7f03ebb4e000

r = open("/proc/{}/mem".format(pid), 'rb')
r.seek(start)
mem = r.read(0x400000)
tbl = mem[0xa000:]

def expr(v):
    r = ''
    if v & 4:
        r += " U"
    else:
        r += " K"
    if v & 2:
        r += " RW"
    else:
        r += " RO"
    if v & 1:
        r += " P"
    else:
        r += " N"
    return r.lstrip(' ')

h = {}
attr = {}

for i in xrange(512):
    pgpt = u64(tbl[8*i:8*i+8])
    if pgpt == 0:
        continue
    print "pml4t[{:-3d}]: {:016x} {}".format(i, pgpt, expr(pgpt))
    pgpt = (pgpt >> 12) << 12

    pgpt_tbl = mem[pgpt:]
    for j in xrange(512):
        pdt = u64(pgpt_tbl[8*j:8*j+8])
        if pdt == 0:
            continue
        print "\tpdpt[{:-3d}]: {:016x} {}".format(j, pdt, expr(pdt))
        pdt = (pdt >> 12) << 12

        pdt_tbl = mem[pdt:]
        for k in xrange(512):
            pt = u64(pdt_tbl[8*k:8*k+8])
            if pt == 0:
                continue
            print "\t\tpdt[{:-3d}]: {:016x} {}".format(k, pt, expr(pt))
            pt = (pt >> 12) << 12

            pt_tbl = mem[pt:]
            for l in xrange(512):
                phy = u64(pt_tbl[8*l:8*l+8])
                if phy == 0 or phy ^ 1 == 0:
                    continue
                virt = (i << 39) + (j << 30) + (k << 21) + (l << 12)
                print "\t\t\tpt[{:-3d}]: phy {:016x} - virt {:016x} {}".format(l, phy, virt, expr(phy))
                attr[virt] = expr(phy)
                phy = (phy >> 12) << 12
                if not h.has_key(phy):
                    h[phy] = []
                h[phy].append(virt)
print
print "[duplicated entries]"
import sys
import collections
od = collections.OrderedDict(sorted(h.items()))
for phy, virt in od.iteritems():
    if len(virt) > 1:
        sys.stdout.write("{:016x} -".format(phy))
        for v in virt:
            sys.stdout.write(" {:016x} [{}]".format(v, attr[v]))
        print
