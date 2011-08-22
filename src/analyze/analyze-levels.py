#!/usr/bin/python

import sys, collections

field_ciphers = collections.defaultdict(set)
collapse_ciphers = True

while True:
    l = sys.stdin.readline()
    if l == '':
        break

    w = l.strip().split(' ')
    if len(w) != 4 or w[0] != 'FIELD' or w[2] != 'CIPHER':
        continue

    f = w[1]
    c = w[3]
    field_ciphers[f].add(c)

cipherset_count = collections.defaultdict(int)

for cs in field_ciphers.itervalues():
    if collapse_ciphers:
        if len(cs) > 1 and 'any' in cs: cs.remove('any')
        if 'plain' in cs: cs = ['plain']
        if 'order' in cs and 'order_soft' in cs: cs.remove('order_soft')
        if 'order' in cs and 'equal' in cs: cs.remove('equal')
    cipherset_count[str(sorted(cs))] += 1

for cs in sorted(cipherset_count, key=lambda cs: cipherset_count[cs]):
    print '%9d' % cipherset_count[cs], cs

