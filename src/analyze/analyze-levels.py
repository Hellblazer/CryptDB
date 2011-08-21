#!/usr/bin/python

import sys, collections

field_ciphers = collections.defaultdict(set)

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
    cipherset_count[str(sorted(cs))] += 1

for cs in sorted(cipherset_count, key=lambda cs: cipherset_count[cs]):
    print cs, cipherset_count[cs]

