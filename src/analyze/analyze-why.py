#!/usr/bin/python

import sys, collections, multiprocessing, gzip

def do_parse(fn):
    reason_fields = collections.defaultdict(set)
    f = gzip.open(fn)
    while True:
        l = f.readline()
        if l == '':
            return reason_fields

        w = l.strip().split(' ')
        
        w = l.strip().split(' ')
        if len(w) < 4 or w[0] != 'FIELD' or w[2] != 'CIPHER' or w[3] != enctype:
            continue

        field = w[1]
        cipher = w[3]
        reason = w[6]
        reason_fields[reason].add(field)

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print 'Usage:', sys.argv[0], 'enctype-to-explain parsed-all/*.gz'
        sys.exit(0)

    enctype = sys.argv[1]
    files = sys.argv[2:]

    p = multiprocessing.Pool(processes = len(files))

    merged = collections.defaultdict(set)
    for x in p.map(do_parse, files):
        for k in x:
            merged[k].update(x[k])

    for reason in merged:
        print '%9d' % len(merged[reason]), reason

