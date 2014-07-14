#!/usr/bin/env python2

from os.path import join
from os import listdir, readlink, kill
from re import match, search
from time import sleep
import logging

class Hunter(object):
    _root = '/proc'
    _page = 4*1024
    def __init__(self, images, t, sink):
        self._images = images
        self._sink = sink
        self._t = t
        self._blacklist = set()
        self._logger = logging.getLogger('Hunter')

    def scan(self):
        seen = set()
        for d in listdir(self._root):
            if not match(r'\d+', d):
                continue

            seen.add(d)
            if d in self._blacklist:
                continue

            try:
                exe = readlink(join(self._root, d, 'exe'))
                with open(join(self._root, d, 'statm')) as f:
                    mem = int(f.read().split()[1]) * self._page
            except OSError as e:
                self._logger.info('OSError on %s: %s', d, e)
                self._blacklist.add(d)
                continue
                
            for re in self._images:
                if search(re, exe):
                    break
            else:
                continue
            self._sink(int(d), exe, mem)
        self._blacklist.intersection_update(seen)

    def run(self):
        while True:
            self.scan()
            sleep(self._t)

class Killer(object):
    def __init__(self, limit):
        self._limit = limit
        self._logger = logging.getLogger('Killer')

    def check(self, pid, exe, memory):
        if memory <= self._limit:
            return
        self._logger.info('Killing %s, %s, %s', pid, exe, memory)
        kill(pid, 9)

def daemonize():
    from os import fork, chdir, setsid, umask, getpid, dup2
    from sys import stdout, stderr, stdin, exit
    if fork():
        exit(0)
    chdir("/")
    setsid()
    umask(0)
    if fork():
        exit(0)
    stdout.flush()
    stderr.flush()
    n1 = open('/dev/null', 'r')
    n2 = open('/dev/null', 'w')
    dup2(n1.fileno(), stdin.fileno())
    dup2(n2.fileno(), stdout.fileno())
    dup2(n2.fileno(), stderr.fileno())
    return getpid()

def main():
    from argparse import ArgumentParser
    parser = ArgumentParser(description='I kill processes :3')
    parser.add_argument('filters', metavar='RE', nargs='+', help='Regular expressions, to match against executable path')
    parser.add_argument(
        '--limit', metavar='BYTES', type=int, help='Maximal RES memory, before process is killed', default=100*1024*1024
    )
    parser.add_argument('-t', metavar='SECONDS', type=float, help='Poll frequency', default=1)
    parser.add_argument('--daemon', metavar='PID', help='Daemonize and write pid to file', default=None)
    parser.add_argument('--log', metavar='LOG', help='Log file', default=None)
    args = parser.parse_args()
    
    if (not args.daemon) or args.log:
        largs = {
            'level': logging.INFO,
            'format': '%(asctime)s %(message)s'
        }
        if args.log:
            largs['filename'] = args.log
        logging.basicConfig(**largs)

    if args.daemon:
        with open(args.daemon, 'w') as pid_file:
            logging.info('Daemonizing...')
            pid = daemonize()
            pid_file.write(str(pid))
    k = Killer(args.limit)
    h = Hunter(args.filters, args.t, k.check)
    h.run()

if __name__ == '__main__':
    main()
