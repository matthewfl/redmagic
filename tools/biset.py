#!/usr/bin/env python3

import sys
import subprocess
import os
import time
from collections import deque



def do_run(instruction_count, process, error_search):
    env = os.environ.copy()
    env['REDMAGIC_GLOBAL_ABORT'] = str(instruction_count)

    cnt = 0
    qu = deque([], maxlen=600)

    proc = subprocess.Popen(process, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)

    try:
        for li in proc.stdout:
            qu.append(li)
            if cnt % 50000 == 0:
                print(instruction_count, li)
            cnt += 1
    finally:
        proc.kill()

        ending = '\n'.join(map(str, qu))
        print(ending)

        if any([e in ending for e in error_search]):
            print('FAILED')
            return False
        else:
            print('SUCCESS')
            return True


def main():
    max_i = int(sys.argv[-1])
    min_i = int(sys.argv[-2])

    assert max_i > min_i

    error_search = ['IndexError', 'Assertion', 'SIGSEGV', 'Traceback']
    #process = '/home/matthew/developer/cpython/python -m IPython -c exit()'.split()
    # run under gdb since the program seems to change behavor depending on how it is run
    process = ['gdb', '/home/matthew/developer/cpython/python', '--eval-command=run -m IPython -c "exit()"', '--eval-command=quit']

    try:
        while max_i - min_i > 2:
            inst = (max_i + min_i) // 2
            print('>>>>>>>>>>>>>>>>>>>running bisect stopping at instruction {} ({}, {}, {})'.format(inst, min_i, max_i, max_i - min_i))
            time.sleep(5)
            r = do_run(inst, process, error_search)
            if r:
                min_i = inst
            else:
                max_i = inst
    finally:
        print(min_i, max_i)




if __name__ == '__main__':
    main()
