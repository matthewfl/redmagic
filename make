#!/usr/bin/env python2

import sys
sys.path.insert(0, 'deps/fabricate/')

import glob
import subprocess
import os
from fabricate import *

TARGET = 'jit-test'

UNIT_TARGET = 'build/unit_tests'

CXX_FLAGS = (
    '-std=c++14 '
    '-I ./deps/ '
    '-ggdb '
    '-O0 '
    '-I ./deps/udis86'
    # '-I /home/matthew/Downloads/bochs-code/bochs/cpu/ '
    # '-I /home/matthew/Downloads/bochs-code/bochs/ '
    # '-I /home/matthew/Downloads/bochs-code/bochs/instrument/stubs '

)
CXX_FLAGS_UNIT = (
    '-I ./deps/catch/ '
    '-I ./src/ '
)
LIBS = (
    '-pthread '
    'deps/udis86/libudis86/.libs/libudis86.a '
    # '/home/matthew/Downloads/bochs-code/bochs/cpu/libcpu.a '
    # '/home/matthew/Downloads/bochs-code/bochs/logio.o '
    # '/home/matthew/Downloads/bochs-code/bochs/cpu/fpu/libfpu.a '
    # '/home/matthew/Downloads/bochs-code/bochs/cpu/cpudb/libcpudb.a '
    # '/home/matthew/Downloads/bochs-code/bochs/gui/libgui.a '

    # '-ljemalloc'
)
LD_FLAGS = ''
CXX='g++'
CC='gcc'
LD='g++'

def build():
    deps()
    compile()
    link()

def mic():
    global CXX, CXX_FLAGS, LD
    CXX_FLAGS += '-wd1478 '  # using dep std::smart pointer
    CXX = 'icpc'
    LD = 'icpc'

def release():
    global CXX_FLAGS
    CXX_FLAGS = CXX_FLAGS.replace('-O0', '-O3')
    CXX_FLAGS = CXX_FLAGS.replace('-ggdb', '')
    build()

def clean():
    Shell('cd deps/udis86 && make clean', shell=True)
    autoclean()

def run():
    build()
    Shell('./' + TARGET)

def debug():
    build()
    Shell('gdb ./{TARGET} --eval-command=run'.format(
        TARGET=TARGET
    ))

def link():
    objs = ' '.join(filter(lambda x: 'unit_' not in x, glob.glob('build/*.o')))
    Run('{CXX} {LD_FLAGS} -o {TARGET} {objs} {LIBS}'.format(
        **dict(globals(), **locals())
    ))
    after()

def compile():
    for f in glob.glob('src/*.cc'):
        Run('{CXX} {} -c {} -o {}'.format(
            CXX_FLAGS,
            f,
            f.replace('src', 'build').replace('.cc', '.o'),
            CXX=CXX
        ))
    Run('{CC} -c src/asm.s -o build/asm.o'.format(
        CC=CC
    ))
    after()

def unit_compile():
    for f in glob.glob('unit_tests/*.cc'):
        Run('{CXX} {} -c {} -o {}'.format(
            CXX_FLAGS + CXX_FLAGS_UNIT,
            f,
            f.replace('unit_tests/', 'build/unit_').replace('.cc', '.o'),
            CXX=CXX,
        ))

def unit_link():
    objs = ' '.join(filter(lambda x: '/main.o' not in x, glob.glob('build/*.o')))
    Run('{CXX} {LD_FLAGS} -o {UNIT_TARGET} {objs} {LIBS}'.format(
        **dict(globals(), **locals())
    ))
    after()

def unit():
    deps()
    unit_compile()
    compile()
    unit_link()
    Shell('./' + UNIT_TARGET)

def deps():
    # udis86 version 1.7.2
    if not os.path.isfile('deps/udis86/libudis86/.libs/libudis86.a'):
        Shell('cd deps/udis86 && ./configure && make', shell=True)
    after()


if __name__ == '__main__':
    main(parallel_ok=True)#, jobs=4)
