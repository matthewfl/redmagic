#!/usr/bin/env python2

import sys
sys.path.insert(0, 'deps/fabricate/')

import glob
import subprocess
import os
from fabricate import *

TARGET = 'jit-test'

UNIT_TARGET = 'build/unit_tests'

GIT_VERSION = Shell('git describe --always --long --dirty --abbrev=12', silent=True).strip()

CXX_FLAGS = (
    '-fPIC '
    '-std=c++14 '
    '-I ./deps/ '
    '-ggdb '
    '-O0 '
    '-I ./deps/udis86 '
)
CXX_FLAGS_UNIT = (
    '-I ./deps/catch/ '
    '-I ./src/ '
)
LIBS = (
    '-pthread '
    '-ldl '
    '-Wl,-Bstatic -lboost_context -Wl,-Bdynamic '
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

def release():
    global CXX_FLAGS, LD_FLAGS
    CXX_FLAGS = CXX_FLAGS.replace('-O0', '-O2')
    CXX_FLAGS = CXX_FLAGS.replace('-ggdb', '')
    CXX_FLAGS += ' -DNDEBUG -fdata-sections -ffunction-sections -flto '
    LD_FLAGS += '-flto '
    build()
    Run('mkdir -p release')
    Run('cp build/libredmagic.so.1.0.0 release/')
    Run('cp src/redmagic.h release/')
    Run('strip --strip-unneeded -w -K redmagic_* release/libredmagic.so.1.0.0')


def clean():
    autoclean()
    Shell('cd deps/udis86 && make clean', shell=True)

def run():
    build()
    Shell('./' + TARGET)

def debug():
    build()
    Shell('gdb ./{TARGET} --eval-command=run'.format(
        TARGET=TARGET
    ))

def link():
    objs = ' '.join(filter(lambda x: 'unit_' not in x and 'main.o' not in x, glob.glob('build/*.o')))
    # Run('ar rcs build/redmagic.a {objs} {LIBRARY_LIBS}'.format(
    #     **dict(globals(), **locals())
    # ))
    udis_libs = ' '.join(glob.glob('deps/udis86/libudis86/.libs/*.o'))
    Run('{LD} {LD_FLAGS} -shared -fPIC -Wl,-soname,libredmagic.so.1.0.0 -o build/libredmagic.so.1.0.0 {objs} {udis_libs} {LIBS}'.format(
        **dict(globals(), **locals())
    ))
    after()
    Run('{LD} {LD_FLAGS} -o {TARGET} build/main.o build/libredmagic.so.1.0.0 -Wl,-rpath=$ORIGIN/build/'.format(
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
    # Run('{CC} -c src/asm.s -o build/asm.o'.format(
    #     CC=CC
    # ))
    # Run('{CC} -c src/asm_snippets.s -o build/asm_snippets.o'.format(
    #     CC=CC
    # ))
    Run('{CC} -c src/asm_interface.s -o build/asm_snippets.o'.format(
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
    if not os.path.isfile('deps/udis86/libudis86/.libs/libudis86.so') or not os.path.isfile('deps/udis86/libudis86/itab.h'):
        Shell('cd deps/udis86 && ./autogen.sh && PYTHON=`which python2` ./configure && make', shell=True)
    if not os.path.isfile('build'):
        Shell('mkdir -p build')
    after()


if __name__ == '__main__':
    main(parallel_ok=True)#, jobs=4)
