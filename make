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

C_FLAGS = (
    '-fPIC '
    '-I ./deps/ '
    '-ggdb '
    '-O0 '
    '-I ./deps/udis86 '
    '-I ./deps/asmjit/src '
)
CXX_FLAGS = (
    '-std=c++14 '
)
CXX_FLAGS_UNIT = (
    '-I ./deps/catch/ '
    '-I ./src/ '
)
LIBS = (
    '-pthread '
    '-ldl '
    #'-Wl,-Bstatic -lboost_context -Wl,-Bdynamic '
    # '-ljemalloc'
)
LD_FLAGS = '-Wl,--wrap=malloc -Wl,--wrap=free -Wl,--wrap=realloc -Wl,--wrap=calloc '
CXX='g++'
CC='gcc'
LD='g++'
RELEASE = False

def build():
    deps()
    compile()
    link()

def release():
    global C_FLAGS, LD_FLAGS, RELEASE
    RELEASE = True
    C_FLAGS = C_FLAGS.replace('-O0', '-O2')
    C_FLAGS = C_FLAGS.replace('-ggdb', '')
    C_FLAGS += ' -DNDEBUG -fdata-sections -ffunction-sections -flto '
    LD_FLAGS += '-flto ' #-Wl,--gc-sections -Wl,--print-gc-sections '
    clean()
    build()
    Run('mkdir -p release')
    Run('cp build/libredmagic.so.1.0.0 release/')
    Run('cp src/redmagic.h release/')
    Run('strip --strip-unneeded -w -K redmagic_* release/libredmagic.so.1.0.0')


def clean():
    autoclean()
    Shell('cd deps/udis86 && make clean', shell=True)
    Shell('rm -rf build/asmjit')

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
    # we are not using the compiler interface, just the assembler, would be nice if we could strip all the functions
    asmjit_libs = ' '.join(filter(lambda x: 'compiler' not in x, glob.glob('build/asmjit/CMakeFiles/asmjit.dir/src/asmjit/*/*.o')))
    Run('{LD} {LD_FLAGS} -shared -fPIC -Wl,-Bsymbolic -Wl,-soname,libredmagic.so.1.0.0 -o build/libredmagic.so.1.0.0 {objs} {udis_libs} {asmjit_libs} {LIBS}'.format(
        **dict(globals(), **locals())
    ))
    after()
    Run('{LD} -o {TARGET} build/main.o build/libredmagic.so.1.0.0 -Wl,-rpath=$ORIGIN/build/'.format(
        **dict(globals(), **locals())
    ))
    after()

def compile():
    for f in glob.glob('src/*.cc'):
        Run('{CXX} {} -c {} -o {}'.format(
            C_FLAGS + CXX_FLAGS,
            f,
            f.replace('src', 'build').replace('.cc', '.o'),
            CXX=CXX
        ))
    for f in glob.glob('src/*.c'):
        Run('{CC} {} -c {} -o {}'.format(
            C_FLAGS,
            f,
            f.replace('src', 'build').replace('.c', '.o'),
            CC=CC,
        ))
    # Run('{CC} -c src/asm.s -o build/asm.o'.format(
    #     CC=CC
    # ))
    for s in ['asm_snippets.S', 'asm_interface.S']:
        Run('{CC} -c src/{fname} -o build/{cname}'.format(
            CC=CC,
            fname=s,
            cname=s.replace('.S', '.o')
        ), group='asm_snippet1-{}'.format(s)
        )
        # Run("sed -i '\"s/NL/\\\n/g\"' build/{}".format(s.replace('.S', '.s')),
        #     group='asm_snippet2-{}'.format(s),
        #     after='asm_snippet1-{}'.format(s)
        # )
        # Run('{CC} -fPIC -c build/{fname} -o build/{oname}'.format(
        #     CC=CC,
        #     fname=s.replace('.S', '.s'),
        #     oname=s.replace('.S', '.o'),
        # ), after='asm_snippet2-{}'.format(s))

    # Run('{CC} -c src/asm_snippets.S -o build/asm_snippets.o'.format(
    #     CC=CC
    # ))
    # Run('{CC} -c src/asm_interface.S -o build/asm_interface.o'.format(
    #     CC=CC
    # ))
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
    if not os.path.isdir('build'):
        Shell('mkdir -p build')
    if not os.path.isfile('deps/udis86/libudis86/.libs/libudis86.so') or not os.path.isfile('deps/udis86/libudis86/itab.h'):
          Shell('cd deps/udis86 && ./autogen.sh && PYTHON=`which python2` ./configure && make', shell=True)
    if not os.path.isfile('build/asmjit/libasmjit.so'):
        Shell('mkdir -p build/asmjit')
        asm_flags = ''  # -DASMJIT_ALLOC=test123
        if RELEASE:
            Shell('cd build/asmjit && cmake ../../deps/asmjit -DASMJIT_DISABLE_COMPILER=1 -DASMJIT_CFLAGS=\'==REPLACE_ME==\' -DASMJIT_RELEASE=1', shell=True)
            asm_flags += '\-O2'
        else:
            Shell('cd build/asmjit && cmake ../../deps/asmjit -DASMJIT_DISABLE_COMPILER=1 -DASMJIT_CFLAGS=\'==REPLACE_ME==\' -DASMJIT_DEBUG=1', shell=True)
            asm_flags += '\-ggdb'
        Shell('sed -i s/==REPLACE_ME==/{}/ build/asmjit/CMakeFiles/asmjit.dir/flags.make'.format(asm_flags), shell=True)
        Shell('cd build/asmjit && make VERBOSE=1', shell=True)
    after()


if __name__ == '__main__':
    main(parallel_ok=True)#, jobs=4)
