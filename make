#!/usr/bin/env python2

import sys
sys.path.insert(0, 'deps/fabricate/')

import glob
import subprocess
import os
from fabricate import *

TARGET = 'jit-test'

VERSION = '1.0.0'

UNIT_TARGET = 'build/unit_tests'

GIT_VERSION = Shell('git describe --always --long --dirty --abbrev=12', silent=True).strip()

C_FLAGS = (
    '-fPIC '
    #'-mgeneral-regs-only '
    '-ggdb '
    '-O0 '
    '-I ./deps/ '
    '-I ./deps/udis86 '
    '-I ./deps/asmjit/src '
    '-I ./build/ '
)
CXX_FLAGS = (
    '-std=c++14 '
    '-fno-exceptions '
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
    C_FLAGS += ' -DNDEBUG -DRED_RELEASE -fdata-sections -ffunction-sections -flto '
    LD_FLAGS += '-flto -O2 ' #-Wl,--gc-sections -Wl,--print-gc-sections '
    clean()
    build()
    Run('mkdir -p release')
    Run('cp build/libredmagic.so.{} release/'.format(VERSION))
    Run('cp src/redmagic.h release/')
    Run('strip --strip-unneeded -w -K redmagic_* release/libredmagic.so.{}'.format(VERSION))


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
    # we are not using the compiler interface, just the assembler
    asmjit_libs = ' '.join(filter(lambda x: 'compiler' not in x, glob.glob('build/asmjit/CMakeFiles/asmjit.dir/src/asmjit/*/*.o')))
    Run('{LD} {LD_FLAGS} -shared -fPIC -Wl,-Bsymbolic -Wl,-soname,libredmagic.so.{VERSION} -o build/libredmagic.so.{VERSION} {objs} {udis_libs} {asmjit_libs} {LIBS}'.format(
        **dict(globals(), **locals())
    ))
    after()
    Run('{LD} -o {TARGET} build/main.o build/libredmagic.so.{VERSION} -Wl,-rpath=$ORIGIN/build/'.format(
        **dict(globals(), **locals())
    ))
    after()

def compile():
    with open('build/build_version.h', 'w+') as f:
        f.write('''
#ifndef RED_BUILD_VERSION
#define RED_BUILD_VERSION "{}"
#define RED_OBJ_VERSION "{}"
#endif
        '''.format(GIT_VERSION, VERSION))

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
    if not os.path.isdir('build'):
        Shell('mkdir -p build')
    if not os.path.isfile('deps/udis86/libudis86/.libs/libudis86.so') or not os.path.isfile('deps/udis86/libudis86/itab.h'):
          Shell('cd deps/udis86 && ./autogen.sh && PYTHON=`which python2` ./configure && ' +
                #("sed -i '/^CFLAGS\ =/ s/$/\ \-flto/' Makefile &&" if RELEASE else '') +
                'make V=1 CFLAGS=' + ('"-Wall -O2 -flto"' if RELEASE else '"-Wall -ggdb"')
                , shell=True)
    if not os.path.isfile('build/asmjit/libasmjit.so'):
        Shell('mkdir -p build/asmjit')
        asm_flags = '\-fno-exceptions\ '  # -DASMJIT_ALLOC=test123
        cm_args = '-DASMJIT_DISABLE_COMPILER=1 -DASMJIT_CFLAGS=\'==REPLACE_ME==\' -DCMAKE_CXX_COMPILER=g++ -DCMAKE_C_COMPILER=gcc'
        if RELEASE:
            Shell('cd build/asmjit && cmake ../../deps/asmjit {} -DASMJIT_RELEASE=1'.format(cm_args), shell=True)
            asm_flags += '\-O2\ \-flto'
        else:
            Shell('cd build/asmjit && cmake ../../deps/asmjit {} -DASMJIT_DEBUG=1'.format(cm_args), shell=True)
            asm_flags += '\-ggdb'
        Shell('sed -i s/==REPLACE_ME==/{}/ build/asmjit/CMakeFiles/asmjit.dir/flags.make'.format(asm_flags), shell=True)
        Shell('cd build/asmjit && make VERBOSE=1', shell=True)
    after()


if __name__ == '__main__':
    main(parallel_ok=True)#, jobs=4)
