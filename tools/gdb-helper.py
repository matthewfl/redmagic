#!/usr/bin/env python3

# load using source tools/gdb-helper.py

import gdb


class TraceJumps(gdb.Command):

    def __init__(self):
        super().__init__("trace-jumps", gdb.COMMAND_USER)

    def invoke(self, args, from_tty):
        argv = gdb.string_to_argv(args)

        redmagic_info = gdb.execute('info shared redmagic', to_string=True).split()
        redmagic_start = int(redmagic_info[7], 16)
        redmagic_end = int(redmagic_info[8], 16)

        branches_taken = []

        def get_rip():
            return int(gdb.parse_and_eval('$rip'))

        current_rip = get_rip()

        while True:
            last_rip = current_rip
            if redmagic_start < last_rip < redmagic_end:
                gdb.execute('n', to_string=True)
                current_rip = get_rip()
            else:
                gdb.execute('si', to_string=True)
                current_rip = get_rip()
                if not (0 < current_rip - last_rip < 15):
                    # then we probably have taken a branch or something
                    li = gdb.execute('x/i {}'.format(last_rip), to_string=True)
                    if '__tls_get_addr' not in li:
                        gdb.write(li)


TraceJumps()
