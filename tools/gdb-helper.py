#!/usr/bin/env python3

# load using source tools/gdb-helper.py
# helpful to set: set pagination off

# for gdb attach
# echo 0 > /proc/sys/kernel/yama/ptrace_scope

import gdb
import time
import traceback


class TraceJumps(gdb.Command):

    def __init__(self):
        super().__init__("trace-jumps", gdb.COMMAND_USER)

    def invoke(self, args, from_tty):
        argv = gdb.string_to_argv(args)

        redmagic_info = gdb.execute('info shared redmagic', to_string=True).split('\n')[-2].split()
        redmagic_start = int(redmagic_info[0], 16)
        redmagic_end = int(redmagic_info[1], 16)

        verbose = False

        branches_taken = []

        def get_rip():
            return int(gdb.parse_and_eval('$rip'))

        # so that we can determine where it is resuming the trace
        gdb.execute('break red_asm_resume_eval_block')

        current_rip = get_rip()

        while True:
            last_rip = current_rip
            if not verbose and redmagic_start < last_rip < redmagic_end:
                li = gdb.execute('x/i {}'.format(last_rip), to_string=True)
                if 'red_asm_resume_eval_block' in li:
                    gdb.execute('si', to_string=True)
                else:
                    gdb.execute('n', to_string=True)
                current_rip = get_rip()
            else:
                gdb.execute('si', to_string=True)
                current_rip = get_rip()
                if not (0 < current_rip - last_rip < 15):
                    # then we probably have taken a branch or something
                    li = gdb.execute('x/i {}'.format(last_rip), to_string=True)
                    if verbose or ('__tls_get_addr' not in li and '_dl_addr' not in li):
                        #branches_taken.append(li)
                        gdb.write(li)

TraceJumps()


class LocateFirstValue(gdb.Command):

    def __init__(self):
        super().__init__("local-first-value", gdb.COMMAND_USER)

    def invoke(self, args, from_tty):
        argv = gdb.string_to_argv(args)

        redmagic_info = gdb.execute('info shared redmagic', to_string=True).split('\n')[-2].split()
        redmagic_start = int(redmagic_info[0], 16)
        redmagic_end = int(redmagic_info[1], 16)

        search = argv[0]

        verbose = False

        gdb.execute('break red_asm_resume_eval_block')

        while True:
            rip = int(gdb.parse_and_eval('$rip'))
            if redmagic_start < rip < redmagic_end:
                li = gdb.execute('x/i {}'.format(rip), to_string=True)
                if 'red_asm_resume_eval_block' in li:
                    gdb.execute('si', to_string=True)
                else:
                    gdb.execute('n', to_string=True)
            else:
                regs_info = gdb.execute('info all-registers', to_string=True)
                if search in regs_info:
                    stack = gdb.execute('bt', to_string=True)
                    # filter out methods that are called from the tracer such as memcpy etc
                    if 'red_asm_begin_block' not in stack:
                        sr = '\n\t'.join([r for r in regs_info.split('\n') if search in r])
                        gdb.write('search pattern found in: \n\t{}'.format(sr))
                        return
                gdb.execute('si', to_string=True)


LocateFirstValue()



# class BisectTrace(gdb.Command):
#     # NOTE: this doesn't fully work, gdb will produce strange results some times

#     def __init__(self):
#         super().__init__("trace-bisect", gdb.COMMAND_USER)

#     def invoke(self, args, from_tty):
#         argv = args.split()

#         success_break = int(argv[0])
#         failure_break = int(argv[1])

#         # current_max_instruction = int(argv[2]) // 2
#         # current_instruction_change_size = current_max_instruction // 2
#         current_high = int(argv[2])
#         current_low = 0

#         last_break_point_info = {}

#         def get_breakpoint():
#             # determine which breakpoint we hit
#             nonlocal last_break_point_info
#             bp_cnts = {}
#             info = gdb.execute('info break', to_string=True).split('\n')
#             print(info)
#             i = 0
#             while i < len(info):
#                 try:
#                     bi = int(info[i].split()[0])
#                     if 'already hit' in info[i + 1]:
#                         cnt = int(info[i+1].split()[3])
#                     else:
#                         cnt = 0
#                     bp_cnts[bi] = cnt
#                 except (ValueError, IndexError):
#                     pass
#                 i += 1
#             r = None
#             for bi, v in bp_cnts.items():
#                 if last_break_point_info.get(bi) != v:
#                     r = bi
#             last_break_point_info = bp_cnts
#             print(bp_cnts)
#             return r

#         try:
#             while current_high - current_low > 2:
#                 try:
#                     # kernel kill so that we don't deal with random cleanup code
#                     gdb.execute('signal 9')
#                     #gdb.execute('kill')
#                 except gdb.error as e:
#                     pass
#                 get_breakpoint()
#                 stop_i = (current_high + current_low) // 2
#                 print('\n='*15)
#                 print('current instruction at {}'.format(stop_i))
#                 print('\n='*15)
#                 time.sleep(5)
#                 set_count = True
#                 try:
#                     gdb.execute('run')  # will use the run arguments from the previous time
#                     while True:
#                         # del bp
#                         # try:
#                         #     bp = int(gdb.parse_and_eval('$bpnum'))
#                         # except gdb.error:
#                         #     print('failed to get breakpoint num')
#                         #     break
#                         bp = get_breakpoint()
#                         print('at breakpoint number {}'.format(bp))
#                         time.sleep(2)
#                         if bp == success_break:
#                             # we were successful
#                             current_low = stop_i
#                             print('successful run')
#                             break
#                         elif bp == failure_break:
#                             current_high = stop_i
#                             print('failure run')
#                             break
#                         else:
#                             if set_count:
#                                 gdb.execute('set redmagic::global_icount_abort = {}'.format(stop_i))
#                                 set_count = False
#                             gdb.execute('c')
#                 except gdb.error:
#                     time.sleep(2)
#                     pass
#         except Exception as e:
#             print(e)
#             traceback.print_exc(10)
#         finally:
#             gdb.write('error instruction: {} {}'.format(current_high, current_low))
#             print('current instruction at {} {}'.format(current_high, current_low))


# BisectTrace()
