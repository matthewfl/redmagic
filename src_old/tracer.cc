#include "jit_internal.h"

#ifndef __x86_64__
  #error "expecting 64 bit compile"
#endif


#ifdef CONF_COMPILE_IN_PARENT
# include "compiler.h"
#endif


//#include <sys/time.h>


#include <assert.h>

#include <iostream>
using namespace std;

using namespace redmagic;

extern "C" {
  void red_asm_return_after_method_call();
}



namespace redmagic {
  int udis_input_hook(ud_t *ud) {
    Tracer* trace = (Tracer*)ud_get_user_opaque_data(ud);

    mem_loc_t loc = trace->read_offset++;

    return trace->readByte(loc);
  }

#ifdef CONF_COMPILE_IN_PARENT
  extern Compiler *_global_compiler_pointer;
#endif
}



Tracer::Tracer(ParentManager *man, pid_t pid):
  manager(man), thread_pid(pid) {
  ud_init(&disassm);
  ud_set_user_opaque_data(&disassm, this);
  ud_set_input_hook(&disassm, udis_input_hook);
  ud_set_mode(&disassm, 64); // 64 bit
  ud_set_vendor(&disassm, UD_VENDOR_INTEL);
  ud_set_syntax(&disassm, UD_SYN_INTEL);


}

// void Tracer::start() {
//   running_thread = std::thread([this](){
//       this->run();
//     });
// }


void Tracer::run() {
  // define vars up here so we can use goto
  int res, stat;
  Check_struct reg_check;
  JumpTrace jtrace;
  register_t new_pc;
  Check_struct cs;
  mem_loc_t ins_loc;
  unsigned char replaced_dat;

  mem_loc_t current_replaced_loc = -1;
  mem_loc_t after_method_call_pc = -1;

  cerr << "tracer running " << thread_pid << endl << flush;

  if(ptrace(PTRACE_ATTACH, thread_pid, NULL, NULL) < 0) {
    perror("failed attach");
  }

  //res = waitpid(thread_pid, &stat, WUNTRACED);
  res = manager->waitpid(thread_pid, &stat);
  if((res != thread_pid) || !(WIFSTOPPED(stat))) {
    cerr << "unexpected state when beginning trace\n";
    ::exit(-1);
  }

  // this should currently be in a raise sigstop state, so we want to continue

#ifndef NDEBUG
  // double check the register
  struct user_regs_struct dcheck_regs;
  if(ptrace(PTRACE_GETREGS, thread_pid, &dcheck_regs, &dcheck_regs) < 0) {
      perror("failed to get regs");
  }
  // different internal raise?? I guess so can't directly check the memory addresses
  // uint64_t dcheck_diff = (uint64_t)&raise - (uint64_t)dcheck_regs.rip;
  // assert(dcheck_diff < 500);
#endif

  // have to single step it at least once otherwise it doesn't move on continue????????????????????????????????
  if((res = ptrace(PTRACE_SINGLESTEP, thread_pid, NULL, NULL)) < 0) {
    perror("failed single step");
    ::exit(1);
  }

  res = manager->waitpid(thread_pid, &stat);
  //res = waitpid(thread_pid, &stat, 0);

  if((res = ptrace(PTRACE_CONT, thread_pid, SIGCONT, SIGCONT)) < 0) {
    perror("failed cont1");
    ::exit(1);
  }

  // now we should be on the int3 instrunction that follows the raise

  cout << "attached: " << res << " " << stat << endl << flush;
  while(true) {
    // if((res = ptrace(PTRACE_SINGLESTEP, thread_pid, NULL, NULL)) < 0) {
    //   perror("failed single step");
    // }

    // if((res = ptrace(PTRACE_CONT, thread_pid, NULL, NULL)) < 0) {
    //   perror("failed cont");
    // }

    //res = waitpid(thread_pid, &stat, 0);
    res = manager->waitpid(thread_pid, &stat);
    // TODO: handle various states of this child process
    if(WIFEXITED(stat)) {
      ::exit(WEXITSTATUS(stat));
      return;
    }

    cerr << WIFEXITED(stat) << " " << WEXITSTATUS(stat) << " " << WIFSIGNALED(stat) << " " << WTERMSIG(stat) << " " << WIFSTOPPED(stat) << " " <<
      WSTOPSIG(stat) << " " << WIFCONTINUED(stat) << endl << flush;


    if(WSTOPSIG(stat) != SIGTRAP) {
      // then this is not the trap instruction that we are looking for
      // if(ptrace(PTRACE_CONT, thread_pid, NULL, NULL) < 0) {
      //   perror(
      // }

      // TODO: something clever
      ::exit(1);
    }

    // if(WTERMSIG(stat)) {
    //   assert(0);
    // }


    // by getting the whole struct we are avoiding more than 1 syscall
    // not sure if this is an advantage?
    struct user_regs_struct regs;
    if(ptrace(PTRACE_GETREGS, thread_pid, &regs, &regs) < 0) {
      perror("failed to get regs");
    }

    // reset this instruction since we would have just been interuppted with an int3

    // by default do the default action
    Int3_action act = NO_ACT;

    // -1 since int3 is 1 byte long, so we are going to the start of it
    setOffset(((mem_loc_t)regs.rip) - 1);

    //read_offset = ((mem_loc_t)regs.rip) - 1;
    // what we previously had at this location
    int prev_asm_ins = manager->get_program_pval(read_offset);
    //ud_set_pc(&disassm, read_offset);

    if(prev_asm_ins == -1) {
      // then we don't have this location saved?
      int i = 0;
      while(action_table[i].location != NULL) {
        // determine what action we should take
        // the memory location will be the position after the int3
        if(action_table[i].location == (void*)read_offset) {
          // then we should take this action
          act = action_table[i].act;
          break;
        }
        i++;
      }
      // what are we doing here
      assert(act != NO_ACT);
    } else {
      // invalidate the cache since we have to write back the correct byte
      // read_cache_loc = -1;
      current_replaced_loc = -1;
      writeByte(read_offset, (uint8_t)(prev_asm_ins & 0xff));
      // reset the location of the instruction pointer so that when we continue we will execute this instruction
      if(ptrace(PTRACE_POKEUSER, thread_pid, sizeof(register_t) * RIP, read_offset) < 0) {
        perror("failed to reset the instruction pointer");
      }
    }

    if(act != NO_ACT) {
      switch(act) {
      case BEGIN_TRACE_ACT: {
        // set the next break point and continue the thread
        // skip the int3 instruction since we want to keep that
        if(!ud_disassemble(&disassm)) {
          perror("failed to skip int3");
          ::exit(1);
        }
        goto locate_next_replace_instruction;

      }
      case END_TRACE_ACT: {
        // TODO:
        if(current_replaced_loc != -1) {
          int prev_asm_ins = manager->get_program_pval(current_replaced_loc);
          assert(prev_asm_ins != -1);
          writeByte(current_replaced_loc, (uint8_t)(prev_asm_ins & 0xff));
          current_replaced_loc = -1;
        }
        goto end_tracing;
      }
      case TEMP_DISABLE_ACT: {
        temp_disable = true;
        if(current_replaced_loc != -1) {
          int prev_asm_ins = manager->get_program_pval(current_replaced_loc);
          assert(prev_asm_ins != -1);
          writeByte(current_replaced_loc, (uint8_t)(prev_asm_ins & 0xff));
          current_replaced_loc = -1;
        }
        goto continue_program;
      }
      case TEMP_ENABLE_ACT: {
        temp_disable = false;
        if(!ud_disassemble(&disassm)) {
          perror("failed to skip int3");
          ::exit(1);
        }

        goto locate_next_replace_instruction;
      }
      case RETURN_FROM_METHOD_ACT: {
        // returned from a method that we were not tracing
        setOffset(after_method_call_pc);
        if(ptrace(PTRACE_POKEUSER, thread_pid, sizeof(register_t) * RIP, after_method_call_pc) < 0) {
          perror("failed to set rip after intercepted method return");
        }
        after_method_call_pc = -1;
        goto locate_next_replace_instruction;
      }
      }
    }

    if(temp_disable) {
      // TODO: have to continue the loop
      goto continue_program;
    }

    // record the instruction current state and where it ends up next

    if(!(res = ud_disassemble(&disassm))) {
      perror("failed to dissassm");
    }
    /*Check_struct*/ reg_check = decode_instruction();
    if(reg_check.check_register == -2) {
      perror("this is not a branching instruction, something went wrong");
      ::exit(1);

    }
    if(reg_check.check_register >= 0) {
      if(reg_check.check_memory) {
        // the location in memory that we are interested in
        // TODO: have to deal with offsets from memory addresses
        register_t rv = static_cast<register_t*>((void*)&regs)[reg_check.check_register];

        // TODO: this can read 8 bytes so we don't need the second call
        // need to read the value out of memory
        union {
          register_t rr;
          struct {
            int r1;
            int r2;
          };
        } ru;
        // reads one word at a time
        // ru.r1 = ptrace(PTRACE_PEEKDATA, thread_pid, rv, NULL);
        // ru.r2 = ptrace(PTRACE_PEEKDATA, thread_pid, ((char*)rv) + 4, NULL);
        // reg_check.memory_value = ru.rr; //((r1 & 0xffffffff) << 32) | (r2 & 0xffffffff);
        assert(reg_check.scale_register == -1);

        reg_check.memory_value = ptrace(PTRACE_PEEKDATA, thread_pid, rv + reg_check.memory_offset, NULL);
      } else {
        reg_check.register_value = static_cast<register_t*>((void*)&regs)[reg_check.check_register];
      }
    }

    /* JumpTrace jtrace; */
    jtrace.op = INST_TRACE_OP;
    jtrace.check = reg_check;
    jtrace.ins_pc = ud_insn_off(&disassm);
    jtrace.instruction = ud_insn_mnemonic(&disassm);
    jtrace.ins_len = ud_insn_len(&disassm);

    if(ptrace(PTRACE_SINGLESTEP, thread_pid, NULL, NULL) < 0) {
      perror("failed to single step a branching instruction");
    }

    res = manager->waitpid(thread_pid, &stat);
    //res = waitpid(thread_pid, &stat, 0);

    /*register_t*/ new_pc = ptrace(PTRACE_PEEKUSER, thread_pid, RIP * sizeof(register_t), NULL);
    jtrace.target_pc = new_pc;

    if(jtrace.instruction == UD_Icall) {
      // check if we are in a method call that we want to ignore
      if(manager->is_ignored_method(new_pc) || new_pc == (register_t)&malloc) {
        // this is an ignored method
        register_t sp = ptrace(PTRACE_PEEKUSER, thread_pid, RSP * sizeof(register_t), NULL);
        after_method_call_pc = ptrace(PTRACE_PEEKDATA, thread_pid, sp, NULL);
        if(ptrace(PTRACE_POKEDATA, thread_pid, sp, &red_asm_return_after_method_call) < 0) {
          perror("failed to set return address after ignored method");
        }
        goto continue_program;
      }
    }

    // save this tracing operation
    traces.push_back(jtrace);


    setOffset(new_pc);
    // read_offset = new_pc;
    // ud_set_pc(&disassm, new_pc);



    // TODO: save the check register and its value somewhere as well as the program counter


  locate_next_replace_instruction:


    // skip forward till we find the next instruction to
    /* Check_struct cs; */
    while(ud_disassemble(&disassm)) {
      cout << "[0x" << std::hex << ud_insn_off(&disassm) << std::dec << "] " << ud_insn_asm(&disassm) << "\t" << ud_insn_hex(&disassm) <<  endl << flush;
      cs = decode_instruction();
      if(cs.check_register != -2)
        break;
    }

    /*mem_loc_t*/ ins_loc = ud_insn_off(&disassm);
    /*unsigned char*/ replaced_dat = readByte(ins_loc);

    if(replaced_dat == 0xCC) {
      cerr << "the data that we are replacing is an int3??\n";
      ::exit(1);
    }

    manager->set_program_pval(ins_loc, replaced_dat);

    assert(current_replaced_loc == -1);
    current_replaced_loc = ins_loc;
    writeByte(ins_loc, (uint8_t)0xCC);


  continue_program:
    // if(ptrace(PTRACE_SINGLESTEP, thread_pid, NULL, NULL) < 0) {
    //   //
    //   perror("failed to single step after interuppted");
    // }
    if(ptrace(PTRACE_CONT, thread_pid, NULL, NULL) < 0) {
      perror("failed to continue program");
    }


    // cout << "\t" << num_ins++ << " " <<
    //   //"\t[" << time.tv_sec << "." << time.tv_usec << "]\t" <<
    //   ud_insn_asm(&disassm) << endl;


  }

 end_tracing:

#ifdef CONF_COMPILE_IN_PARENT
  // this thread has the program suspended at this point and should be able to perform reads of its memory from this thread
  // so run the compiler from here

  auto compiler = new Compiler(this);
compiler->Run();
  _global_compiler_pointer = compiler;
#endif

  if(ptrace(PTRACE_CONT, thread_pid, NULL, NULL) < 0) {
    perror("failed to continue after done ptrace");
  }

  // this is suppose to continue the trace once detached
  // however it seems to just leave the process in a frozen state

  //#ifndef CONF_COMPILE_IN_PARENT
  // we can't detach since we still need this connection to read from the programs memory

  if(ptrace(PTRACE_DETACH, thread_pid, NULL, NULL) < 0) {
    perror("failed to detach ptrace");
  }
  //#error "wth"
  //#endif

  cout << "finished the trace\n";

  // indicate that we are done
  // should not return
  manager->waitpid(-1, NULL);

  // need to send the results of the traced back to the main running program
}

Check_struct Tracer::decode_instruction() {

  // register that should be check for this instrunction
  //int check_register = -1;

  Check_struct r = {0};
  r.scale_register = -1;
  r.check_register = -1;

  switch(ud_insn_mnemonic(&disassm)) {
  case UD_Ijo:
  case UD_Ijno:
  case UD_Ijb:
  case UD_Ijae:
  case UD_Ijz:
  case UD_Ijnz:
  case UD_Ijbe:
  case UD_Ija:
  case UD_Ijs:
  case UD_Ijns:
  case UD_Ijp:
  case UD_Ijnp:
  case UD_Ijl:
  case UD_Ijge:
  case UD_Ijle:
  case UD_Ijg: {
    r.check_register = EFLAGS;
    r.check_memory = false;
    return r;
  }
  case UD_Ijcxz:
  case UD_Ijecxz:
  case UD_Ijrcxz: {
    //check_register = RCX;
    r.check_register = RCX;
    r.check_memory = false;
    return r;
  }
  case UD_Ijmp: {
    const ud_operand_t *opr = ud_insn_opr(&disassm, 0);
    if(opr == NULL || opr->type == UD_OP_IMM || opr->type == UD_OP_JIMM) {
      r.check_register = -1;
      r.check_memory = false;
      return r;
    }
    if(opr->type == UD_OP_REG) {
      r.check_register = ud_register_to_sys(opr->base);
      if(r.check_register == RIP) {
        // then this is set to be a PIC instruction which we don't care about
        r.check_register = -1;
      }
      r.check_memory = false;
      return r;
    }
    if(opr->type == UD_OP_MEM) {
      r.check_register = ud_register_to_sys(opr->base);
      if(r.check_register == RIP) {
        r.check_register = -1;
        return r;
      }
      // TODO: check that this is the right thing to do
      r.check_memory = true;
      r.memory_offset = opr->lval.uqword;
      return r;
    }

    assert(0);
  }

    // jump instrunctions

  case UD_Icall: {
    // determine if a register or memory is being used
    // and if so which reigster
    int nopr = 0;
    while(ud_insn_opr(&disassm, nopr) != NULL) nopr++;

    if(nopr == 1) {
      const ud_operand_t *opr = ud_insn_opr(&disassm, 0);
      if(opr->type == UD_OP_JIMM) {
        // this performs a call to a constant location
        r.check_register = -1;
        r.check_memory = false;
        return r;
      } else if(opr->type == UD_OP_REG) {
        r.check_register = ud_register_to_sys(opr->base);
        r.check_memory = false;
        return r;
      } else if(opr->type == UD_OP_MEM) {
        r.check_register = ud_register_to_sys(opr->base);
        r.check_memory = true;
        switch(opr->offset) {
        case 8:
          r.memory_offset = opr->lval.sbyte;
          break;
        case 16:
          r.memory_offset = opr->lval.sword;
          break;
        case 32:
          r.memory_offset = opr->lval.sdword;
          break;
        case 64:
          r.memory_offset = opr->lval.sqword;
          break;
        default:
          assert(0);
        }
        return r;
      } else {
        perror("what type is this??");
        break;
      }
    } else {
      assert(0);
    }
  }

  case UD_Iiretw:
  case UD_Iiretd:
  case UD_Iiretq: {
    // these should not be found
    perror("interupt return instructions?");

    ::exit(1);
  }
  case UD_Iret:
  case UD_Iretf: {
    // TODO: check if we are performing a more complicated type of jump?
    // TODO: there is a form of ret that takes an assembly instruction for poping a variable number of spaces on the stack http://repzret.org/p/repzret/

    // controls how much the stack pointer should change by in addition
    // currently not setup to handle this
    const ud_operand_t *opr = ud_insn_opr(&disassm, 0);
    assert(opr == NULL);

    r.check_register = -1;
    //r.memory_offset = -sizeof(mem_loc_t);
    r.check_memory = false;
    return r;
  }

  case UD_Iinvalid: {
    cerr << "no idea: " << ud_insn_hex(&disassm) << endl;
  }

  default: {
    // this is not an instruction that we care about
    r.check_register = -2;
    r.check_memory = false;
    return r;
  }
  }

  r.check_register = -2;
  r.check_memory = false;
  return r;



}


unsigned char Tracer::readByte(mem_loc_t loc) {
  // long res = ptrace(PTRACE_PEEKDATA, thread_pid, where & ~0x7, NULL);
  // return (res >> (8 * (where & 0x7))) & 0xff;

  // long res = ptrace(PTRACE_PEEKDATA, thread_pid, where, NULL);
  // return res & 0xff;


  if(read_cache_loc == loc & ~0x7) {
      // then we can just read the bytes from the cache
    return (read_cache >> (8 * (loc & 0x7))) & 0xff;
  }

  long res = ptrace(PTRACE_PEEKDATA, thread_pid, loc & ~0x7, NULL);
  if(errno) {
    perror("failed to read memory");
    assert(!errno);
  }
  read_cache_loc = loc & ~0x7;
  read_cache = res;
  int r = (res >> (8 * (loc & 0x7))) & 0xff;
  return r;

}

void Tracer::writeByte(mem_loc_t where, uint8_t b) {
  //assert(readByte(140737351968729 - 7) != 0);
  read_cache_loc = -1;
  long ores = ptrace(PTRACE_PEEKDATA, thread_pid, where & ~0x7, NULL);
  long res = ((long)b) << (8 * (where & 0x7)) | ((~(((long)0xff) << (8 * (where & 0x7)))) & ores);
  if(ptrace(PTRACE_POKEDATA, thread_pid, where & ~0x7, res) < 0) {
    perror("failed to write byte");
  }

#ifndef NDEBUG
  long res2 = ptrace(PTRACE_PEEKDATA, thread_pid, where & ~0x7, NULL);
  assert(res == res2);
  long res3 = ptrace(PTRACE_PEEKDATA, thread_pid, where, NULL);
  assert((uint8_t)(res3 & 0xff) == b);

  assert(readByte(140737351968729 - 7) != 0);
#endif
}


void Tracer::setOffset(mem_loc_t where) {
  read_offset = where;
  ud_set_pc(&disassm, where);
}


int Tracer::getSteps() {
  return traces.size();
}

void Tracer::writeTrace(int fn) {
  char *buf = (char*)traces.data();
  size_t len = traces.size() * sizeof(JumpTrace);
  if(write(fn, buf, len) != len) {
    perror("failed to write the trace");
  }
}
