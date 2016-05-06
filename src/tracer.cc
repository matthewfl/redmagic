#include "jit_internal.h"

#ifndef __x86_64__
  #error "expecting 64 bit compile"
#endif

//#include <sys/time.h>

#include <assert.h>

#include <iostream>
using namespace std;

using namespace redmagic;

// convert a register from udis to sys/reg.h
static int ud_register_to_sys(ud_type t) {
  switch(t) {
  case UD_R_R15B:
  case UD_R_R15W:
  case UD_R_R15D:
  case UD_R_R15:
    return R15;
  case UD_R_R14B:
  case UD_R_R14W:
  case UD_R_R14D:
  case UD_R_R14:
    return R14;
  case UD_R_R13B:
  case UD_R_R13W:
  case UD_R_R13D:
  case UD_R_R13:
    return R13;
  case UD_R_R12B:
  case UD_R_R12W:
  case UD_R_R12D:
  case UD_R_R12:
    return R12;
  case UD_R_CH: // ??
  case UD_R_BP:
  case UD_R_EBP:
  case UD_R_RBP:
    return RBP;
  case UD_R_BL:
  case UD_R_BX:
  case UD_R_EBX:
  case UD_R_RBX:
    return RBX;
  case UD_R_R11B:
  case UD_R_R11W:
  case UD_R_R11D:
  case UD_R_R11:
    return R11;
  case UD_R_R10B:
  case UD_R_R10W:
  case UD_R_R10D:
  case UD_R_R10:
    return R10;
  case UD_R_R9B:
  case UD_R_R9W:
  case UD_R_R9D:
  case UD_R_R9:
    return R9;
  case UD_R_R8B:
  case UD_R_R8W:
  case UD_R_R8D:
  case UD_R_R8:
    return R8;
  case UD_R_AL:
  case UD_R_AX:
  case UD_R_EAX:
  case UD_R_RAX:
    return RAX;
  case UD_R_CL:
  case UD_R_CX:
  case UD_R_ECX:
  case UD_R_RCX:
    return RCX;
  case UD_R_DL:
  case UD_R_DX:
  case UD_R_EDX:
  case UD_R_RDX:
    return RDX;
  case UD_R_DH:
  case UD_R_SI:
  case UD_R_ESI:
  case UD_R_RSI:
    return RSI;
  case UD_R_BH:
  case UD_R_DI:
  case UD_R_EDI:
  case UD_R_RDI:
    return RDI;
    // orig rax
  case UD_R_RIP:
    // instrunction pointer??
    return RIP;
  case UD_R_CS:
    return CS;
    // eflags not directly accessable, use pushf and popf
  case UD_R_AH:
  case UD_R_SP:
  case UD_R_ESP:
  case UD_R_RSP:
    return RSP;
    // fsbase, gsbase
  case UD_R_DS:
    return DS;
  case UD_R_ES:
    return ES;
  case UD_R_FS:
    return FS;
  case UD_R_GS:
    return GS;
  default:
    return -1;
  }
}

namespace redmagic {
  int udis_input_hook(ud_t *ud) {
    Tracer* trace = (Tracer*)ud_get_user_opaque_data(ud);

    unsigned long loc = trace->read_offset++;

    // TODO: this looks like it can return 8 bytes at a time
    if(trace->read_cache_loc == loc & ~0x7) {
      // then we can just read the bytes from the cache
      return (trace->read_cache >> (8 * (loc & 0x7))) & 0xff;
    }

    long res = ptrace(PTRACE_PEEKDATA, trace->thread_pid, loc & ~0x7, NULL);
    trace->read_cache_loc = loc & ~0x7;
    trace->read_cache = res;
    int r = (res >> (8 * (loc & 0x7))) & 0xff;
    return r;

  }
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

void Tracer::start() {
  running_thread = std::thread([this](){
      this->run();
    });
}


void Tracer::run() {
  // define vars up here so we can use goto
  int res, stat;
  Check_struct reg_check;
  JumpTrace jtrace;
  register_t new_pc;
  Check_struct cs;
  mem_loc_t ins_loc;
  unsigned char replaced_dat;

  cerr << "tracer running " << thread_pid << endl << flush;

  if(ptrace(PTRACE_ATTACH, thread_pid, NULL, NULL) < 0) {
    perror("failed attach");
  }

  res = waitpid(thread_pid, &stat, WUNTRACED);
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

  res = waitpid(thread_pid, &stat, 0);

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

    res = waitpid(thread_pid, &stat, 0);
    // TODO: handle various states of this child process
    if(WIFEXITED(stat)) {
      return;
    }

    cerr << WIFEXITED(stat) << " " << WEXITSTATUS(stat) << " " << WIFSIGNALED(stat) << " " << WTERMSIG(stat) << " " << WIFSTOPPED(stat) << " " <<
      WSTOPSIG(stat) << " " << WIFCONTINUED(stat) << endl << flush;


    if(WSTOPSIG(stat) != SIGTRAP) {
      // then this is not the trap instruction that we are looking for
      // if(ptrace(PTRACE_CONT, thread_pid, NULL, NULL) < 0) {
      //   perror(
      // }

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
        exit(2);
        break;
      }
      case TEMP_DISABLE_ACT: {
        temp_disable = true;
        goto continue_program;
        break;
      }
      case TEMP_ENABLE_ACT: {
        temp_disable = false;
        if(!ud_disassemble(&disassm)) {
          perror("failed to skip int3");
          ::exit(1);
        }

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
        register_t rv = static_cast<register_t*>((void*)&regs)[reg_check.check_register];
        // need to read the value out of memory
        union {
          register_t rr;
          struct {
            int r1;
            int r2;
          };
        } ru;
        // reads one word at a time
        ru.r1 = ptrace(PTRACE_PEEKDATA, thread_pid, rv, NULL);
        ru.r2 = ptrace(PTRACE_PEEKDATA, thread_pid, ((char*)rv) + 4, NULL);
        reg_check.memory_value = ru.rr; //((r1 & 0xffffffff) << 32) | (r2 & 0xffffffff);
      } else {
        reg_check.register_value = static_cast<register_t*>((void*)&regs)[reg_check.check_register];
      }
    }

    /* JumpTrace jtrace; */
    jtrace.check = reg_check;
    jtrace.ins_pc = ud_insn_off(&disassm);
    jtrace.instruction = ud_insn_mnemonic(&disassm);

    if(ptrace(PTRACE_SINGLESTEP, thread_pid, NULL, NULL) < 0) {
      perror("failed to single step a branching instruction");
    }

    res = waitpid(thread_pid, &stat, 0);

    /*register_t*/ new_pc = ptrace(PTRACE_PEEKUSER, thread_pid, RIP * sizeof(register_t), NULL);
    jtrace.target_pc = new_pc;

    setOffset(new_pc);
    // read_offset = new_pc;
    // ud_set_pc(&disassm, new_pc);



    // TODO: save the check register and its value somewhere as well as the program counter


  locate_next_replace_instruction: ;


    // skip forward till we find the next instruction to
    /* Check_struct cs; */
    while(ud_disassemble(&disassm)) {
      cout << "[" << ud_insn_off(&disassm) << "] " << ud_insn_asm(&disassm) << " " << ud_insn_hex(&disassm) <<  endl << flush;
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
}

Check_struct Tracer::decode_instruction() {

  // register that should be check for this instrunction
  //int check_register = -1;

  Check_struct r = {0};

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
      assert(0);
      return r;
    } else {
      perror("what type is this??");
      break;
    }
  }

  case UD_Iiretw:
  case UD_Iiretd:
  case UD_Iiretq:
    // these should not be found
    perror("interupt return instructions?");

  case UD_Iret:
  case UD_Iretf: {
    // TODO: check if we are performing a more complicated type of jump?
    // TODO: there is a form of ret that takes an assembly instruction for poping a variable number of spaces on the stack http://repzret.org/p/repzret/
    r.check_register = -1;
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


unsigned char Tracer::readByte(mem_loc_t where) {
  // long res = ptrace(PTRACE_PEEKDATA, thread_pid, where & ~0x7, NULL);
  // return (res >> (8 * (where & 0x7))) & 0xff;

  long res = ptrace(PTRACE_PEEKDATA, thread_pid, where, NULL);
  return res & 0xff;
}

void Tracer::writeByte(mem_loc_t where, uint8_t b) {
  assert(readByte(140737351968729 - 7) != 0);
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
