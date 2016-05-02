#include "jit_internal.h"

#ifndef __x86_64__
  #error "expecting 64 bit compile"
#endif

//#include <sys/time.h>

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

    if(trace->read_cache_loc == loc & ~0x3) {
      // then we can just read the bytes from the cache
      return (trace->read_cache >> (8 * (loc & 0x3))) & 0xff;
    }

    long res = ptrace(PTRACE_PEEKDATA, trace->thread_pid, loc, NULL);
    trace->read_cache_loc = loc & ~0x3;
    trace->read_cache = res;
    return (res >> (8 * (loc & 0x3))) & 0xff;

    // TODO: cache the result of this since we get 4 bytes at a time
    // TODO: check that we are reading the correct byte and not off by 3
    //return res & 0xff;

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
  cerr << "tracer running " << thread_pid << endl << flush;
  int res, stat;

  if(ptrace(PTRACE_ATTACH, thread_pid, NULL, NULL) < 0) {
    perror("failed attach");
  }

  res = waitpid(thread_pid, &stat, WUNTRACED);
  if((res != thread_pid) || !(WIFSTOPPED(stat))) {
    cerr << "unexpected state when beginning trace\n";
    ::exit(-1);
  }
  cout << "attached: " << res << " " << stat << endl << flush;
  while(!exit) {
    if((res = ptrace(PTRACE_SINGLESTEP, thread_pid, NULL, NULL)) < 0) {
      perror("failed single step");
    }
    // if(ptrace(PTRACE_CONT, thread_pid, NULL, NULL) < 0) {
    //   cerr << "failed continue\n";
    // }
    res = waitpid(thread_pid, &stat, 0);
    // TODO: handle various states of this child process
    if(WIFEXITED(stat)) {
      exit = true;
      return;
    }

    // by getting the whole struct we are avoiding more than 1 syscall
    // not sure if this is an advantage?
    struct user_regs_struct regs;
    if(ptrace(PTRACE_GETREGS, thread_pid, &regs, &regs) < 0) {
      perror("failed to get regs");
    }

    // reset this instruction since we would have just been interuppted with an int3

    // by default do the default action
    Int3_action act = NO_ACT;

    read_offset = regs.rip;
    int prev_asm_ins = manager->get_program_pval((void*)regs.rip);
    if(prev_asm_ins == -1) {
      // then we don't have this location saved?
      int i = 0;
      while(action_table[i].location != NULL) {
        // determine what action we should take
        if(action_table[i].location == (void*)regs.rip) {
          // then we should take this action
          act = action_table[i].act;
          break;
        }
        i++;
      }

    } else {
      // invalidate the cache since we have to write back the correct byte
      read_cache_loc = -1;
      writeByte((void*)regs.rip, (unsigned char)(prev_asm_ins & 0xff));
    }
    ud_set_pc(&disassm, regs.rip);


    if(!(res = ud_disassemble(&disassm))) {
      perror("failed to dissassm");
    }
    Check_struct reg_check = decode_instruction();
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


    // TODO: save the check register and its value somewhere as well as the program counter


    // skip forward till we find the next instruction to
    // while(ud_disassemble(&disassm) && (res = decode_instruction()) != -2)
    //   ;

    // if(res == -2) {
    //   perror("have somehow hit the end of the decoding stream without finding some jump");
    // }






    // // struct timeval time;

    // // gettimeofday(&time, NULL);

    cout << "\t" << num_ins++ << " " <<
      //"\t[" << time.tv_sec << "." << time.tv_usec << "]\t" <<
      ud_insn_asm(&disassm) << endl;
  }
}

Check_struct Tracer::decode_instruction() {

  // register that should be check for this instrunction
  //int check_register = -1;

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
    Check_struct r;
    r.check_register = EFLAGS;
    r.check_memory = false;
    return r;
  }
  case UD_Ijcxz:
  case UD_Ijecxz:
  case UD_Ijrcxz: {
    //check_register = RCX;
    Check_struct r;
    r.check_register = RCX;
    r.check_memory = false;
    return r;
  }
  case UD_Ijmp: {
    Check_struct r;
    r.check_register = -1;
    r.check_memory = false;
    return r;
  }

    // jump instrunctions

  case UD_Icall: {
    // determine if a register or memory is being used
    // and if so which reigster
    const ud_operand_t *opr = ud_insn_opr(&disassm, 0);
    if(opr->type == UD_OP_JIMM) {
      // this performs a call to a constant location
      Check_struct r;
      r.check_register = -1;
      r.check_memory = false;
      return r;
    } else if(opr->type == UD_OP_REG) {
      Check_struct r;
      r.check_register = ud_register_to_sys(opr->base);
      r.check_memory = false;
      return r;
    } else if(opr->type == UD_OP_MEM) {
      Check_struct r;
      r.check_register = ud_register_to_sys(opr->base);
      r.check_memory = true;
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
    Check_struct r;
    r.check_register = -1;
    r.check_memory = false;
    return r;
  }

  default: {
    // this is not an instruction that we care about
    Check_struct r;
    r.check_register = -2;
    r.check_memory = false;
    return r;
  }
  }

  Check_struct r;
  r.check_register = -2;
  r.check_memory = false;
  return r;



}


unsigned char Tracer::readByte(void* where) {
  unsigned long w = (unsigned long)where;
  long res = ptrace(PTRACE_PEEKDATA, thread_pid, w & ~0x3, NULL);
  return (res >> (8 * (w & 0x3))) & 0xff;
}

void Tracer::writeByte(void* where, unsigned char b) {
  unsigned long w = (unsigned long)w;
  long res = ptrace(PTRACE_POKEDATA, thread_pid, w & ~0x3, NULL);


}
