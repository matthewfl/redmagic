//#define _GNU_SOURCE
#include <dlfcn.h>

#include "compiler.h"

using namespace redmagic;


#include <iostream>
using namespace std;

#if 0

Compiler::Compiler(
#ifdef CONF_COMPILE_IN_PARENT
                   Tracer *tracer
#else
                   std::vector<JumpTrace> &&traces
#endif
                   ) {
#ifdef CONF_COMPILE_IN_PARENT
  _tracer = tracer;
  this->traces = std::move(_tracer->traces);
#else
  this->traces = std::move(traces);
#endif
}

unsigned char Compiler::readByte(mem_loc_t where) {
#ifdef CONF_COMPILE_IN_PARENT
  return _tracer->readByte(where);
#else
  // then we are in the same process as where we want to read from, so we can directly read
  return *(unsigned char*)where;
#endif
}

#ifdef CONF_COMPILE_IN_PARENT
# define OPT_TRACE_ARG _tracer,
#else
# define OPT_TRACE_ARG
#endif

#define EXTERN_SNIPPET(name)                    \
  extern "C" void name ## _start () ;           \
  extern "C" void name ## _end () ;             \
  const static size_t name ## _len =  ((mem_loc_t)& name ## _end) - ((mem_loc_t)& name ## _start) ;

EXTERN_SNIPPET(red_asm_decrease_stack_addr);
EXTERN_SNIPPET(red_asm_push_const_to_stack);


static void _self_filler_func() {}

void Compiler::Run() {
  vector<CodeBuffer> bufs;
  CodeBuffer target_buffer(4 * 1024 * 1024);
  Dl_info dlinfo, dlinfo_self;
  int r = dladdr((void*)&_self_filler_func, &dlinfo_self);
  assert(r);

  vector<mem_loc_t> forward_jumps;

#define CODEBUF_SNIPPET(snipname)      \
  CodeBuffer cb_snip_ ## snipname ( OPT_TRACE_ARG ((mem_loc_t)& snipname ## _start) , snipname ## _len) ;

#define REPLACE_FILLER(type, from, to)                                \
  {                                                                   \
    uint8_t did_replace = 0;                                          \
    type current_value = 0;                                           \
    size_t location = start_off;                                      \
    while(location < end_off) {                                       \
      current_value <<= 8;                                            \
      current_value |= target_buffer.readByte(location);              \
      if(current_value == from) {                                     \
        for(int _ii = sizeof(type) - 1; _ii >= 0; _ii--) {            \
          target_buffer.writeByte(location - _ii, to >> (8 * (sizeof(type) - _ii - 1))); \
        }                                                             \
        did_replace = 1;                                              \
        break;                                                        \
      }                                                               \
      location++;                                                     \
    }                                                                 \
    assert(did_replace);                                              \
  }

#define REPLACE_16(from, to) REPLACE_FILLER(uint16_t, from, to)
#define REPLACE_64(from, to) REPLACE_FILLER(uint64_t, from, to)


#define INSERT_SNIPPET(snipname, ...)                  \
  {                                                    \
    size_t start_off = target_buffer.getOffset();      \
    target_buffer.writeToEnd(cb_snip_ ## snipname);    \
    size_t end_off = target_buffer.getOffset();        \
    __VA_ARGS__ ;                                      \
  }

  CODEBUF_SNIPPET(red_asm_decrease_stack_addr);
  CODEBUF_SNIPPET(red_asm_push_const_to_stack);

  for(int i = 0; i < traces.size() - 1; i++) {
    JumpTrace tr = traces[i];
    JumpTrace nt = traces[i+1];
    // determine if this is something internal to redmagic
    // and should be ignored
    r = dladdr((void*)tr.ins_pc, &dlinfo);
    if(r && dlinfo.dli_fbase == dlinfo_self.dli_fbase) {
      // this is a symbol in redmagic so we are going to ignore it
      continue;
    }

    if(tr.check.check_register != -1) {
      // then this is not a conditional branch instruction
      if(tr.check.check_register == EFLAGS) {
        // this is some conditional jump

      }
    }
    if(tr.instruction == UD_Iretf || tr.instruction == UD_Iret) {
      // then we have to move the stack pointer
      INSERT_SNIPPET(red_asm_decrease_stack_addr,
                     REPLACE_16(0xfafa, 8);
                     );
      cout << "qwer";
    }
    if(tr.instruction == UD_Icall) {
      INSERT_SNIPPET(red_asm_push_const_to_stack,
                     REPLACE_64(0xfafafafafafafafa, tr.ins_pc + tr.ins_len);
                     );
    }


    CodeBuffer buf(OPT_TRACE_ARG tr.target_pc, nt.ins_pc - tr.target_pc);
    bufs.push_back(buf);

    target_buffer.writeToEnd(buf);



    cout << "test " << buf.getSize() << " " << target_buffer.getOffset() << endl;
  }



  cout << "finished making all the bufs\n";
}


namespace redmagic {
  // size_t relocate_code(ud_t *source, void *dest, size_t length, size_t output_limit) {
  //   size_t dest_len = 0;
  //   size_t processed_len = 0;
  //   while(processed_len < length && dest_len < output_limit) {
  //     processed_len += ud_disassemble(source);

  //     switch(ud_insn_mnemonic(source)) {

  //     }
  //   }

  //   return dest_len;

  // }

  static int64_t get_opr_val_signed(const ud_operand_t *opr) {
    switch(opr->size) {
    case 8:
      return opr->lval.sbyte;
    case 16:
      return opr->lval.sword;
    case 32:
      return opr->lval.sdword;
    case 64:
      return  opr->lval.sqword;
    default:
      assert(0);
    }
  }

  std::vector<mem_loc_t> find_jumps(ud_t *disassm, size_t size) {
    std::vector<mem_loc_t> ret;

    size_t processed = 0;
    while(processed < size) {
      uint64_t ilen = ud_disassemble(disassm);
      processed += ilen;
      uint64_t ioff = ud_insn_off(disassm);
      switch(ud_insn_mnemonic(disassm)) {
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
      case UD_Ijg:


      case UD_Ijcxz:
      case UD_Ijecxz:
      case UD_Ijrcxz:

      case UD_Ijmp:

      case UD_Icall:

        {
          const ud_operand_t *opr = ud_insn_opr(disassm, 0);
          if(opr->type == UD_OP_JIMM) {
            int64_t jmpo = get_opr_val_signed(opr);
            if(jmpo < 0 && -jmpo > (processed - ilen))
              ret.push_back(ioff);
            else if(jmpo > 0 && jmpo > (size - (processed - ilen)))
              ret.push_back(ioff);
          } else {
            ret.push_back(ioff);
          }
          // assuming that this would be a not allowed value?
          // maybe to a constant memory location?
          assert(opr->type != UD_OP_CONST);
          break;
        }

      case UD_Iiretw:
      case UD_Iiretd:
      case UD_Iiretq:
        // these should not be found
        perror("interupt return instructions?");

      case UD_Iret:
      case UD_Iretf:
        perror("return instruction");


      case UD_Iinvalid: {
        cerr << "no idea: " << ud_insn_hex(disassm) << endl;
      }

      default: { }
      }
    }

    return ret;
  }


  unsigned int find_clobbered_registers(ud_t *disassm, unsigned int found, unsigned int used, unsigned int count, size_t size) {
    size_t processed = 0;

#define SET_USED(x) {                           \
      if(x > 0) used = used | 1 << x;           \
    }

    SET_USED(RIP);
    SET_USED(EFLAGS);
    SET_USED(GS);
    SET_USED(FS);
    SET_USED(ES);
    SET_USED(DS);
    SET_USED(FS_BASE);
    SET_USED(GS_BASE);

    while(processed < size) {
      uint64_t ilen = ud_disassemble(disassm);
      processed += ilen;
      unsigned int clobbered = 0; // clobbered during this instruction
      for(int i = 0;; i++) {
        const ud_operand_t *opt = ud_insn_opr(disassm, i);
        if(opt == NULL)
          break;
        switch(ud_insn_mnemonic(disassm)) {

        case UD_Ixor:
          if(i == 0 && opt->type == UD_OP_REG) {
            const ud_operand_t *o2 = ud_insn_opr(disassm, 1);
            if(o2->type == UD_OP_REG && o2->base == opt->base) {
              int reg = ud_register_to_sys(opt->base);
              if(reg != -1) {
                clobbered |= 1 << reg;
                break;
              }
            }
          }
          goto processes_used;

        case UD_Ilea:
          if(i == 0 && opt->type == UD_OP_REG) {
            int reg = ud_register_to_sys(opt->base);
            if(reg != -1) {
              clobbered |= 1 << reg;
              break;
            }
          }
          goto processes_used;

        case UD_Imov:
        case UD_Imovapd:
        case UD_Imovaps:
        case UD_Imovbe:
        case UD_Imovd:
        case UD_Imovddup:
        case UD_Imovdq2q:
        case UD_Imovdqa:
        case UD_Imovdqu:
        case UD_Imovhlps:
        case UD_Imovhpd:
        case UD_Imovhps:
        case UD_Imovlhps:
        case UD_Imovlpd:
        case UD_Imovlps:
        case UD_Imovmskpd:
        case UD_Imovmskps:
        case UD_Imovntdq:
        case UD_Imovntdqa:
        case UD_Imovnti:
        case UD_Imovntpd:
        case UD_Imovntps:
        case UD_Imovntq:
        case UD_Imovq:
        case UD_Imovq2dq:
        case UD_Imovsb:
        case UD_Imovsd:
        case UD_Imovshdup:
        case UD_Imovsldup:
        case UD_Imovsq:
        case UD_Imovss:
        case UD_Imovsw:
        case UD_Imovsx:
        case UD_Imovsxd:
        case UD_Imovupd:
        case UD_Imovups:
        case UD_Imovzx:
          if(i == 0 && opt->type == UD_OP_REG) {
            int reg = ud_register_to_sys(opt->base);
            if(reg != -1) {
              clobbered != 1 << reg;
              break;
            }
          }
          goto processes_used;

        processes_used:
        default:
          if(opt->type == UD_OP_MEM) {
            if(opt->base != UD_NONE) {
              SET_USED(ud_register_to_sys(opt->base));
            }
            if(opt->index != UD_NONE) {
              SET_USED(ud_register_to_sys(opt->base));
            }
          } else if(opt->type == UD_OP_REG) {
            SET_USED(ud_register_to_sys(opt->base));
          }
          assert(opt->type != UD_OP_PTR);
        }

      }
      // do this afterwards since we might set and use a register twice in the same operation
      found = found | (clobbered & ~used);
      if(bits_set(found) >= count) {
        return found;
      }
    }
    return found;
  }

#undef SET_USED

}

#endif // 0
