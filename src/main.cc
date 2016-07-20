
#include <iostream>
#include <thread>

#include "redmagic.h"

#include <unistd.h>

using namespace std;

enum {
  PRINT_NUM,
  JUMP_BACK,
  EXIT,
  COND_JUMP,
  COND_SET,
  COND_ADD,
};

int main(int argc, char* argv[]) {

  // will perform a fork internally
  // to be called as early as possible


  redmagic_start();

  int program2[] = {
    PRINT_NUM, 0,
    JUMP_BACK, 0,
    EXIT,
  };

  int program[] = {
    PRINT_NUM, 0,
    COND_SET, 100,
    PRINT_NUM, 1,
    COND_ADD, -1,
    COND_JUMP, 4,  // print num
    EXIT,
  };

  // sleep(1);

  // init so that the dynamic resolve doesn't cause an early abort
  redmagic_fellthrough_branch((void*)123123);

  int pc = 0;

  int cond_var = 0;

  while(1) {
    switch(program[pc]) {
    case PRINT_NUM:
      //redmagic_temp_disable();
      cout << program[pc + 1] << endl;
      //redmagic_temp_enable();
      //printf("%i\n", program[pc + 1]);
      pc += 2;
      break;
    case JUMP_BACK:
      redmagic_backwards_branch((void*)pc);
      pc = program[pc + 1];
      break;
    case COND_JUMP:
      if(cond_var != 0) {
        redmagic_backwards_branch((void*)pc);
        pc = program[pc + 1];
      } else {
        redmagic_fellthrough_branch((void*)pc);
        pc += 2;
      }
      break;
    case COND_SET:
      cond_var = program[pc + 1];
      pc += 2;
      break;
    case COND_ADD:
      cond_var += program[pc + 1];
      pc += 2;
      break;
    case EXIT:
      cout << "hitting normal exit case\n";
      exit(0);
    default:
      exit(-1);
    }
  }


  // redmagic_force_begin_trace((void*)123);

  // cout << "asdf\n";

  // sleep(2);

  // char *a = (char*)malloc(1000);
  // *a = 1;

  // //asm("int3");

  // redmagic_temp_disable();

  // cout << "test123";

  // redmagic_temp_enable();

  // sleep(1);

  // redmagic_force_end_trace((void*)123);


  cout << "program exiting\n";


}
