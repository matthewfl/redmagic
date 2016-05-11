
#include <iostream>
#include <thread>

#include "redmagic.h"

#include <unistd.h>

using namespace std;

int main(int argc, char* argv[]) {

  // will perform a fork internally
  // to be called as early as possible
  redmagic_start();

  sleep(1);

  redmagic_force_begin_trace((void*)123);

  cout << "asdf\n";

  sleep(2);

  char *a = (char*)malloc(1000);
  *a = 1;

  //asm("int3");

  redmagic_temp_disable();

  cout << "test123";

  redmagic_temp_enable();

  sleep(1);

  redmagic_force_end_trace((void*)123);



}
