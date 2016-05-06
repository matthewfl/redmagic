
#include <iostream>
#include <thread>

#include "redmagic.h"

#include <unistd.h>

using namespace std;

int main(int argc, char* argv[]) {

  // will perform a fork internally
  // to be called as early as possible
  redmagic_start();

  redmagic_force_begin_trace();

  cout << "asdf\n";

  sleep(2);

  //asm("int3");

  cout << "test123";

  sleep(1);

}
