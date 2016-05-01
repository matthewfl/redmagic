
#include <iostream>
#include <thread>

#include "redmagic.h"

#include <unistd.h>

using namespace std;

int main(int argc, char* argv[]) {

  // will perform a fork internally
  redmagic_init();

  cout << "asdf\n";

  sleep(1);

  asm("int3");

  cout << "test123";

  sleep(1);

}
