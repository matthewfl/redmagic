#include <iostream>

#include "config.h"
#include "bochs.h"
#include "cpu.h"

//#include "gui/siminterface.h"

using namespace std;


#if BX_SUPPORT_SMP
// multiprocessor simulation, we need an array of cpus
BOCHSAPI BX_CPU_C_PTR *bx_cpu_array = NULL;
# error "todo"
#else
// single processor simulation, so there's one of everything
BOCHSAPI BX_CPU_C bx_cpu;
#endif

bx_simulator_interface_c *SIM;

int simpleF() {
  return 42;
}

int main(int argc, char **argv) {

  SIM = new bx_simulator_interface_c();

  auto a = new BX_CPU_C(0);


  cout << "hello world\n";
}
