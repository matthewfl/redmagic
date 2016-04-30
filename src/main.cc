
#include <iostream>
#include <thread>

#include "redmagic.h"

#include <unistd.h>

using namespace std;

int main(int argc, char* argv[]) {

  redmagic_init();


  std::thread tt([]() {
  redmagic_start_trace(NULL);

  cout << "asdf\n";

  sleep(10);

  cout << "test123";

    });

  tt.join();
}
