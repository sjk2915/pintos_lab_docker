/* Wait for a subprocess to finish. */

#include "tests/lib.h"
#include "tests/main.h"
#include <syscall.h>

void test_main(void) {
  int pid;
  if ((pid = fork("child-simple"))) {
    msg("wait(exec()) = %d", wait(pid));
  } else {
    exec("child-simple");
  }
}
