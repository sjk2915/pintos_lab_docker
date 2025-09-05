/* Wait for a process that will be killed for bad behavior. */

#include "tests/lib.h"
#include "tests/main.h"
#include <syscall.h>

void test_main(void) {
  pid_t child;
  if ((child = fork("child-bad"))) {
    msg("wait(exec()) = %d", wait(child));
  } else {
    exec("child-bad");
  }
}
