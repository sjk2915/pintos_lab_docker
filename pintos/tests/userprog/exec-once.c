/* Executes and waits for a single child process. */

#include "tests/lib.h"
#include "tests/main.h"
#include <syscall.h>

void test_main(void) {
  msg("I'm your father");
  exec("child-simple");
}
