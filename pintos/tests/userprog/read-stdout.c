/* Try reading from fd 1 (stdout),
   which may just fail or terminate the process with -1 exit
   code. */

#include "tests/main.h"
#include <stdio.h>
#include <syscall.h>

void test_main(void) {
  char buf;
  read(STDOUT_FILENO, &buf, 1);
}
