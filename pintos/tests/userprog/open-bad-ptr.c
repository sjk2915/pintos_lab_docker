/* Passes an invalid pointer to the open system call.
   The process must be terminated with -1 exit code. */

#include "tests/lib.h"
#include "tests/main.h"
#include <syscall.h>

void test_main(void) {
  msg("open(0x20101234): %d", open((char *)0x20101234));
  fail("should have called exit(-1)");
}
