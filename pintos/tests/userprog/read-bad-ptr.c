/* Passes an invalid pointer to the read system call.
   The process must be terminated with -1 exit code. */

#include "tests/lib.h"
#include "tests/main.h"
#include <syscall.h>

void test_main(void) {
  int handle;
  CHECK((handle = open("sample.txt")) > 1, "open \"sample.txt\"");

  read(handle, (char *)0xc0100000, 123);
  fail("should not have survived read()");
}
