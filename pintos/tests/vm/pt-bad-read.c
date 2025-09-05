/* Reads from a file into a bad address.
   The process must be terminated with -1 exit code. */

#include "tests/lib.h"
#include "tests/main.h"
#include <syscall.h>

void test_main(void) {
  int handle;

  CHECK((handle = open("sample.txt")) > 1, "open \"sample.txt\"");
  read(handle, (char *)&handle - 4096, 1);
  fail("survived reading data into bad address");
}
