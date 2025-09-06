/* Open a file. */

#include "tests/lib.h"
#include "tests/main.h"
#include <syscall.h>

void test_main(void) {
  int handle = open("sample.txt");
  if (handle < 2)
    fail("open() returned %d", handle);
}
