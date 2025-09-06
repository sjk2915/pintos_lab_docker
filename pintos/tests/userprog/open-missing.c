/* Tries to open a nonexistent file. */

#include "tests/lib.h"
#include "tests/main.h"
#include <syscall.h>

void test_main(void) {
  int handle = open("no-such-file");
  if (handle != -1)
    fail("open() returned %d", handle);
}
