/* Tries to open a file with the empty string as its name. */

#include "tests/lib.h"
#include "tests/main.h"
#include <syscall.h>

void test_main(void) {
  int handle = open("");
  if (handle != -1)
    fail("open() returned %d instead of -1", handle);
}
