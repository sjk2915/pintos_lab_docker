/* Tries to mmap an invalid fd,
   which must either fail silently or terminate the process with
   exit code -1. */

#include "tests/lib.h"
#include "tests/main.h"
#include <syscall.h>

void test_main(void) {
  CHECK(mmap((void *)0x10000000, 4096, 0, 0x5678, 0) == MAP_FAILED,
        "try to mmap invalid fd");
}
