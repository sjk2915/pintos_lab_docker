/* Tries to create a file with the same name as an existing
   directory, which must return failure. */

#include "tests/lib.h"
#include "tests/main.h"
#include <syscall.h>

void test_main(void) {
  CHECK(mkdir("abc"), "mkdir \"abc\"");
  CHECK(!create("abc", 0), "create \"abc\" (must return false)");
}
