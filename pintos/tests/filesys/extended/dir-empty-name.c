/* Tries to create a directory named as the empty string,
   which must return failure. */

#include "tests/lib.h"
#include "tests/main.h"
#include <syscall.h>

void test_main(void) { CHECK(!mkdir(""), "mkdir \"\" (must return false)"); }
