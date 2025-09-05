/* Tries to open a file with the null pointer as its name.
   The process must be terminated with exit code -1. */

#include "tests/main.h"
#include <stddef.h>
#include <syscall.h>

void test_main(void) { open(NULL); }
