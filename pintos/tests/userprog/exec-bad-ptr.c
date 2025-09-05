/* Passes an invalid pointer to the exec system call.
   The process must be terminated with -1 exit code. */

#include "tests/main.h"
#include <syscall.h>

void test_main(void) { exec((char *)0x20101234); }
