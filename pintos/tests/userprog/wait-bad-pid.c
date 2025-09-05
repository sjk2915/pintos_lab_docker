/* Waits for an invalid pid.  This may fail or terminate the
   process with -1 exit code. */

#include "tests/main.h"
#include <syscall.h>

void test_main(void) { wait((pid_t)0x0c020301); }
