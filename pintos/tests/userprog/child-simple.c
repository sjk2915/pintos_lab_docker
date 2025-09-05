/* Child process run by exec-multiple, exec-one, wait-simple, and
   wait-twice tests.
   Just prints a single message and terminates. */

#include "tests/lib.h"
#include <stdio.h>

int main(void) {
  test_name = "child-simple";

  msg("run");
  return 81;
}
