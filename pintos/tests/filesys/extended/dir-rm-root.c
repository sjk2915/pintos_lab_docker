/* Try to remove the root directory.
   This must fail. */

#include "tests/lib.h"
#include "tests/main.h"
#include <syscall.h>

void test_main(void) {
  CHECK(!remove("/"), "remove \"/\" (must fail)");
  CHECK(create("/a", 243), "create \"/a\"");
}
