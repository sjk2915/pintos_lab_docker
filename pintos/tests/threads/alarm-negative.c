/* Tests timer_sleep(-100).  Only requirement is that it not crash. */

#include "devices/timer.h"
#include "tests/threads/tests.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include <stdio.h>

void test_alarm_negative(void) {
  timer_sleep(-100);
  pass();
}
