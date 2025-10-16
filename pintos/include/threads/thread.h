#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "threads/interrupt.h"
#include "threads/fixed-point.h"
#ifdef USERPROG
#include "threads/synch.h"
#endif
#ifdef VM
#include "vm/vm.h"
#endif

/* States in a thread's life cycle. */
enum thread_status
{
    THREAD_RUNNING, /* Running thread. */
    THREAD_READY,   /* Not running but ready to run. */
    THREAD_BLOCKED, /* Waiting for an event to trigger. */
    THREAD_DYING    /* About to be destroyed. */
};

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) - 1) /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0      /* Lowest priority. */
#define PRI_DEFAULT 31 /* Default priority. */
#define PRI_MAX 63     /* Highest priority. */

/* Predefined fd handles. */
#define STDIN_FDNO (struct file *)1
#define STDOUT_FDNO (struct file *)2

#define IS_STDIO(filep) ((filep) == STDIN_FDNO || (filep) == STDOUT_FDNO) ? true : false

#define INITIAL_FDT_SIZE 4
#define MAX_FDT_SIZE 512

#define MAX(a, b) (a) > (b) ? (a) : (b)

/* A kernel thread or user process.
 *
 * Each thread structure is stored in its own 4 kB page.  The
 * thread structure itself sits at the very bottom of the page
 * (at offset 0).  The rest of the page is reserved for the
 * thread's kernel stack, which grows downward from the top of
 * the page (at offset 4 kB).  Here's an illustration:
 *
 *      4 kB +---------------------------------+
 *           |          kernel stack           |
 *           |                |                |
 *           |                |                |
 *           |                V                |
 *           |         grows downward          |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           +---------------------------------+
 *           |              magic              |
 *           |            intr_frame           |
 *           |                :                |
 *           |                :                |
 *           |               name              |
 *           |              status             |
 *      0 kB +---------------------------------+
 *
 * The upshot of this is twofold:
 *
 *    1. First, `struct thread' must not be allowed to grow too
 *       big.  If it does, then there will not be enough room for
 *       the kernel stack.  Our base `struct thread' is only a
 *       few bytes in size.  It probably should stay well under 1
 *       kB.
 *
 *    2. Second, kernel stacks must not be allowed to grow too
 *       large.  If a stack overflows, it will corrupt the thread
 *       state.  Thus, kernel functions should not allocate large
 *       structures or arrays as non-static local variables.  Use
 *       dynamic allocation with malloc() or palloc_get_page()
 *       instead.
 *
 * The first symptom of either of these problems will probably be
 * an assertion failure in thread_current(), which checks that
 * the `magic' member of the running thread's `struct thread' is
 * set to THREAD_MAGIC.  Stack overflow will normally change this
 * value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
 * the run queue (thread.c), or it can be an element in a
 * semaphore wait list (synch.c).  It can be used these two ways
 * only because they are mutually exclusive: only a thread in the
 * ready state is on the run queue, whereas only a thread in the
 * blocked state is on a semaphore wait list. */
struct thread
{
    /* Owned by thread.c. */
    tid_t tid;                 /* Thread identifier. */
    enum thread_status status; /* Thread state. */
    char name[16];             /* Name (for debugging purposes). */
    int priority;              /* Priority. */
    int base_priority;         /* 원본 값 */
    struct lock *waiting_lock; /* 기다리고 있는 락 */
    int64_t wakeup_tick;       /* 자고있는애가 일어날 시간 */

    int nice;      /* 나이쓰 (-20 ~ 20) */
    fp recent_cpu; /* 최근 cpu 사용량 */

    /* Shared between thread.c and synch.c. */
    struct list donors;             /* 우선순위 기부해준 애들 리스트 */
    struct list_elem elem;          /* List element. */
    struct list_elem donation_elem; /* Donor List element. */

#ifdef USERPROG
    /* Owned by userprog/process.c. */
    uint64_t *pml4; /* Page map level 4 */
    struct list child_list;
    struct list_elem child_elem;
    struct semaphore wait_sema; /* wait용 */
    struct semaphore exit_sema; /* exit용 */
    struct semaphore fork_sema; /* fork용 */
    int exit_status;
    struct file *exec;
    struct file **fdt;
    int fdt_size;
#endif
#ifdef VM
    /* Table for whole virtual memory owned by thread. */
    struct supplemental_page_table spt;
    uintptr_t user_rsp; // 유저 프로세스의 rsp를 저장할 변수
    struct thread *parent;
#endif

    /* Owned by thread.c. */
    struct intr_frame tf; /* Information for switching */
    unsigned magic;       /* Detects stack overflow. */
};

/* 자는 쓰레드를 넣을 리스트
   timer.c 에서도 써야됨 */
extern struct list sleep_list;

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init(void);
void thread_start(void);

void thread_tick(void);
void thread_print_stats(void);

typedef void thread_func(void *aux);
tid_t thread_create(const char *name, int priority, thread_func *, void *);

void thread_block(void);
void thread_unblock(struct thread *);

struct thread *thread_current(void);
tid_t thread_tid(void);
const char *thread_name(void);

void thread_exit(void) NO_RETURN;
void thread_yield(void);
void thread_preempt(void);

bool cmp_priority(const struct list_elem *a, const struct list_elem *b, void *aux);
int thread_get_priority(void);
void thread_set_priority(int);
void thread_donate_priority(struct thread *thrd, struct thread *donor);
void thread_update_priority(struct thread *t, void *aux UNUSED);

/* 쓰레드를 업데이트하는 함수를 정의 */
typedef void thread_update_func(struct thread *t, void *aux);
void thread_update_all(thread_update_func *update, void *aux);

void thread_mlfqs_update_priority(void);
void thread_mlfqs_update_recent_cpu(void);
void thread_mlfqs_update_load_avg(void);

int thread_get_nice(void);
void thread_set_nice(int);
int thread_get_recent_cpu(void);
int thread_get_load_avg(void);

struct thread *thread_get_child(tid_t child_tid);

void do_iret(struct intr_frame *tf);

#endif /* threads/thread.h */
