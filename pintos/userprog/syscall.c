#include "userprog/syscall.h"
#include "userprog/gdt.h"
#include "userprog/process.h"
#include "lib/kernel/stdio.h"
#include "lib/string.h"
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "intrinsic.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/inode.h"
#include "devices/input.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);
/* Projects 2 and later. */
static void check_ptr(void *addr);
static int check_fd(struct thread *t, int fd);

static int find_fd(struct thread *t);
static int extend_fdt(struct thread *t);

static void sys_halt(void);
static void sys_exit(int status);
static pid_t sys_fork(const char *thread_name, struct intr_frame *f);
static int sys_exec(const char *cmd_line);
static int sys_wait(pid_t pid);
static bool sys_create(const char *file, unsigned initial_size);
static bool sys_remove(const char *file);
static int sys_open(const char *file);
static int sys_filesize(int fd);
static int sys_read(int fd, void *buffer, unsigned size);
static int sys_write(int fd, const void *buffer, unsigned size);
static void sys_seek(int fd, unsigned position);
static unsigned sys_tell(int fd);
static void sys_close(int fd);

static int sys_dup2(int oldfd, int newfd);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void syscall_init(void)
{
    write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 | ((uint64_t)SEL_KCSEG) << 32);
    write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

    /* The interrupt service rountine should not serve any interrupts
     * until the syscall_entry swaps the userland stack to the kernel
     * mode stack. Therefore, we masked the FLAG_FL. */
    write_msr(MSR_SYSCALL_MASK, FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f)
{
    // user_rsp 저장
    thread_current()->user_rsp = f->rsp;
    // TODO: Your implementation goes here.
    struct thread *t = thread_current();
    t->usr_rsp = f->rsp;
    switch (f->R.rax)
    {
    case SYS_HALT:
        sys_halt();
        break;
    case SYS_EXIT:
        sys_exit(f->R.rdi);
        break;
    case SYS_FORK:
        f->R.rax = sys_fork((const char *)f->R.rdi, f);
        break;
    case SYS_EXEC:
        f->R.rax = sys_exec((const char *)f->R.rdi);
        break;
    case SYS_WAIT:
        f->R.rax = sys_wait(f->R.rdi);
        break;
    case SYS_CREATE:
        f->R.rax = sys_create((const char *)f->R.rdi, f->R.rsi);
        break;
    case SYS_REMOVE:
        f->R.rax = sys_remove((const char *)f->R.rdi);
        break;
    case SYS_OPEN:
        f->R.rax = sys_open((const char *)f->R.rdi);
        break;
    case SYS_FILESIZE:
        f->R.rax = sys_filesize(f->R.rdi);
        break;
    case SYS_READ:
        f->R.rax = sys_read(f->R.rdi, (const void *)f->R.rsi, f->R.rdx);
        break;
    case SYS_WRITE:
        f->R.rax = sys_write(f->R.rdi, (const void *)f->R.rsi, f->R.rdx);
        break;
    case SYS_SEEK:
        sys_seek(f->R.rdi, f->R.rsi);
        break;
    case SYS_TELL:
        f->R.rax = sys_tell(f->R.rdi);
        break;
    case SYS_CLOSE:
        sys_close(f->R.rdi);
        break;
    case SYS_DUP2:
        f->R.rax = sys_dup2(f->R.rdi, f->R.rsi);
        break;
    default:
        printf("not implemented system call!: %d\n", f->R.rax);
        sys_exit(-1);
        break;
    }
}

static void check_ptr(void *ptr)
{
    if (ptr == NULL || is_kernel_vaddr(ptr)) // null 포인터, 커널 메모리 침범
        sys_exit(-1);
}

static int check_fd(struct thread *t, int fd)
{
    // 잘못된 fd 접근
    if (fd < 0 || fd >= t->fdt_size)
        return -1;
    // 없는 fd 접근
    if (t->fdt[fd] == NULL)
        return -1;
    return 0;
}

static int find_fd(struct thread *t)
{
    // fd 찾기
    for (int i = 0; i < t->fdt_size; i++)
        if (t->fdt[i] == NULL)
            return i;

    // fd 할당 실패 확장 시도
    int old_size = t->fdt_size;
    if (extend_fdt(t) == -1)
        return -1;
    return old_size;
}

static int extend_fdt(struct thread *t)
{
    // 두배씩 늘리기
    int new_size = t->fdt_size * 2;
    if (new_size > MAX_FDT_SIZE)
        return -1;
    struct file **new_fdt = (struct file **)realloc(t->fdt, new_size * sizeof(struct file *));
    if (new_fdt == NULL)
        return -1;

    // 초기화
    for (int i = t->fdt_size; i < new_size; i++)
        new_fdt[i] = NULL;

    t->fdt = new_fdt;
    t->fdt_size = new_size;
}

static void sys_halt(void)
{
    power_off();
}

static void sys_exit(int status)
{
    struct thread *cur = thread_current();
    cur->exit_status = status;
    printf("%s: exit(%d)\n", cur->name, cur->exit_status);
    thread_exit();
}

static pid_t sys_fork(const char *thread_name, struct intr_frame *f)
{
    check_ptr(thread_name);
    return process_fork(thread_name, f);
}

static int sys_exec(const char *cmd_line)
{
    check_ptr(cmd_line);
    char *cmd_cpy = palloc_get_page(PAL_ZERO);
    if (cmd_cpy == NULL)
        return -1;
    strlcpy(cmd_cpy, cmd_line, strlen(cmd_line) + 1);

    // 실패하거나
    if (process_exec(cmd_cpy) == -1)
        sys_exit(-1);
    // 반환하지 않거나 - 여기도달하면 망한 함수
    NOT_REACHED();
}

static int sys_wait(pid_t pid)
{
    return process_wait(pid);
}

static bool sys_create(const char *file, unsigned initial_size)
{
    check_ptr(file);
    return filesys_create(file, initial_size);
}

static bool sys_remove(const char *file)
{
    check_ptr(file);
    return filesys_remove(file);
}

static int sys_open(const char *file)
{
    check_ptr(file);
    struct thread *cur = thread_current();
    struct file *new_file = filesys_open(file);
    // 열기 실패
    if (new_file == NULL)
        return -1;

    int fd = find_fd(cur);
    // fd 할당 실패
    if (fd < 0)
    {
        file_close(new_file);
        return -1;
    }

    cur->fdt[fd] = new_file;
    return fd;
}

static int sys_filesize(int fd)
{
    struct thread *cur = thread_current();
    if (check_fd(cur, fd) == -1)
        return -1;
    if (IS_STDIO(cur->fdt[fd]))
        return -1;
    return file_length(cur->fdt[fd]);
}

static int sys_read(int fd, void *buffer, unsigned size)
{
    check_ptr(buffer);
    struct page *page = spt_find_page(&thread_current()->spt, buffer);
    if (page && !page->writable)
    {
        sys_exit(-1);
    }
    struct thread *cur = thread_current();
    if (check_fd(cur, fd) == -1)
        return -1;

    // 콘솔입력에서 읽기
    if (cur->fdt[fd] == STDIN_FDNO)
    {
        char *buf = buffer;
        for (unsigned i = 0; i < size; i++)
            buf[i] = input_getc();
        return size;
    }

    // 콘솔출력에 읽기 금지
    else if (cur->fdt[fd] == STDOUT_FDNO)
        return -1;

    else
        return file_read(cur->fdt[fd], buffer, size);
}

static int sys_write(int fd, const void *buffer, unsigned size)
{
    check_ptr(buffer);
    struct thread *cur = thread_current();
    if (check_fd(cur, fd) == -1)
        return -1;

    // 콘솔입력에 쓰기 금지
    if (cur->fdt[fd] == STDIN_FDNO)
        return -1;

    // 콘솔출력에 냅다 붓기
    else if (cur->fdt[fd] == STDOUT_FDNO)
    {
        putbuf(buffer, size);
        return size;
    }

    else
        return file_write(cur->fdt[fd], buffer, size);
}

static void sys_seek(int fd, unsigned position)
{
    struct thread *cur = thread_current();
    if (check_fd(cur, fd) == -1)
        return;
    if (IS_STDIO(cur->fdt[fd]))
        return;
    file_seek(cur->fdt[fd], position);
}

static unsigned sys_tell(int fd)
{
    struct thread *cur = thread_current();
    if (check_fd(cur, fd) == -1)
        return -1;
    if (IS_STDIO(cur->fdt[fd]))
        return -1;
    return file_tell(cur->fdt[fd]);
}

static void sys_close(int fd)
{
    struct thread *cur = thread_current();
    if (check_fd(cur, fd) == -1)
        return;
    if (!IS_STDIO(cur->fdt[fd]))
        file_close(cur->fdt[fd]);
    cur->fdt[fd] = NULL;
}

static int sys_dup2(int oldfd, int newfd)
{
    struct thread *cur = thread_current();
    // fd 검사
    if (check_fd(cur, oldfd) == -1)
        return -1;
    if (newfd < 0)
        return -1;
    if (oldfd == newfd)
        return newfd;

    // 원하는 숫자보다 사이즈가 작으면 확장시도
    while (cur->fdt_size < newfd)
        if (extend_fdt(cur) == -1)
            return -1;
    // 열려있으면 닫기
    if (cur->fdt[newfd] != NULL)
    {
        if (!IS_STDIO(cur->fdt[newfd]))
            file_close(cur->fdt[newfd]);
        cur->fdt[newfd] = NULL;
    }
    // fdt 복사
    if (IS_STDIO(cur->fdt[oldfd]))
        cur->fdt[newfd] = cur->fdt[oldfd];
    else
        cur->fdt[newfd] = file_duplicate2(cur->fdt[oldfd]);

    return newfd;
}