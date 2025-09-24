#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/synch.h"
#include "threads/init.h"

#define MSR_STAR 0xc0000081
#define MSR_LSTAR 0xc0000082
#define MSR_SYSCALL_MASK 0xc0000084

void syscall_entry(void);
void syscall_handler(struct intr_frame *);
static void check_address(void *addr);
static void release_fd(int fd);
static int allocate_fd(struct file *file);
static struct file *get_file(int fd);
static void check_buffer(void *buffer, unsigned size);
static struct lock filesys_lock;

void syscall_init(void)
{
    write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 |
                            ((uint64_t)SEL_KCSEG) << 32);
    write_msr(MSR_LSTAR, (uint64_t)syscall_entry);
    write_msr(MSR_SYSCALL_MASK,
              FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

    lock_init(&filesys_lock);
}

void syscall_handler(struct intr_frame *f)
{
    uint64_t nr = f->R.rax;

    switch (nr)
    {
    case SYS_HALT:
        power_off();
        break;

    case SYS_EXIT:
    {
        int status = (int)f->R.rdi;
        struct thread *cur = thread_current();
        cur->exit_status = status;
        printf("%s: exit(%d)\n", cur->name, status);
        thread_exit();
    }
    break;

    // case SYS_WRITE:
    // {
    //     int fd = (int)f->R.rdi;
    //     const void *buffer = (const void *)f->R.rsi;
    //     unsigned size = (unsigned)f->R.rdx;

    //     check_address((void *)buffer);

    //     if (fd == 1)
    //     {
    //         putbuf((const char *)buffer, size);
    //         f->R.rax = size;
    //     }
    //     else
    //     {
    //         f->R.rax = -1;
    //     }
    // }
    // break;
    case SYS_WRITE:
    {
        int fd = (int)f->R.rdi;
        const void *buffer = (const void *)f->R.rsi;
        unsigned size = (unsigned)f->R.rdx;

        check_buffer((void *)buffer, size); // 이렇게 변경

        if (fd == 1)
        {
            // stdout에 쓰기
            putbuf((const char *)buffer, size);
            f->R.rax = size;
        }
        else if (fd == 0)
        {
            // stdin에 쓰기 시도 - 에러
            f->R.rax = -1;
        }
        else
        {
            // 일반 파일에 쓰기 구현
            struct file *file = get_file(fd);
            if (file == NULL)
            {
                f->R.rax = -1;
                break;
            }

            lock_acquire(&filesys_lock);
            int bytes_written = file_write(file, buffer, size);
            lock_release(&filesys_lock);

            f->R.rax = bytes_written;
        }
        break;
    }

    case SYS_CREATE:
    {
        const char *path = (const char *)f->R.rdi;
        unsigned sz = (unsigned)f->R.rsi;

        check_address((void *)path);

        // 파일명 기본 검증
        if (!path || path[0] == '\0')
        {
            f->R.rax = false;
            break;
        }

        lock_acquire(&filesys_lock);
        bool result = filesys_create(path, sz);
        lock_release(&filesys_lock);

        f->R.rax = result;
        break;
    }
    case SYS_OPEN:
    {
        const char *path = (const char *)f->R.rdi;

        check_address((void *)path);
        lock_acquire(&filesys_lock);
        struct file *file = filesys_open(path);
        lock_release(&filesys_lock);

        if (file == NULL)
        {
            f->R.rax = -1; // 파일 열기 실패
        }
        else
        {
            int fd = allocate_fd(file);
            if (fd == -1)
            {
                // fd 테이블 가득 참, 파일 닫기
                file_close(file);
                f->R.rax = -1;
            }
            else
            {
                f->R.rax = fd; // 성공적으로 할당된 fd 반환
            }
        }
        break;
    }

    case SYS_CLOSE:
    {
        int fd = (int)f->R.rdi;

        struct file *file = get_file(fd);
        if (file != NULL)
        {
            lock_acquire(&filesys_lock);
            file_close(file);
            lock_release(&filesys_lock);

            release_fd(fd);
        }
        // close는 반환값 없음
        break;
    }
    case SYS_READ:
    {
        int fd = (int)f->R.rdi;
        void *buffer = (void *)f->R.rsi;
        unsigned size = (unsigned)f->R.rdx;

        // 버퍼 주소 검증
        check_buffer(buffer, size);

        if (fd == 0)
        {
            // stdin에서 읽기
            char *buf = (char *)buffer;
            for (unsigned i = 0; i < size; i++)
            {
                buf[i] = input_getc();
            }
            f->R.rax = size;
        }
        else if (fd == 1)
        {
            // stdout에서 읽기 시도 - 에러
            f->R.rax = -1;
        }
        else
        {
            // 파일에서 읽기
            struct file *file = get_file(fd);
            if (file == NULL)
            {
                f->R.rax = -1;
                break;
            }

            lock_acquire(&filesys_lock);
            int bytes_read = file_read(file, buffer, size);
            lock_release(&filesys_lock);

            f->R.rax = bytes_read;
        }
        break;
    }
    case SYS_FILESIZE:
    {
        int fd = (int)f->R.rdi;

        struct file *file = get_file(fd);
        if (file == NULL)
        {
            f->R.rax = -1;
            break;
        }

        lock_acquire(&filesys_lock);
        off_t size = file_length(file);
        lock_release(&filesys_lock);

        f->R.rax = size;
        break;
    }
        // syscall_handler 함수의 switch문에 추가:

    case SYS_FORK:
    {
        const char *thread_name = (const char *)f->R.rdi;
        check_address((void *)thread_name);
        f->R.rax = process_fork(thread_name, f);
        break;
    }

    case SYS_EXEC:
    {
        const char *cmd_line = (const char *)f->R.rdi;
        check_address((void *)cmd_line);

        char *cmd_copy = palloc_get_page(0);
        if (cmd_copy == NULL)
        {
            f->R.rax = -1;
            break;
        }
        strlcpy(cmd_copy, cmd_line, PGSIZE);

        f->R.rax = process_exec(cmd_copy);
        break;
    }

    case SYS_WAIT:
    {
        tid_t pid = (tid_t)f->R.rdi;
        f->R.rax = process_wait(pid);
        break;
    }
    case SYS_SEEK:
    {
        int fd = (int)f->R.rdi;
        unsigned position = (unsigned)f->R.rsi;

        struct file *file = get_file(fd);
        if (file != NULL)
        {
            lock_acquire(&filesys_lock);
            file_seek(file, position);
            lock_release(&filesys_lock);
        }
        break;
    }
    case SYS_TELL:
    {
        int fd = (int)f->R.rdi;
        struct file *file = get_file(fd);
        if (file == NULL)
        {
            f->R.rax = -1;
            break;
        }

        lock_acquire(&filesys_lock);
        f->R.rax = file_tell(file);
        lock_release(&filesys_lock);
        break;
    }
    case SYS_REMOVE:
    {
        const char *file = (const char *)f->R.rdi;
        check_address((void *)file);

        lock_acquire(&filesys_lock);
        f->R.rax = filesys_remove(file);
        lock_release(&filesys_lock);
        break;
    }
    default:
        printf("Unknown system call: %d\n", (int)nr);
        printf("%s: exit(-1)\n", thread_current()->name);
        thread_current()->exit_status = -1;
        thread_exit();
        break;
    }
}

static void check_address(void *addr)
{
    if (addr == NULL || !is_user_vaddr(addr))
    {
        printf("%s: exit(-1)\n", thread_current()->name);
        thread_current()->exit_status = -1;
        thread_exit();
    }
}

static int allocate_fd(struct file *file)
{
    struct thread *cur = thread_current();

    // 3번부터 빈 슬롯 찾기 (0=stdin, 1=stdout, 2=stderr 예약)
    for (int fd = 3; fd < cur->fd_idx && fd < FDCOUNT_LIMIT; fd++)
    {
        if (cur->fdt[fd] == NULL)
        {
            cur->fdt[fd] = file;
            if (fd >= cur->fd_idx)
                cur->fd_idx = fd + 1;
            return fd;
        }
    }

    // 새 슬롯 할당
    if (cur->fd_idx < FDCOUNT_LIMIT)
    {
        cur->fdt[cur->fd_idx] = file;
        return cur->fd_idx++;
    }

    return -1; // 테이블 가득 참
}

static struct file *get_file(int fd)
{
    struct thread *cur = thread_current();
    if (fd < 0 || fd >= FDCOUNT_LIMIT || fd >= cur->fd_idx)
    {
        return NULL;
    }

    return cur->fdt[fd];
}

static void release_fd(int fd)
{
    struct thread *cur = thread_current();

    if (fd >= 3 && fd < FDCOUNT_LIMIT && fd < cur->fd_idx)
    {
        cur->fdt[fd] = NULL;
    }
}
static void check_buffer(void *buffer, unsigned size)
{
    if (buffer == NULL || !is_user_vaddr(buffer))
    {
        printf("%s: exit(-1)\n", thread_current()->name);
        thread_current()->exit_status = -1;
        thread_exit();
    }

    // 버퍼 전체 영역이 사용자 공간인지 확인
    char *end = (char *)buffer + size - 1;
    if (!is_user_vaddr(end))
    {
        printf("%s: exit(-1)\n", thread_current()->name);
        thread_current()->exit_status = -1;
        thread_exit();
    }
}