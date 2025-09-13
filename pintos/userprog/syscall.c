#include "userprog/syscall.h"
#include "userprog/gdt.h"
#include "userprog/process.h"
#include "lib/kernel/stdio.h"
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "intrinsic.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/input.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
static void check_ptr(void *addr);

/* Predefined file handles. */
#define STDIN_FILENO 0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2

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

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	switch (f->R.rax)
	{
	case SYS_HALT:
		sys_halt();
		break;
	case SYS_EXIT:
		sys_exit(f->R.rdi);
		break;
	case SYS_FORK:
		f->R.rax = sys_fork(f->R.rdi);
		break;
	case SYS_WAIT:
		f->R.rax = sys_wait(f->R.rdi);
		break;
	case SYS_CREATE:
		f->R.rax = sys_create((const char*)f->R.rdi, f->R.rsi);
		break;
	case SYS_REMOVE:
		f->R.rax = sys_remove((const char*)f->R.rdi);
		break;
	case SYS_OPEN:
		f->R.rax = sys_open((const char*)f->R.rdi);
		break;
	case SYS_FILESIZE:
		f->R.rax = sys_filesize(f->R.rdi);
		break;
	case SYS_READ:
		f->R.rax = sys_read(f->R.rdi, (const void*)f->R.rsi, f->R.rdx);
		break;
	case SYS_WRITE:
		f->R.rax = sys_write(f->R.rdi, (const void*)f->R.rsi, f->R.rdx);
		break;
	case SYS_CLOSE:
		sys_close(f->R.rdi);
		break;
	default:
		printf ("system call!\n");
		thread_exit ();
		break;
	}
}

static void check_ptr(void *ptr)
{
	if (ptr == NULL 												// null 포인터
		|| is_kernel_vaddr(ptr) 									// 커널 메모리 침범
		|| pml4_get_page(thread_current()->pml4, ptr) == NULL)		// 매핑안됨
		sys_exit(-1);
}

static void check_fd(int fd)
{
	// 잘못된 fd 접근
	if (fd < 0 || fd >= FDT_SIZE)
		sys_exit(-1);
}

void sys_halt (void)
{
	power_off();
}

void sys_exit (int status)
{
	struct thread *cur = thread_current();
	cur->exit_status = status;
	printf("%s: exit(%d)\n", cur->name, cur->exit_status);
	thread_exit();
}

pid_t sys_fork (const char *thread_name)
{
	check_ptr(thread_name);
	return process_fork(thread_name, &thread_current()->tf);
}

int sys_wait (pid_t)
{

}

bool sys_create (const char *file, unsigned initial_size)
{
	check_ptr(file);
	return filesys_create(file, initial_size);
}

bool sys_remove (const char *file)
{
	check_ptr(file);
	return filesys_remove(file);
}

int sys_open (const char *file)
{
	check_ptr(file);
	struct thread *cur = thread_current();
	struct file *new_file = filesys_open(file);
	if (new_file == NULL) return -1;
	for (int i=3; i<FDT_SIZE; i++)
	{
		if (cur->fdt[i] == NULL)
		{
			cur->fdt[i] = new_file;
			return i;
		}
	}
	// fdt 할당 실패
	file_close(new_file);
	return -1;
}

int sys_filesize(int fd)
{
	check_fd(fd);
	struct thread *cur = thread_current();
	if (cur->fdt[fd] == NULL) sys_exit(-1);
	return file_length(cur->fdt[fd]);
}

int sys_read (int fd, void *buffer, unsigned length)
{
	check_fd(fd);
	check_ptr(buffer);
	// 콘솔입력에서 읽기
	if (fd == STDIN_FILENO)
	{
		char *buf = buffer;
		for (int i=0; i<length; i++)
			buf[i] = input_getc();
		return length;
	}

	// 콘솔출력에 읽기 금지
	else if (fd == STDOUT_FILENO) return -1;

	else
	{
		struct thread *cur = thread_current();
		if (cur->fdt[fd] == NULL) sys_exit(-1);
		return file_read(cur->fdt[fd], buffer, length);
	}
}

int sys_write (int fd, const void *buffer, unsigned length)
{
	check_fd(fd);
	check_ptr(buffer);
	// 콘솔입력에 쓰기 금지
	if (fd == STDIN_FILENO) return -1;

	// 콘솔출력에 냅다 붓기
	else if (fd == STDOUT_FILENO)
	{
		putbuf(buffer, length);
		return length;
	}

	else
	{
		struct thread *cur = thread_current();
		if (cur->fdt[fd] == NULL) sys_exit(-1);
		return file_write(cur->fdt[fd], buffer, length);
	}
}

void sys_close (int fd)
{
	check_fd(fd);
	struct thread *cur = thread_current();
	if (cur->fdt[fd] == NULL) sys_exit(-1);
	file_close(cur->fdt[fd]);
	cur->fdt[fd] = NULL;
}