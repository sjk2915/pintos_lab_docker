#include "userprog/syscall.h"
#include "lib/kernel/stdio.h"
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
void file_check(const char* file);


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
	case SYS_WAIT:
		f->R.rax = sys_wait(f->R.rdi);
		break;
	case SYS_WRITE:
		f->R.rax = sys_write(f->R.rdi, (const void*)f->R.rsi, f->R.rdx);
		break;
	case SYS_EXIT:
		sys_exit(f->R.rdi);
		break;
	case SYS_HALT:
		sys_halt();
		break;
	case SYS_CREATE:
		f->R.rax = sys_create(f->R.rdi, f->R.rsi);
		break;
	case SYS_OPEN:
		f->R.rax = sys_open(f->R.rdi);
		break;
	case SYS_CLOSE:
		sys_close(f->R.rdi);
		break;
	case SYS_READ:
		f->R.rax = sys_read(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_FILESIZE:
		f->R.rax = sys_filesize(f->R.rdi);
		break;
	default:
		printf ("system call!\n");
		thread_exit ();
		break;
	}
}

int sys_wait (pid_t pid)
{
	return process_wait (pid);
}

int sys_write (int fd, const void *buffer, unsigned size)
{
	if (fd == 1){
		putbuf(buffer, size);
		return size;
	}
	struct thread* cur = thread_current();
	int bytes_read = 0;

	file_check((char*)buffer);
	
	if(fd < 0 || fd == 1 || fd >= 32) return -1;
	else{
		struct file* file = cur -> fd_list[fd];
		if(file == NULL) return -1;

		bytes_read = file_read(file, buffer, size);
	}

	return bytes_read;

}

void sys_exit(int status)
{	
	struct thread* cur = thread_current();
	cur -> exit_status = status;
	printf("%s: exit(%d)\n", cur -> name, status);
	process_exit();
}

void sys_halt(void){
	power_off();
}

void file_check(const char* file){
	//file이 null인지 체크
	if(file == NULL) sys_exit(-1);
	// 커널 영역에 있는지 없는지 체크
	if(!is_user_vaddr(file)) sys_exit(-1);
	// 실제로 할당된 메모리인지 아닌지(매핑되어 있는지)
	struct thread* cur = thread_current();
	if(pml4_get_page(cur -> pml4, file) == NULL){
		sys_exit(-1);
	}
}

bool sys_create (const char *file, unsigned initial_size){
	
	file_check(file);
	
	return filesys_create(file, initial_size);
}

int sys_open (const char *file){
	int fd;
	struct thread* cur = thread_current();

	file_check(file);
	
	struct file* op_fl = filesys_open(file);

	if(op_fl == NULL){
		return -1;
	}
	else{
		int idx = 2;
		for(int i = 2; i< 32; i++){
			if(cur -> fd_list[i] == NULL){
				cur -> fd_list[i] = op_fl;
				break;
			}
			idx++; 
		}
		if(idx == 32){
			return -1;
		}
		else
			return idx;
	}
}

void sys_close(int fd){
	struct thread* cur = thread_current();
	
	if(fd < 2 || fd >=32) return;

	struct file* file = cur -> fd_list[fd];
	if(cur -> fd_list[fd] == NULL) return;

	// file_check(file);
		
	cur -> fd_list[fd] = NULL;
	file_close(file);
	
}

int sys_read(int fd, void* buffer, unsigned size){
	struct thread* cur = thread_current();
	int bytes_read = 0;

	file_check((char*)buffer);
	
	if(fd < 0 || fd == 1 || fd >= 32) return -1;

	if(fd == 0){
		for(int i = 0; i < size; i++){
			((char*)buffer)[i] = input_getc();
		}
		bytes_read = size;
	}
	else{
		struct file* file = cur -> fd_list[fd];
		if(file == NULL) return -1;

		bytes_read = file_read(file, buffer, size);
	}

	return bytes_read;
}

int sys_filesize(int fd){
	struct thread* cur = thread_current();
	struct file* file = cur -> fd_list[fd];

	return file_length(file);
}

