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
#include "userprog/process.h"
#include <debug.h>
#include <string.h>
#include "threads/palloc.h"
#include "threads/malloc.h"


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
	thread_current() -> tf = *f;
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
	case SYS_FORK:
		f->R.rax = sys_fork(f->R.rdi);
		break;
	case SYS_EXEC:
		f->R.rax = sys_exec(f->R.rdi);
		break;
	case SYS_SEEK:
		sys_seek(f->R.rdi, f->R.rsi);
		break;
	case SYS_REMOVE:
		f->R.rax = sys_remove(f->R.rdi);
		break;
	case SYS_TELL:
		f->R.rax = sys_tell(f->R.rdi);
		break;
	case SYS_DUP2:
		f->R.rax = sys_dup2(f->R.rdi, f->R.rsi);
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
	struct thread* cur = thread_current();
	int bytes_write = 0;

	file_check((char*)buffer);
	
	if(fd < 0 || fd >= cur -> fd_listsize) return -1;
	if(cur -> fd_list[fd] == fd_stdin || cur -> fd_list[fd] == fd_error){
		return -1;
	}

	if (cur -> fd_list[fd] == fd_stdout){
		putbuf(buffer, size);
		return size;
	}


	struct file* file = cur -> fd_list[fd];
	if(file == NULL) return -1;

	bytes_write = file_write(file, buffer, size); 

	return bytes_write;

}

void sys_exit(int status)
{	
	struct thread* cur = thread_current();
	cur -> exit_status = status;
	printf("%s: exit(%d)\n", cur -> name, status);
	thread_exit();
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

int plus_fd_list(struct thread *t){
	
	int new_fdlistsize = t -> fd_listsize + 32;
	if(new_fdlistsize > FD_maxsize) return -1;

	struct file** new_fd_list = 
	(struct file**)realloc(t -> fd_list, sizeof(struct file*) * new_fdlistsize);
	
	if(new_fd_list == NULL) return -1;

	for(int i = t -> fd_listsize; i < new_fdlistsize; i++){
		new_fd_list[i] = NULL;
	}

	t -> fd_list = new_fd_list;
	t -> fd_listsize = new_fdlistsize;

	return 0;
}




int sys_open (const char *file){

	struct thread* cur = thread_current();
	// bool check = false;

	file_check(file);

	struct file* op_fl = filesys_open(file);
	if(op_fl == NULL) return -1;

	while(1){

		for(int i = 0; i< cur -> fd_listsize; i++){
			if(cur -> fd_list[i] == NULL){
				cur -> fd_list[i] = op_fl;
				// check = true;
				return i;
			}
		}
		if(plus_fd_list(cur) < 0){
			file_close(op_fl);
			return -1;
		}
	}

}

void sys_close(int fd){

	struct thread* cur = thread_current();
	if(fd < 0 || fd >= cur -> fd_listsize) return;

	struct file* f = cur -> fd_list[fd];
	if(cur -> fd_list[fd] == NULL) return;
	if(cur -> fd_list[fd] == fd_stdin || cur -> fd_list[fd] == fd_stdout || cur -> fd_list[fd] == fd_error){
		return;
	}
	// if(cur -> fd_list[fd] != fd_stdin && cur -> fd_list[fd] != fd_stdout && cur -> fd_list[fd] != fd_error){
	// 	file_close(cur -> fd_list[fd]);
	// }
	file_close(cur -> fd_list[fd]);
	cur -> fd_list[fd] = NULL;
	
}

int sys_read(int fd, void* buffer, unsigned size){
	struct thread* cur = thread_current();
	int bytes_read = 0;

	file_check((char*)buffer);
	
	if(fd < 0 || fd >= cur -> fd_listsize) return -1;
	if(cur -> fd_list[fd] == fd_stdout || cur -> fd_list[fd] == fd_error){
		return -1;
	}

	if(cur -> fd_list[fd] == fd_stdin){
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
	if(fd < 0 || fd >= cur -> fd_listsize) return -1;

	struct file* file = cur -> fd_list[fd];
	if(file == fd_stdin || file == fd_stdout || file == fd_error) return -1;
	if(file == NULL) return -1;

	return file_length(file);
}

pid_t sys_fork(const char* thread_name){
	
	file_check(thread_name);

	struct thread* parent = thread_current();

	return process_fork(thread_name, &parent -> tf);
}

int sys_exec (const char *file){

	file_check(file);

	char* src = file; // 이거 없이 하고 싶으면 palloc_get_page(PAL_ZERO)로 사용해야함
	char* kpage;
	kpage = palloc_get_page(0);
	if(kpage == NULL) sys_exit(-1);

	strlcpy(kpage, src, PGSIZE);

	if(process_exec(kpage) == -1){
		sys_exit(-1);
	}
	
	NOT_REACHED();
}

void sys_seek(int fd, unsigned position){
	struct thread* cur = thread_current();
	struct file* file = cur -> fd_list[fd];
	
	if(fd < 0 || fd >= cur -> fd_listsize) return;
	if(file == fd_stdin || file == fd_stdout || file == fd_error) return;
	if(file == NULL) return;

	file_seek(file, position);
}

bool sys_remove(const char* file){

	file_check(file);

	return filesys_remove(file);
}

unsigned sys_tell(int fd){
	struct thread* cur = thread_current();
	struct file* file = cur -> fd_list[fd];
	if(fd < 0 || fd >= cur -> fd_listsize) return -1;
	if(file == fd_error || file == fd_stdin || file == fd_stdout) return -1;
	if(file == NULL) return -1;

	return file_tell (file);
}

int sys_dup2(int oldfd, int newfd){
	struct thread* cur = thread_current();
	if(oldfd < 0 || oldfd >= cur -> fd_listsize) return -1;
	if(cur -> fd_list[oldfd] == NULL) return -1;
	
	// if(cur -> fd_listsize < newfd){
	// 	cur -> fd_list = (struct file**)realloc(cur -> fd_list, sizeof(struct file**) * newfd + 1);
	// 	if(cur -> fd_list == NULL) return -1;
	// 	for(int i = cur -> fd_listsize; i < newfd+1; i++){
	// 		cur -> fd_list[i] = NULL;
	// 	}
	// 	cur -> fd_listsize = newfd + 1;
	// }

	while(newfd >= cur -> fd_listsize){
		if(plus_fd_list(cur) < 0) return -1;
	}

	if(newfd < 0 || newfd >= cur -> fd_listsize) return -1;
	if(cur -> fd_list[newfd] == cur -> fd_list[oldfd]) return newfd;

	if(cur -> fd_list[newfd] != NULL){
		if(cur -> fd_list[newfd] != fd_stdin && cur -> fd_list[newfd] != fd_stdout && cur -> fd_list[newfd] != fd_error){
			file_close(cur -> fd_list[newfd]);
		}
	}

	if(cur -> fd_list[oldfd] == fd_stdin || cur -> fd_list[oldfd] == fd_stdout || cur -> fd_list[oldfd] == fd_error){
		cur -> fd_list[newfd] = cur -> fd_list[oldfd];
	}
	else{
		cur -> fd_list[newfd] = cur -> fd_list[oldfd];
		file_duplicate2(cur -> fd_list[oldfd]);
	}

	return newfd;

}