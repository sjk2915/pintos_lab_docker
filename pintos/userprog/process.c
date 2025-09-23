#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#ifdef VM
#include "vm/vm.h"
#endif

static void process_cleanup(void);
static bool load(const char *file_name, struct intr_frame *if_);
static void initd(void *f_name);
static void __do_fork(void *);
static bool argument_stack(struct intr_frame *if_, char *argv[], int argc);

static struct thread *get_child_process(int pid) {
    struct thread *curr = thread_current();
    struct thread *t;

    for (struct list_elem *e = list_begin(&curr->child_list); e != list_end(&curr->child_list); e = list_next(e)) {
        t = list_entry(e, struct thread, child_elem);
        if (pid == t->tid)
            return t;
    }
    return NULL;
}


/* initd 및 기타 프로세스를 위한 일반적인 프로세스 초기화자. */
static void
process_init(void)
{
	struct thread *current = thread_current();
}

/* 첫 번째 유저랜드 프로그램인 "initd"를 FILE_NAME에서 로드하여 시작합니다.
 * 새 스레드는 스케줄될 수 있으며(심지어 종료될 수도 있음),
 * process_create_initd()가 반환되기 전에 실행될 수 있습니다.
 * initd의 스레드 id를 반환하고, 생성에 실패하면 TID_ERROR를 반환합니다.
 * 주의: 이 함수는 한 번만 호출되어야 합니다. */
// tid_t process_create_initd(const char *file_name)
// {
// 	char *fn_copy;
// 	tid_t tid;

// 	/* FILE_NAME의 사본을 만듭니다.
// 	 * 그렇지 않으면 호출자와 load() 사이에 경쟁 상태가 발생할 수 있습니다. */
// 	// 사본을 만들어야 경쟁이 안 일어남
// 	fn_copy = palloc_get_page(0);
// 	if (fn_copy == NULL)
// 		return TID_ERROR;
// 	strlcpy(fn_copy, file_name, PGSIZE);

// 	/* FILE_NAME을 실행할 새로운 스레드를 생성합니다. */

// 	// 스레드를 만들어서 다시는 커널로 돌아오지 않게 사용자 프로그램으로 변신해야 함(initd의 역할)
// 	tid = thread_create(file_name, PRI_DEFAULT, initd, fn_copy);
// 	if (tid == TID_ERROR)
// 		palloc_free_page(fn_copy);
// 	return tid;
// }
tid_t process_create_initd(const char *file_name)
{
    char *fn_copy;
    tid_t tid;

    fn_copy = palloc_get_page(0);
    if (fn_copy == NULL)
        return TID_ERROR;
    strlcpy(fn_copy, file_name, PGSIZE);

    // 프로그램 이름만 추출
    char *save_ptr;
    char *prog_name = strtok_r(fn_copy, " ", &save_ptr);
    if (prog_name == NULL) {
        palloc_free_page(fn_copy);
        return TID_ERROR;
    }

    // 전체 명령행 복사본 다시 생성 (strtok_r이 원본을 수정하므로)
    char *cmd_copy = palloc_get_page(0);
    if (cmd_copy == NULL) {
        palloc_free_page(fn_copy);
        return TID_ERROR;
    }
    strlcpy(cmd_copy, file_name, PGSIZE);

    // 프로그램 이름으로만 스레드 생성
    tid = thread_create(prog_name, PRI_DEFAULT, initd, cmd_copy);
    if (tid == TID_ERROR) {
        palloc_free_page(cmd_copy);
    }
    
    palloc_free_page(fn_copy);
    return tid;
}

/* 첫 번째 사용자 프로세스를 실행하는 스레드 함수. */
static void
initd(void *f_name)
{
#ifdef VM
	supplemental_page_table_init(&thread_current()->spt);
#endif

	process_init();

	if (process_exec(f_name) < 0)
		PANIC("initd 실행 실패\n");
	NOT_REACHED();
}

/* 현재 프로세스를 `name`으로 복제합니다.
 * 새 프로세스의 스레드 id를 반환하고, 실패 시 TID_ERROR를 반환합니다. */
tid_t process_fork(const char *name, struct intr_frame *if_) {
    struct thread *curr = thread_current();

    // 1. 현재 프로세스의 interrupt frame을 저장
    struct intr_frame *f = (pg_round_up(rrsp()) - sizeof(struct intr_frame));
    memcpy(&curr->parent_if, f, sizeof(struct intr_frame));

    // 2. 자식 스레드 생성
    tid_t tid = thread_create(name, PRI_DEFAULT, __do_fork, curr);

    if (tid == TID_ERROR)
        return TID_ERROR;

    // 3. 자식이 fork 완료할 때까지 대기
    struct thread *child = get_child_process(tid);
    sema_down(&child->fork_sema);

    if (child->exit_status == TID_ERROR)
        return TID_ERROR;

    return tid;
}

#ifndef VM
/* 부모의 주소 공간을 pml4_for_each에 이 함수를 전달하여 복제합니다.
 * 이 함수는 프로젝트 2에서만 사용됩니다. */
static bool duplicate_pte(uint64_t *pte, void *va, void *aux) {
    struct thread *current = thread_current();
    struct thread *parent = (struct thread *)aux;
    void *parent_page;
    void *newpage;
    bool writable;

    /* 1. parent_page가 커널 페이지라면, 즉시 반환 */
    if (is_kernel_vaddr(va))
        return true;

    /* 2. 부모의 PML4에서 VA를 해석합니다. */
    parent_page = pml4_get_page(parent->pml4, va);
    if (parent_page == NULL)
        return false;

    /* 3. 자식용으로 PAL_USER 페이지를 새로 할당 */
    newpage = palloc_get_page(PAL_USER | PAL_ZERO);
    if (newpage == NULL)
        return false;

    /* 4. 부모 페이지의 내용을 새 페이지로 복제 */
    memcpy(newpage, parent_page, PGSIZE);
    writable = is_writable(pte);

    /* 5. 자식의 페이지 테이블에 주소 VA로 NEWPAGE를 WRITABLE 권한과 함께 추가합니다. */
    if (!pml4_set_page(current->pml4, va, newpage, writable)) {
        /* 6. 페이지 삽입에 실패하면 에러 처리 */
        palloc_free_page(newpage);
        return false;
    }
    return true;
}

#endif

/* 부모의 실행 컨텍스트를 복사하는 스레드 함수.
 * 힌트) parent->tf는 프로세스의 유저랜드 컨텍스트를 보유하지 않습니다.
 *       즉, 이 함수에 process_fork의 두 번째 인자(if_)를 전달해야 합니다. */
static void __do_fork(void *aux) {
    struct intr_frame if_;
    struct thread *parent = (struct thread *)aux;
    struct thread *current = thread_current();
    struct intr_frame *parent_if = &parent->parent_if;
    bool succ = true;

    // 1. CPU 컨텍스트를 로컬 스택으로 읽어옵니다
    memcpy(&if_, parent_if, sizeof(struct intr_frame));
    if_.R.rax = 0;  // 자식 프로세스의 return값 (0)

    // 2. 페이지 테이블 복제
    current->pml4 = pml4_create();
    if (current->pml4 == NULL)
        goto error;

    process_activate(current);
#ifdef VM
    supplemental_page_table_init(&current->spt);
    if (!supplemental_page_table_copy(&current->spt, &parent->spt))
        goto error;
#else
    if (!pml4_for_each(parent->pml4, duplicate_pte, parent))
        goto error;
#endif

    // 파일 디스크립터 테이블 복제
    if (parent->fd_idx >= FDCOUNT_LIMIT)
        goto error;

    current->fd_idx = parent->fd_idx;
    for (int fd = 3; fd < parent->fd_idx; fd++) {
        if (parent->fdt[fd] == NULL)
            continue;
        current->fdt[fd] = file_duplicate(parent->fdt[fd]);
    }

    sema_up(&current->fork_sema);  // fork 프로세스가 정상적으로 완료

    process_init();

    /* 마지막으로, 새로 생성된 프로세스로 전환합니다. */
    if (succ)
        do_iret(&if_);

error:
    sema_up(&current->fork_sema);  // 복제에 실패
    current->exit_status = TID_ERROR;
    thread_exit();
}


int process_exec(void *f_name)
{
    char *file_name = f_name;
    bool success = false;

    struct intr_frame _if;
    memset(&_if, 0, sizeof _if);
    _if.ds = _if.es = _if.ss = SEL_UDSEG;
    _if.cs = SEL_UCSEG;
    _if.eflags = FLAG_IF | FLAG_MBS;

    process_cleanup();

    // 토큰화
    char *argv[32];
    int argc = 0;
    char *save_ptr;
    
    char *token = strtok_r(file_name, " ", &save_ptr);
    while (token && argc < 31) {
        // 따옴표 제거
        if ((token[0] == '\'' || token[0] == '"')) {
            size_t len = strlen(token);
            if (len >= 2 && token[len-1] == token[0]) {
                token[len-1] = '\0';
                token++;
            }
        }
        argv[argc++] = token;
        token = strtok_r(NULL, " ", &save_ptr);
    }
    argv[argc] = NULL;

    if (argc == 0) {
        palloc_free_page(file_name);
        return -1;
    }

 

    // 바이너리 로드
    success = load(argv[0], &_if);
    if (!success) {
        palloc_free_page(file_name);
        return -1;
    }
   	// 토큰화 후 스레드 이름 설정 (따옴표 제거 적용)
    //strlcpy(thread_current()->name, argv[0], sizeof(thread_current()->name));

    // Argument Passing
    if (!argument_stack(&_if, argv, argc)) {
        palloc_free_page(file_name);
        return -1;
    }

    palloc_free_page(file_name);
    do_iret(&_if);
    NOT_REACHED();
}

#define ARG_MAX 64
static bool
argument_stack(struct intr_frame *if_, char *argv[], int argc) {
    uint8_t *rsp = (uint8_t *)if_->rsp;

    // 1) 문자열을 역순으로 스택에 복사
    uint64_t arg_addrs[ARG_MAX];
    for (int i = argc - 1; i >= 0; i--) {
        size_t len = strlen(argv[i]) + 1;
        rsp -= len;
        memcpy(rsp, argv[i], len);
        arg_addrs[i] = (uint64_t)rsp;
    }

    // 2) 8바이트 경계로 정렬
    rsp = (uint8_t *)((uintptr_t)rsp & ~(uintptr_t)0x7);

    // 3) argv 포인터 배열과 NULL 센티널
    rsp -= 8 * (argc + 1);
    uint64_t *argv_slots = (uint64_t *)rsp;
    for (int i = 0; i < argc; i++) {
        argv_slots[i] = arg_addrs[i];
    }
    argv_slots[argc] = 0; // NULL 센티널

    // 4) fake return address
    rsp -= 8;
    *(uint64_t *)rsp = 0;

    // 5) 레지스터 설정
    if_->R.rdi = argc;                  // argc는 정수값
    if_->R.rsi = (uint64_t)argv_slots;  // argv는 포인터

    // 6) 최종 RSP 설정
    if_->rsp = (uint64_t)rsp;

    return true;
}
/* 스레드 TID가 종료될 때까지 기다리고 종료 상태를 반환합니다.
 * 커널에 의해 종료되었다면(예: 예외로 인해 kill된 경우) -1을 반환합니다.
 * TID가 유효하지 않거나, 호출 프로세스의 자식이 아니거나,
 * 또는 해당 TID에 대해 process_wait()이 이미 성공적으로 호출된 경우,
 * 즉시 -1을 반환하며 기다리지 않습니다.
 *
 * 이 함수는 문제 2-2에서 구현됩니다. 현재는 아무 것도 하지 않습니다. */

/*
	대상 제한: 직계 자식만 가능, 내 자식이 아니면 바로 -1
	단 한번: 같은 자식에게 여러번 wait 불가, 이미 했으면 -1
	대기/즉시 반환

	자식이 아직 안끝났으면 블록(세마포어로 잠들기)
	자식이 이미 끝났으면 바로 종료코드 반환

	수거(reap): 종료코드를 받아오면서 자식의 레코드를 리스트에서 제거하고 해제

	부모-자식 연결 정보:
	부모는 children 리스트에 각 자식의 상태 노드를 들고 있음(tid, exit_status,exited,waited,sema)등
	자식은 자신의 노드 주소를 백포인터로 가지고 있다가, 종료 시 exit_status 세팅+ exited=true+ sema_up()으로
	부모를 깨움
*/

int process_wait(tid_t child_tid) {
    struct thread *cur = thread_current();
    struct thread *child = get_child_process(child_tid);
    
    if (child == NULL)
        return -1;

    sema_down(&child->wait_sema);  // 자식 프로세스가 종료될 때까지 대기

    int exit_status = child->exit_status;
    list_remove(&child->child_elem);

    sema_up(&child->exit_sema);  // 자식 프로세스가 죽을 수 있도록 signal

    return exit_status;
}

/*
	process_exit() 개념
	언제: 커널이 스레드(프로세스)를 실제로 끝날때 호출

	주소 공간 -> 페이지 테이블등 메모리 해제
	파일 --> 열린 FD 모두 닫기, 실행 파일에 걸어둔 deny_write 해제 후 닫기
	동기화: 부모가 기다릴 수 있게 종료 상태를 어딘가에 기록하고 신호(sema_up)을 보내기

	좀비 상태: 자식은 종료했지만, 부모가 wait으로 수거하기 전까지는 종료코드 보관용 기록이 남아있음

*/

/* 프로세스를 종료합니다. 이 함수는 thread_exit()에 의해 호출됩니다. */
// process.c의 process_exit에서
// process_exit 수정
void process_exit(void) {
    struct thread *curr = thread_current();
    
    /* 열린 파일들 모두 닫기 */
    for (int fd = 3; fd < curr->fd_idx; fd++) {
        if (curr->fdt[fd] != NULL) {
            file_close(curr->fdt[fd]);
            curr->fdt[fd] = NULL;
        }
    }

    /* 실행 파일 닫기 */
    if (curr->runn_file != NULL) {
        file_close(curr->runn_file);
        curr->runn_file = NULL;
    }

    /* fdt 메모리 해제 */
    if (curr->fdt != NULL) {
        palloc_free_multiple(curr->fdt, FDT_PAGES);
        curr->fdt = NULL;
    }

    process_cleanup();

    sema_up(&curr->wait_sema);  // 자식 프로세스가 종료될 때까지 대기하는 부모에게 signal
    sema_down(&curr->exit_sema);  // 부모 프로세스가 종료될 때까지 대기
}
/* 현재 프로세스의 자원을 해제합니다. */
static void
process_cleanup(void)
{
	struct thread *curr = thread_current();

#ifdef VM
	supplemental_page_table_kill(&curr->spt);
#endif

	uint64_t *pml4;
	/* 현재 프로세스의 페이지 디렉터리를 파괴하고
	 * 커널 전용 페이지 디렉터리로 다시 전환합니다. */
	pml4 = curr->pml4;
	if (pml4 != NULL)
	{
		/* 올바른 순서가 매우 중요합니다.
		 * 타이머 인터럽트가 프로세스의 페이지 디렉터리로
		 * 되돌아가지 않도록, 디렉터리를 전환하기 전에
		 * cur->pagedir을 NULL로 설정해야 합니다.
		 * 또한, 프로세스의 페이지 디렉터리를 파괴하기 전에
		 * 기본 페이지 디렉터리를 활성화해야 합니다.
		 * 그렇지 않으면 활성 페이지 디렉터리가
		 * 해제(그리고 초기화)된 디렉터리가 됩니다. */
		curr->pml4 = NULL;
		pml4_activate(NULL);
		pml4_destroy(pml4);
	}
}

/* 다음 스레드에서 사용자 코드를 실행하기 위해 CPU를 설정합니다.
 * 이 함수는 매 컨텍스트 스위치마다 호출됩니다. */
void process_activate(struct thread *next)
{
	/* 스레드의 페이지 테이블을 활성화합니다. */
	pml4_activate(next->pml4);

	/* 인터럽트 처리에 사용할 스레드의 커널 스택을 설정합니다. */
	tss_update(next);
}

/* 우리는 ELF 실행 파일을 로드합니다.
 * 아래 정의는 ELF 명세 [ELF1]에서 거의 그대로 가져왔습니다.  */

/* ELF 타입. [ELF1] 1-2 참고. */
#define EI_NIDENT 16

#define PT_NULL 0			/* 무시. */
#define PT_LOAD 1			/* 로드 가능한 세그먼트. */
#define PT_DYNAMIC 2		/* 동적 링킹 정보. */
#define PT_INTERP 3			/* 동적 로더의 이름. */
#define PT_NOTE 4			/* 보조 정보. */
#define PT_SHLIB 5			/* 예약됨. */
#define PT_PHDR 6			/* 프로그램 헤더 테이블. */
#define PT_STACK 0x6474e551 /* 스택 세그먼트. */

#define PF_X 1 /* 실행 가능. */
#define PF_W 2 /* 쓰기 가능. */
#define PF_R 4 /* 읽기 가능. */

/* 실행 파일 헤더. [ELF1] 1-4 ~ 1-8 참고.
 * ELF 바이너리의 가장 앞 부분에 위치합니다. */
struct ELF64_hdr
{
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct ELF64_PHDR
{
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* 약어 */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack(struct intr_frame *if_);
static bool validate_segment(const struct Phdr *, struct file *);
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
						 uint32_t read_bytes, uint32_t zero_bytes,
						 bool writable);

/* FILE_NAME의 ELF 실행 파일을 현재 스레드에 로드합니다.
 * 실행 파일의 entry point를 *RIP에 저장하고,
 * 초기 스택 포인터를 *RSP에 저장합니다.
 * 성공 시 true, 실패 시 false를 반환합니다. */
static bool
load(const char *file_name, struct intr_frame *if_)
{
	struct thread *t = thread_current();
	struct ELF ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;

	/* 페이지 디렉터리를 할당하고 활성화합니다. */
	t->pml4 = pml4_create();
	if (t->pml4 == NULL)
		goto done;
	process_activate(thread_current());

	/* 실행 파일을 엽니다. */
	file = filesys_open(file_name);
	if (file == NULL)
	{
	    printf("load: %s: open failed\n", file_name);
		goto done;
	}

	/* 실행 파일 헤더를 읽고 검증합니다. */
	if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr || memcmp(ehdr.e_ident, "\177ELF\2\1\1", 7) || ehdr.e_type != 2 || ehdr.e_machine != 0x3E // amd64
		|| ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Phdr) || ehdr.e_phnum > 1024)
	{
		printf("load: %s: 실행 파일 로드 오류\n", file_name);
		goto done;
	}

	/* 프로그램 헤더를 읽습니다. */
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++)
	{
		struct Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length(file))
			goto done;
		file_seek(file, file_ofs);

		if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr;
		switch (phdr.p_type)
		{
		case PT_NULL:
		case PT_NOTE:
		case PT_PHDR:
		case PT_STACK:
		default:
			/* 이 세그먼트는 무시합니다. */
			break;
		case PT_DYNAMIC:
		case PT_INTERP:
		case PT_SHLIB:
			goto done;
		case PT_LOAD:
			if (validate_segment(&phdr, file))
			{
				bool writable = (phdr.p_flags & PF_W) != 0;
				uint64_t file_page = phdr.p_offset & ~PGMASK;
				uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
				uint64_t page_offset = phdr.p_vaddr & PGMASK;
				uint32_t read_bytes, zero_bytes;
				if (phdr.p_filesz > 0)
				{
					/* 일반 세그먼트.
					 * 초기 부분은 디스크에서 읽고 나머지는 0으로 채웁니다. */
					read_bytes = page_offset + phdr.p_filesz;
					zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
				}
				else
				{
					/* 전체가 0.
					 * 디스크에서 아무 것도 읽지 않습니다. */
					read_bytes = 0;
					zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
				}
				if (!load_segment(file, file_page, (void *)mem_page,
								  read_bytes, zero_bytes, writable))
					goto done;
			}
			else
				goto done;
			break;
		}
	}

	/* 스택을 설정합니다. */
	if (!setup_stack(if_))
		goto done;

	/* 시작 주소. */
	if_->rip = ehdr.e_entry;

	/* TODO: 여기에 코드를 작성하세요.
	 * TODO: 인자 전달(argument passing)을 구현하세요 (project2/argument_passing.html 참조). */

	success = true;

done:
	/* 로드 성공 여부와 관계없이 여기로 도착합니다. */
	file_close(file);
	return success;
}

/* PHDR가 FILE 내의 유효하고 로드 가능한 세그먼트를 기술하는지 검사하여,
 * 맞으면 true, 아니면 false를 반환합니다. */
static bool
validate_segment(const struct Phdr *phdr, struct file *file)
{
	/* p_offset과 p_vaddr는 동일한 페이지 오프셋을 가져야 합니다. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset은 FILE 내부를 가리켜야 합니다. */
	if (phdr->p_offset > (uint64_t)file_length(file))
		return false;

	/* p_memsz는 p_filesz 이상이어야 합니다. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* 세그먼트는 비어 있으면 안 됩니다. */
	if (phdr->p_memsz == 0)
		return false;

	/* 가상 메모리 영역은 사용자 주소 공간 범위 내에서 시작하고 끝나야 합니다. */
	if (!is_user_vaddr((void *)phdr->p_vaddr))
		return false;
	if (!is_user_vaddr((void *)(phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* 영역이 커널 가상 주소 공간을 가로질러 "랩어라운드"되면 안 됩니다. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* 페이지 0 매핑을 금지합니다.
	   페이지 0을 매핑하는 것은 좋지 않을 뿐 아니라,
	   허용할 경우 시스템 콜에 널 포인터를 전달한 사용자 코드가
	   memcpy() 등의 널 포인터 단언에 의해 커널 패닉을 일으킬 수 있습니다. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* 허용됩니다. */
	return true;
}

#ifndef VM
/* 이 블록의 코드는 프로젝트 2에서만 사용됩니다.
 * 프로젝트 2 전 범위를 위해 함수를 구현하려면, #ifndef 매크로 밖에서 구현하십시오. */

/* load() 보조 함수들. */
static bool install_page(void *upage, void *kpage, bool writable);

/* FILE의 OFS 오프셋에서 시작하는 세그먼트를 주소 UPAGE에 로드합니다.
 * 총 READ_BYTES + ZERO_BYTES 바이트의 가상 메모리를 다음과 같이 초기화합니다:
 *
 * - READ_BYTES 바이트는 FILE의 OFS에서부터 읽어서 UPAGE에 채웁니다.
 *
 * - UPAGE + READ_BYTES 이후의 ZERO_BYTES 바이트는 0으로 채웁니다.
 *
 * WRITABLE이 true면 사용자 프로세스가 이 페이지를 수정할 수 있으며,
 * 그렇지 않으면 읽기 전용입니다.
 *
 * 성공 시 true, 메모리 할당 오류나 디스크 읽기 오류 시 false를 반환합니다. */
static bool
load_segment(struct file *file, off_t ofs, uint8_t *upage,
			 uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
	ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT(pg_ofs(upage) == 0);
	ASSERT(ofs % PGSIZE == 0);

	file_seek(file, ofs);
	while (read_bytes > 0 || zero_bytes > 0)
	{
		/* 이 페이지를 어떻게 채울지 계산합니다.
		 * FILE에서 PAGE_READ_BYTES 바이트를 읽고,
		 * 나머지 PAGE_ZERO_BYTES 바이트는 0으로 채웁니다. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* 메모리 페이지 하나를 가져옵니다. */
		uint8_t *kpage = palloc_get_page(PAL_USER);
		if (kpage == NULL)
			return false;

		/* 이 페이지를 로드합니다. */
		if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes)
		{
			palloc_free_page(kpage);
			return false;
		}
		memset(kpage + page_read_bytes, 0, page_zero_bytes);

		/* 이 페이지를 프로세스의 주소 공간에 추가합니다. */
		if (!install_page(upage, kpage, writable))
		{
			printf("fail\n");
			palloc_free_page(kpage);
			return false;
		}

		/* 다음으로 진행. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* USER_STACK에 0으로 채워진 페이지를 매핑하여 최소한의 스택을 생성합니다. */
static bool
setup_stack(struct intr_frame *if_)
{
	uint8_t *kpage;
	bool success = false;

	kpage = palloc_get_page(PAL_USER | PAL_ZERO);
	if (kpage != NULL)
	{
		success = install_page(((uint8_t *)USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK;
		else
			palloc_free_page(kpage);
	}
	return success;
}

/* 사용자 가상 주소 UPAGE에서 커널 가상 주소 KPAGE로의 매핑을
 * 페이지 테이블에 추가합니다.
 * WRITABLE이 true면 사용자 프로세스가 페이지를 수정할 수 있고,
 * 그렇지 않으면 읽기 전용입니다.
 * UPAGE는 이미 매핑되어 있으면 안 됩니다.
 * KPAGE는 아마도 palloc_get_page()로 사용자 풀에서 얻은 페이지여야 합니다.
 * 성공 시 true를, UPAGE가 이미 매핑되어 있거나 메모리 할당에 실패하면 false를 반환합니다. */
static bool
install_page(void *upage, void *kpage, bool writable)
{
	struct thread *t = thread_current();

	/* 해당 가상 주소에 이미 페이지가 없는지 확인한 후, 우리의 페이지를 거기에 매핑합니다. */
	return (pml4_get_page(t->pml4, upage) == NULL && pml4_set_page(t->pml4, upage, kpage, writable));
}
#else
/* 여기서부터의 코드는 프로젝트 3 이후에 사용됩니다.
 * 프로젝트 2에만 필요한 구현을 원한다면, 윗 블록에 구현하십시오. */

static bool
lazy_load_segment(struct page *page, void *aux)
{
	/* TODO: 파일에서 세그먼트를 로드하십시오. */
	/* TODO: 이 함수는 주소 VA에서 첫 페이지 폴트가 발생했을 때 호출됩니다. */
	/* TODO: 이 함수를 호출할 때 VA는 유효합니다. */
}

/* FILE의 OFS 오프셋에서 시작하는 세그먼트를 주소 UPAGE에 로드합니다.
 * 총 READ_BYTES + ZERO_BYTES 바이트의 가상 메모리를 다음과 같이 초기화합니다:
 *
 * - READ_BYTES 바이트는 FILE의 OFS에서부터 읽어서 UPAGE에 채웁니다.
 *
 * - UPAGE + READ_BYTES 이후의 ZERO_BYTES 바이트는 0으로 채웁니다.
 *
 * WRITABLE이 true면 사용자 프로세스가 이 페이지를 수정할 수 있으며,
 * 그렇지 않으면 읽기 전용입니다.
 *
 * 성공 시 true, 메모리 할당 오류나 디스크 읽기 오류 시 false를 반환합니다. */
static bool
load_segment(struct file *file, off_t ofs, uint8_t *upage,
			 uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
	ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT(pg_ofs(upage) == 0);
	ASSERT(ofs % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0)
	{
		/* 이 페이지를 어떻게 채울지 계산합니다.
		 * FILE에서 PAGE_READ_BYTES 바이트를 읽고,
		 * 나머지 PAGE_ZERO_BYTES 바이트는 0으로 채웁니다. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: lazy_load_segment에 정보를 전달하기 위한 aux를 설정하세요. */
		void *aux = NULL;
		if (!vm_alloc_page_with_initializer(VM_ANON, upage,
											writable, lazy_load_segment, aux))
			return false;

		/* 다음으로 진행. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* USER_STACK에 스택용 PAGE를 생성합니다. 성공 시 true를 반환합니다. */
static bool
setup_stack(struct intr_frame *if_)
{
	bool success = false;
	void *stack_bottom = (void *)(((uint8_t *)USER_STACK) - PGSIZE);

	/* TODO: stack_bottom에 스택을 매핑하고 즉시 클레임(claim)하십시오.
	 * TODO: 성공 시 rsp를 적절히 설정하십시오.
	 * TODO: 해당 페이지가 스택임을 표시해야 합니다. */
	/* TODO: 여기에 코드를 작성하세요 */

	return success;
}
#endif /* VM */