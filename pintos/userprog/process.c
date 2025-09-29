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

static struct thread *get_child_process(int pid)
{
	struct thread *curr = thread_current();
	struct thread *t;

	for (struct list_elem *e = list_begin(&curr->child_list); e != list_end(&curr->child_list); e = list_next(e))
	{
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

/* ===== 첫 번째 사용자 프로세스 생성 함수 ===== */
/* 
 * initd라는 첫 번째 사용자 프로세스를 생성함
 * file_name: 실행할 프로그램의 명령줄 (프로그램명 + 인자들)
 * 
 * 중요한 점: 스레드 이름은 프로그램명만 사용하지만, 실제 실행은 전체 명령줄을 사용함
 * 이는 스레드 이름의 길이 제한 때문임
 */
tid_t process_create_initd(const char *file_name)
{
	char *fn_copy;
	tid_t tid;

	/* 파일명을 커널 메모리에 복사함 - 사용자 메모리가 변경될 수 있기 때문임 */
	fn_copy = palloc_get_page(0);
	if (fn_copy == NULL)
		return TID_ERROR;
	strlcpy(fn_copy, file_name, PGSIZE);

	/* 명령줄에서 프로그램 이름만 추출함 (스레드 이름 용도) */
	char *save_ptr;
	char *prog_name = strtok_r(fn_copy, " ", &save_ptr);  // 첫 번째 토큰이 프로그램명
	if (prog_name == NULL)
	{
		palloc_free_page(fn_copy);
		return TID_ERROR;
	}

	/* strtok_r이 원본 문자열을 수정하므로 전체 명령행을 다시 복사함 */
	char *cmd_copy = palloc_get_page(0);
	if (cmd_copy == NULL)
	{
		palloc_free_page(fn_copy);
		return TID_ERROR;
	}
	strlcpy(cmd_copy, file_name, PGSIZE);

	/* 
	 * 프로그램 이름으로만 스레드를 생성함 
	 * initd 함수가 스레드의 시작점이 되며, cmd_copy가 인자로 전달됨
	 */
	tid = thread_create(prog_name, PRI_DEFAULT, initd, cmd_copy);
	if (tid == TID_ERROR)
	{
		palloc_free_page(cmd_copy);  // 실패시에만 해제 (성공시에는 initd에서 사용)
	}

	palloc_free_page(fn_copy);  // 임시 복사본은 항상 해제
	return tid;
}

/* 
 * 첫 번째 사용자 프로세스를 실행하는 스레드 함수
 * f_name: process_create_initd에서 전달한 전체 명령줄
 * 
 * 이 함수는 커널 스레드로 시작해서 사용자 프로세스로 변신함 (한 번 변신하면 되돌아올 수 없음)
 */
static void
initd(void *f_name)
{
#ifdef VM
	/* 가상 메모리를 사용하는 경우 보조 페이지 테이블을 초기화함 */
	supplemental_page_table_init(&thread_current()->spt);
#endif

	/* 프로세스 초기화 (현재는 빈 함수이지만 향후 확장 가능) */
	process_init();

	/* 
	 * process_exec을 호출하여 사용자 프로그램으로 변신함
	 * 성공하면 이 함수는 절대 리턴하지 않음 (사용자 프로그램으로 점프)
	 * 실패하면 시스템 패닉 발생
	 */
	if (process_exec(f_name) < 0)
		PANIC("initd 실행 실패\n");
	NOT_REACHED();  // 여기에 도달하면 안됨
}

/* ===== FORK 시스템 콜의 핵심 구현 ===== */
/*
 * 현재 프로세스를 복제하여 동일한 자식 프로세스를 생성함
 * 
 * name: 자식 프로세스의 스레드 이름
 * if_: 현재 시스템 콜이 호출된 시점의 interrupt frame (CPU 상태 정보)
 *      이 정보가 없으면 자식이 어디서부터 실행을 재개할지 알 수 없음
 * 
 * 반환값: 부모에게는 자식의 TID, 자식에게는 0이 반환됨 (유닉스 fork와 동일)
 * 
 * 동작 원리:
 * 1. 현재 CPU 상태를 저장
 * 2. 새 스레드(__do_fork)를 생성하여 실제 복제 작업 수행
 * 3. 자식의 초기화가 완료될 때까지 대기
 */
tid_t process_fork(const char *name, struct intr_frame *if_)
{
	struct thread *curr = thread_current();

	/* 
	 * 1단계: 현재 프로세스의 interrupt frame을 저장함
	 * 
	 * rrsp(): 현재 커널 스택의 RSP 레지스터 값을 가져옴
	 * pg_round_up(): 페이지 경계로 올림 (4KB 정렬)
	 * 
	 * 커널 스택의 맨 위에는 사용자 모드에서 시스템 콜을 호출할 때 저장된
	 * interrupt frame이 있음. 이것이 바로 fork 시점의 CPU 상태임
	 */
	struct intr_frame *f = (pg_round_up(rrsp()) - sizeof(struct intr_frame));
	memcpy(&curr->parent_if, f, sizeof(struct intr_frame));

	/* 
	 * 2단계: 자식 스레드를 생성함
	 * 
	 * __do_fork 함수가 자식 스레드의 시작점이 되며,
	 * 현재 스레드(부모)의 포인터가 인자로 전달됨
	 * 이를 통해 자식이 부모의 메모리와 파일을 복사할 수 있음
	 */
	tid_t tid = thread_create(name, PRI_DEFAULT, __do_fork, curr);

	if (tid == TID_ERROR)
		return TID_ERROR;

	/* 
	 * 3단계: 자식이 fork 완료할 때까지 대기함
	 * 
	 * get_child_process(): 자식 리스트에서 해당 TID를 찾음
	 * fork_sema: 자식이 초기화를 완료하면 up() 신호를 보냄
	 * 
	 * 이 동기화가 없으면 자식의 메모리 복사가 완료되기 전에
	 * 부모가 먼저 실행을 계속해버릴 수 있음
	 */
	struct thread *child = get_child_process(tid);
	sema_down(&child->fork_sema);

	// /* 자식의 초기화가 실패했다면 에러를 반환함 */
	if (child->exit_status == TID_ERROR)
		return TID_ERROR;

	return tid;  // 부모는 자식의 TID를 받음
}

#ifndef VM
/* 
 * 부모의 메모리 페이지를 자식으로 복사하는 콜백 함수
 * pml4_for_each() 함수가 부모의 모든 페이지에 대해 이 함수를 호출함
 * 
 * pte: 페이지 테이블 엔트리 (권한 정보 포함)
 * va: 복사할 가상 주소
 * aux: pml4_for_each()에서 전달한 부모 스레드 포인터
 * 
 * 반환값: 성공시 true, 실패시 false (메모리 부족 등)
 */
static bool duplicate_pte(uint64_t *pte, void *va, void *aux)
{
	struct thread *current = thread_current();    // 자식 스레드 (복사 대상)
	struct thread *parent = (struct thread *)aux;  // 부모 스레드 (복사 원본)
	void *parent_page;
	void *newpage;
	bool writable;

	/* 
	 * 1단계: 커널 페이지는 복사하지 않고 공유함
	 * 
	 * 커널 코드와 데이터는 모든 프로세스가 동일하게 사용하므로
	 * 복사할 필요가 없음. 오히려 복사하면 메모리 낭비임
	 */
	if (is_kernel_vaddr(va))
		return true;

	/* 
	 * 2단계: 부모의 해당 가상 주소에서 물리 페이지를 찾음
	 * 
	 * pml4_get_page(): 가상 주소를 물리 주소로 변환
	 * NULL이 반환되면 해당 주소에 페이지가 매핑되지 않음
	 */
	parent_page = pml4_get_page(parent->pml4, va);
	if (parent_page == NULL)
		return false;

	/* 
	 * 3단계: 자식용 새 물리 페이지를 할당함
	 * 
	 * PAL_USER: 사용자 프로세스용 페이지
	 * PAL_ZERO: 0으로 초기화 (보안상 중요)
	 */
	newpage = palloc_get_page(PAL_USER | PAL_ZERO);
	if (newpage == NULL)
		return false;  // 메모리 부족

	/* 
	 * 4단계: 부모 페이지의 내용을 자식 페이지로 복사함
	 * 
	 * 이것이 fork의 핵심임. 부모와 동일한 메모리 내용을 가지되,
	 * 서로 다른 물리 페이지를 사용하여 독립성을 보장함
	 */
	memcpy(newpage, parent_page, PGSIZE);
	writable = is_writable(pte);  // 부모의 권한을 그대로 가져옴

	/* 
	 * 5단계: 자식의 페이지 테이블에 새 페이지를 매핑함
	 * 
	 * 자식도 부모와 동일한 가상 주소에서 접근할 수 있도록
	 * 같은 가상 주소(va)에 새로운 물리 페이지(newpage)를 매핑
	 */
	if (!pml4_set_page(current->pml4, va, newpage, writable))
	{
		/* 페이지 테이블 매핑에 실패하면 할당한 페이지를 해제함 */
		palloc_free_page(newpage);
		return false;
	}
	return true;
}
#endif

static void __do_fork(void *aux)
{
    struct intr_frame if_;
    struct thread *parent = (struct thread *)aux;
    struct thread *current = thread_current();
    struct intr_frame *parent_if = &parent->parent_if;
    bool succ = true;

    memcpy(&if_, parent_if, sizeof(struct intr_frame));
    if_.R.rax = 0;

    current->pml4 = pml4_create();
    if (current->pml4 == NULL)
        goto error;

    if (parent->runn_file != NULL)
    {
        current->runn_file = file_duplicate(parent->runn_file);
    }

    process_activate(current);

#ifdef VM
    supplemental_page_table_init(&current->spt);
    if (!supplemental_page_table_copy(&current->spt, &parent->spt))
        goto error;
#else
    if (!pml4_for_each(parent->pml4, duplicate_pte, parent))
        goto error;
#endif

    if (parent->fd_idx >= FDCOUNT_LIMIT)
        goto error;

    current->fd_idx = parent->fd_idx;

    for (int fd = 3; fd < parent->fd_idx; fd++)
    {
        if (parent->fdt[fd] == NULL)
            continue;
        current->fdt[fd] = file_duplicate(parent->fdt[fd]);
    }

    // 성공 신호를 먼저 보냄
    sema_up(&current->fork_sema);
    
    process_init();

    // 여기서 직접 사용자 모드로 전환
    do_iret(&if_);
    NOT_REACHED(); // 이 줄에 절대 도달하면 안됨

error:
    current->exit_status = TID_ERROR;
    sema_up(&current->fork_sema);
    thread_exit();
}

/* ===== EXEC 시스템 콜 구현 ===== */
/*
 * 현재 프로세스를 새로운 프로그램으로 교체함
 * 
 * f_name: 실행할 프로그램의 명령줄 (프로그램명 + 인자들)
 * 
 * 동작 원리:
 * 1. 기존 메모리 공간을 정리
 * 2. 새 프로그램을 메모리에 로드
 * 3. 인자들을 스택에 배치
 * 4. 새 프로그램의 시작점으로 점프
 * 
 * 성공시: 이 함수는 리턴하지 않음 (새 프로그램으로 교체됨)
 * 실패시: -1 반환
 */
int process_exec(void *f_name)
{
	char *file_name = f_name;
	bool success = false;

	/* 
	 * 새 프로그램의 초기 interrupt frame을 설정함
	 * 
	 * 사용자 모드 세그먼트 설정:
	 * - ds, es, ss: 데이터 세그먼트 (사용자)
	 * - cs: 코드 세그먼트 (사용자)
	 * - eflags: 인터럽트 허용 + MBS 플래그
	 */
	struct intr_frame _if;
	memset(&_if, 0, sizeof _if);
	_if.ds = _if.es = _if.ss = SEL_UDSEG;
	_if.cs = SEL_UCSEG;
	_if.eflags = FLAG_IF | FLAG_MBS;

	/* 
	 * 기존 실행 파일을 정리함 (메모리 해제 전에 먼저 처리)
	 * 
	 * 실행 중인 파일은 쓰기가 금지되어 있으므로
	 * 먼저 쓰기를 허용한 후 파일을 닫음
	 */
	struct thread *curr = thread_current();
	if (curr->runn_file != NULL)
	{
		file_allow_write(curr->runn_file);
		file_close(curr->runn_file);
		curr->runn_file = NULL;
	}

	/* 
	 * 기존 메모리 공간을 정리함
	 * 
	 * 새 프로그램을 위해 기존의 페이지 테이블과
	 * 가상 메모리 구조를 모두 해제함
	 */
	process_cleanup();

	/* 
	 * 명령줄을 파싱하여 프로그램명과 인자들로 분리함
	 * 
	 * strtok_r(): 공백으로 구분된 토큰들을 추출
	 * 따옴표 처리: 'program name' 같은 형태도 지원
	 */
	char *argv[32];  // 최대 31개 인자 + NULL
	int argc = 0;
	char *save_ptr;

	char *token = strtok_r(file_name, " ", &save_ptr);
	while (token && argc < 31)
	{
		/* 
		 * 따옴표 제거 처리
		 * 
		 * 파일명에 공백이 포함된 경우 'file name' 또는 "file name"
		 * 형태로 전달될 수 있음. 시작과 끝 따옴표를 제거함
		 */
		if ((token[0] == '\'' || token[0] == '"'))
		{
			size_t len = strlen(token);
			if (len >= 2 && token[len - 1] == token[0])
			{
				token[len - 1] = '\0';  // 끝 따옴표 제거
				token++;                // 시작 따옴표 건너뜀
			}
		}
		argv[argc++] = token;
		token = strtok_r(NULL, " ", &save_ptr);
	}
	argv[argc] = NULL;  // NULL로 종료

	/* 인자가 없으면 실패 */
	if (argc == 0)
	{
		palloc_free_page(file_name);
		return -1;
	}

	/* 
	 * ELF 바이너리를 메모리에 로드함
	 * 
	 * argv[0]: 실행할 프로그램의 파일명
	 * &_if: 로드 완료 후 초기 상태 정보가 설정됨
	 */
	success = load(argv[0], &_if);
	if (!success)
	{
		palloc_free_page(file_name);
		return -1;
	}

	/* 
	 * 스택에 인자들을 배치함
	 * 
	 * C 프로그램의 main(int argc, char *argv[]) 호출 규약에 맞게
	 * 스택에 인자들을 배치하고 레지스터를 설정함
	 */
	if (!argument_stack(&_if, argv, argc))
	{
		palloc_free_page(file_name);
		return -1;
	}

	/* 임시 메모리 해제 */
	palloc_free_page(file_name);
	
	/* 
	 * 새 프로그램으로 점프함
	 * 
	 * do_iret(): 사용자 모드로 전환하여 새 프로그램의 entry point에서 실행 시작
	 * 이 함수는 절대 리턴하지 않음 (프로세스가 완전히 교체됨)
	 */
	do_iret(&_if);
	NOT_REACHED();
}

/* 
 * C 프로그램 호출 규약에 맞게 스택에 인자들을 배치함
 * 
 * if_: interrupt frame (스택 포인터와 레지스터 설정)
 * argv: 인자 배열
 * argc: 인자 개수
 * 
 * x86-64 호출 규약:
 * - rdi: 첫 번째 인자 (argc)
 * - rsi: 두 번째 인자 (argv)
 * - 스택: 8바이트 정렬 필수
 */
#define ARG_MAX 64
static bool
argument_stack(struct intr_frame *if_, char *argv[], int argc)
{
	uint8_t *rsp = (uint8_t *)if_->rsp;  // 현재 스택 포인터

	/* 
	 * 1단계: 인자 문자열들을 스택에 복사함 (역순으로)
	 * 
	 * 스택은 아래쪽으로 자라므로 마지막 인자부터 먼저 배치
	 * 각 문자열의 주소를 arg_addrs에 저장해둠 (나중에 argv 배열에서 사용)
	 */
	uint64_t arg_addrs[ARG_MAX];
	for (int i = argc - 1; i >= 0; i--)
	{
		size_t len = strlen(argv[i]) + 1;  // NULL 터미네이터 포함
		rsp -= len;                        // 스택 포인터를 문자열 크기만큼 감소
		memcpy(rsp, argv[i], len);        // 문자열을 스택에 복사
		arg_addrs[i] = (uint64_t)rsp;     // 주소를 저장
	}

	/* 
	 * 2단계: 8바이트 경계로 정렬함
	 * 
	 * x86-64에서는 스택이 8바이트로 정렬되어야 함
	 * 하위 3비트를 0으로 만들어 8의 배수로 맞춤
	 */
	rsp = (uint8_t *)((uintptr_t)rsp & ~(uintptr_t)0x7);

	/* 
	 * 3단계: argv 포인터 배열을 스택에 배치함
	 * 
	 * argv[0], argv[1], ..., argv[argc-1], NULL 순서로 배치
	 * 각각은 8바이트 포인터임
	 */
	rsp -= 8 * (argc + 1);                // (argc + 1)개의 포인터 공간 확보
	uint64_t *argv_slots = (uint64_t *)rsp;
	for (int i = 0; i < argc; i++)
	{
		argv_slots[i] = arg_addrs[i];     // 문자열 주소를 포인터 배열에 저장
	}
	argv_slots[argc] = 0;                 // NULL 센티널

	/* 
	 * 4단계: 가짜 반환 주소를 배치함
	 * 
	 * main 함수가 리턴할 때를 대비해 가짜 반환 주소를 배치
	 * 실제로는 main이 리턴하면 exit 시스템 콜이 호출됨
	 */
	rsp -= 8;
	*(uint64_t *)rsp = 0;

	/* 
	 * 5단계: 레지스터를 설정함
	 * 
	 * x86-64 함수 호출 규약에 따라:
	 * - rdi: 첫 번째 인자 (argc)
	 * - rsi: 두 번째 인자 (argv 포인터)
	 */
	if_->R.rdi = argc;
	if_->R.rsi = (uint64_t)argv_slots;

	/* 최종 스택 포인터를 설정함 */
	if_->rsp = (uint64_t)rsp;

	return true;
}

/* ===== WAIT 시스템 콜 구현 ===== */
/*
 * 자식 프로세스가 종료될 때까지 기다리고 종료 상태를 반환함
 * 
 * child_tid: 기다릴 자식 프로세스의 TID
 * 
 * 제약 조건:
 * - 직계 자식만 기다릴 수 있음
 * - 같은 자식에 대해 한 번만 wait 가능
 * - 자식이 이미 종료되었어도 종료 상태를 반환해야 함 (좀비 프로세스 개념)
 * 
 * 반환값: 자식의 종료 상태, 실패시 -1
 */
int process_wait(tid_t child_tid)
{
	struct thread *cur = thread_current();
	struct thread *child = get_child_process(child_tid);

	/* 해당 TID가 내 자식이 아니거나 이미 wait했으면 실패 */
	if (child == NULL)
		return -1;

	/* 
	 * 자식이 종료될 때까지 기다림
	 * 
	 * wait_sema: 자식이 exit할 때 up() 신호를 보냄
	 * 자식이 이미 종료되었으면 이미 up()되어 있어서 즉시 통과
	 */
	sema_down(&child->wait_sema);

	/* 자식의 종료 상태를 가져옴 */
	int exit_status = child->exit_status;
	
	/* 
	 * 자식을 부모의 자식 리스트에서 제거함
	 * 
	 * 이제 이 자식에 대해서는 다시 wait할 수 없음
	 * 좀비 상태 종료
	 */
	list_remove(&child->child_elem);

	/* 
	 * 자식이 완전히 종료될 수 있도록 허용함
	 * 
	 * exit_sema: 자식은 부모가 종료 상태를 수거할 때까지 대기 중
	 * 이 신호를 받으면 자식의 스레드가 완전히 소멸됨
	 */
	sema_up(&child->exit_sema);

	return exit_status;
}

/* ===== 프로세스 종료 처리 ===== */
/*
 * 프로세스를 종료함 (thread_exit()에서 호출됨)
 * 
 * 수행 작업:
 * 1. 열린 모든 파일들을 닫음
 * 2. 실행 파일의 쓰기 금지를 해제하고 닫음
 * 3. 파일 디스크립터 테이블 해제
 * 4. 메모리 공간 해제 (process_cleanup 호출)
 * 5. 부모에게 종료 알림
 * 6. 부모의 수거를 기다림 (좀비 상태)
 */
void process_exit(void)
{
	struct thread *curr = thread_current();

	/* 
	 * 열린 파일들을 모두 닫음
	 * 
	 * fd 3번부터 시작 (0=stdin, 1=stdout, 2=stderr는 시스템이 관리)
	 * 각 파일을 닫고 fdt 슬롯을 NULL로 초기화
	 */
	for (int fd = 3; fd < curr->fd_idx; fd++)
	{
		if (curr->fdt[fd] != NULL)
		{
			file_close(curr->fdt[fd]);
			curr->fdt[fd] = NULL;
		}
	}

	/* 
	 * 현재 실행 중인 파일을 닫음
	 * 
	 * file_allow_write(): 실행 중 설정된 쓰기 금지를 해제
	 * 이를 통해 다른 프로세스가 이 파일을 수정할 수 있게 됨
	 */
	if (curr->runn_file != NULL)
	{
		file_allow_write(curr->runn_file);
		file_close(curr->runn_file);
		curr->runn_file = NULL;
	}

	/* 
	 * 파일 디스크립터 테이블 메모리를 해제함
	 * 
	 * palloc_free_multiple(): 여러 페이지로 할당된 메모리를 해제
	 */
	if (curr->fdt != NULL)
	{
		palloc_free_multiple(curr->fdt, FDT_PAGES);
		curr->fdt = NULL;
	}

	/* 
	 * 메모리 공간을 해제함 (페이지 테이블, 물리 메모리 등)
	 */
	process_cleanup();

	/* 
	 * 부모-자식 동기화 처리
	 * 
	 * wait_sema up: 부모가 wait 중이라면 깨워서 종료 상태를 전달
	 * exit_sema down: 부모가 종료 상태를 수거할 때까지 대기 (좀비 상태)
	 * 
	 * 이 순서가 중요함. 부모가 아직 wait를 호출하지 않았다면
	 * 종료 상태가 보존되어야 하기 때문임
	 */
	sema_up(&curr->wait_sema);
	sema_down(&curr->exit_sema);
}

/* 
 * 프로세스의 메모리 자원을 해제함
 * 
 * 수행 작업:
 * 1. 보조 페이지 테이블 해제 (VM 사용시)
 * 2. 페이지 테이블을 커널 전용으로 전환
 * 3. 프로세스의 페이지 테이블과 모든 물리 메모리 해제
 */
static void
process_cleanup(void)
{
	struct thread *curr = thread_current();

#ifdef VM
	/* 가상 메모리 사용시 보조 페이지 테이블을 해제함 */
	supplemental_page_table_kill(&curr->spt);
#endif

	uint64_t *pml4;
	
	/* 
	 * 현재 프로세스의 페이지 디렉터리를 파괴함
	 * 
	 * 순서가 매우 중요함:
	 * 1. curr->pml4를 NULL로 설정 (타이머 인터럽트 등에서 접근 방지)
	 * 2. 커널 페이지 테이블로 전환
	 * 3. 기존 페이지 테이블 해제
	 * 
	 * 이 순서를 지키지 않으면 활성 페이지 테이블이 해제된 상태에서
	 * 인터럽트가 발생할 수 있어 시스템 크래시가 발생할 수 있음
	 */
	pml4 = curr->pml4;
	if (pml4 != NULL)
	{
		curr->pml4 = NULL;        // 현재 스레드의 페이지 테이블 포인터 제거
		pml4_activate(NULL);      // 커널 전용 페이지 테이블로 전환
		pml4_destroy(pml4);       // 기존 페이지 테이블과 물리 메모리 해제
	}
}

/* 
 * 컨텍스트 스위치시 스레드의 메모리 환경을 활성화함
 * 
 * next: 실행할 스레드
 * 
 * 수행 작업:
 * 1. 해당 스레드의 페이지 테이블을 활성화
 * 2. TSS(Task State Segment) 업데이트 (커널 스택 정보)
 */
void process_activate(struct thread *next)
{
	/* 스레드의 페이지 테이블을 CPU에 로드함 */
	pml4_activate(next->pml4);

	/* 
	 * 인터럽트 처리용 커널 스택을 설정함
	 * 
	 * 사용자 모드에서 인터럽트나 시스템 콜이 발생하면
	 * CPU가 자동으로 이 스택으로 전환함
	 */
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

	t->runn_file = file;   // 실행 파일 저장
	file_deny_write(file); // 실행 중 쓰기 방지

	success = true;

done:
	/* 로드 성공 여부와 관계없이 여기로 도착합니다. */
	if (!success)
		file_close(file); // 실패시에만 파일 닫기
	// 성공시에는 file을 닫지 않음 (runn_file에 저장되어 나중에 process_exit에서 닫음)
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