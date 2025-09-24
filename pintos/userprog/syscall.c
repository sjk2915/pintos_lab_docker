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



/* ===== 시스템 콜 초기화 함수 ===== */
/*
 * 시스템 콜을 위한 하드웨어 및 소프트웨어 환경을 설정함
 * 
 * x86-64에서 시스템 콜은 SYSCALL/SYSRET 명령어를 통해 구현됨
 * 이 함수는 CPU의 MSR (Model Specific Register)들을 설정하여
 * 시스템 콜이 올바르게 동작하도록 함
 * 
 * 동작 원리:
 * 1. 사용자가 SYSCALL 명령어 실행
 * 2. CPU가 자동으로 커널 모드로 전환
 * 3. syscall_entry 함수로 점프
 * 4. syscall_handler가 실제 시스템 콜을 처리
 */
void syscall_init(void)
{
    /*
     * MSR_STAR 레지스터 설정 - 시스템 콜시 사용할 세그먼트 선택자들
     * 
     * 상위 32비트: 사용자 모드 세그먼트 (SYSCALL에서 SYSRET로 돌아갈 때 사용)
     * 하위 32비트: 커널 모드 세그먼트 (SYSCALL시 자동으로 설정됨)
     * 
     * SEL_UCSEG - 0x10: 사용자 데이터 세그먼트 계산
     * SEL_KCSEG: 커널 코드 세그먼트
     */
    write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 |
                            ((uint64_t)SEL_KCSEG) << 32);
                            
    /*
     * MSR_LSTAR 레지스터 설정 - 시스템 콜 진입점 주소
     * 
     * SYSCALL 명령어가 실행되면 CPU가 자동으로 이 주소로 점프함
     * syscall_entry는 어셈블리로 작성된 진입점으로,
     * 레지스터를 저장하고 syscall_handler를 호출함
     */
    write_msr(MSR_LSTAR, (uint64_t)syscall_entry);
    
    /*
     * MSR_SYSCALL_MASK 레지스터 설정 - 시스템 콜시 마스킹할 플래그들
     * 
     * 시스템 콜 진입시 이 플래그들이 자동으로 클리어됨:
     * - FLAG_IF: 인터럽트 비활성화 (시스템 콜 처리 중 방해 방지)
     * - FLAG_TF: 트레이스 플래그 비활성화 (디버깅 방지)
     * - FLAG_DF: 방향 플래그 클리어 (문자열 연산 방향 통일)
     * - FLAG_IOPL: I/O 특권 레벨 클리어 (보안)
     * - FLAG_AC: 정렬 체크 비활성화 (성능)
     * - FLAG_NT: Nested Task 플래그 클리어 (호환성)
     */
    write_msr(MSR_SYSCALL_MASK,
              FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

    /*
     * 파일시스템 접근용 락 초기화
     * 
     * Pintos의 파일시스템은 thread-safe하지 않으므로
     * 모든 파일시스템 연산을 하나의 락으로 보호해야 함
     * 이는 성능상 최적은 아니지만 안전성을 보장함
     */
    lock_init(&filesys_lock);
}

/* ===== 시스템 콜 핸들러 - 모든 시스템 콜의 중앙 처리소 ===== */
/*
 * 모든 시스템 콜 요청을 받아서 적절한 처리를 수행함
 * 
 * f: interrupt frame - 시스템 콜 호출 시점의 CPU 상태
 *    여기에는 시스템 콜 번호와 인자들이 저장되어 있음
 * 
 * x86-64 시스템 콜 규약:
 * - rax: 시스템 콜 번호
 * - rdi: 첫 번째 인자
 * - rsi: 두 번째 인자  
 * - rdx: 세 번째 인자
 * - rcx, r8, r9: 추가 인자들 (필요시)
 * - rax: 반환값 (처리 완료 후)
 */
void syscall_handler(struct intr_frame *f)
{
    /*
     * 시스템 콜 번호를 추출함
     * 
     * rax 레지스터에는 사용자가 호출한 시스템 콜의 번호가 들어있음
     * 예: SYS_FORK = 0, SYS_EXEC = 1, SYS_WAIT = 2 등
     */
    uint64_t nr = f->R.rax;

    /*
     * 시스템 콜 번호에 따라 해당하는 처리를 수행함
     * 
     * 각 케이스는 독립적인 시스템 콜을 처리하며,
     * 대부분 process.c나 filesys 관련 함수들을 호출함
     */
    switch (nr)
    {
    case SYS_HALT:
        /*
         * 시스템을 종료함
         * 
         * 인자 없음, 반환값 없음 (시스템이 종료되므로)
         * 주로 테스트 완료시나 치명적 오류 발생시 사용
         */
        power_off();
        break;

    case SYS_EXIT:
    {
        /*
         * 현재 프로세스를 종료함
         * 
         * 인자: status (종료 상태 코드)
         * - 0: 정상 종료
         * - 양수/음수: 오류 코드 (프로그램마다 의미가 다름)
         * 
         * 중요한 점: 이 시스템 콜은 절대 리턴하지 않음
         * thread_exit()이 호출되면 현재 스레드가 완전히 소멸됨
         */
        int status = (int)f->R.rdi;                // 첫 번째 인자에서 종료 상태 추출
        struct thread *cur = thread_current();
        cur->exit_status = status;                 // 부모가 wait으로 받을 종료 상태 저장
        printf("%s: exit(%d)\n", cur->name, status); // 디버깅용 출력
        thread_exit();                             // 프로세스 종료 (리턴하지 않음)
    }
    break;

    case SYS_WRITE:
    {
        /*
         * 파일 디스크립터에 데이터를 씀
         * 
         * 인자들:
         * - fd: 파일 디스크립터 (0=stdin, 1=stdout, 2=stderr, 3이상=일반파일)
         * - buffer: 쓸 데이터가 들어있는 메모리 주소
         * - size: 쓸 바이트 수
         * 
         * 반환값: 실제로 쓴 바이트 수 (실패시 -1)
         */
        int fd = (int)f->R.rdi;                    // 파일 디스크립터
        const void *buffer = (const void *)f->R.rsi; // 데이터 버퍼
        unsigned size = (unsigned)f->R.rdx;        // 쓸 크기

        /*
         * 버퍼 주소의 유효성을 검증함
         * 
         * 사용자가 잘못된 주소를 전달하면 커널 크래시가 발생할 수 있으므로
         * 미리 주소가 유효한지 확인해야 함
         */
        check_buffer((void *)buffer, size);

        if (fd == 1)
        {
            /*
             * stdout(표준 출력)에 쓰기
             * 
             * putbuf: 콘솔에 직접 출력하는 커널 함수
             * 이는 화면에 즉시 출력되며, 버퍼링되지 않음
             */
            putbuf((const char *)buffer, size);
            f->R.rax = size;                       // 성공시 쓴 바이트 수 반환
        }
        else if (fd == 0)
        {
            /*
             * stdin(표준 입력)에 쓰기 시도
             * 
             * 논리적으로 말이 안되므로 에러 반환
             * 실제 유닉스에서도 stdin은 읽기 전용임
             */
            f->R.rax = -1;                         // 에러 반환
        }
        else
        {
            /*
             * 일반 파일에 쓰기
             * 
             * get_file()로 fd에 해당하는 파일 구조체를 찾아서
             * 실제 파일에 데이터를 쓰는 작업을 수행함
             */
            struct file *file = get_file(fd);
            if (file == NULL)
            {
                /*
                 * 유효하지 않은 파일 디스크립터
                 * 
                 * 파일이 닫혔거나, 존재하지 않는 fd번호일 경우
                 */
                f->R.rax = -1;
                break;
            }

            /*
             * 파일시스템 락 획득 후 쓰기 수행
             * 
             * Pintos 파일시스템은 thread-safe하지 않으므로
             * 모든 파일 연산을 락으로 보호해야 함
             * 
             * 이는 여러 프로세스가 동시에 같은 파일에 접근할 때
             * 데이터 오염을 방지함
             */
            lock_acquire(&filesys_lock);
            int bytes_written = file_write(file, buffer, size);
            lock_release(&filesys_lock);

            f->R.rax = bytes_written;              // 실제로 쓴 바이트 수 반환
        }
        break;
    }

    case SYS_CREATE:
    {
        /*
         * 새로운 파일을 생성함
         * 
         * 인자들:
         * - path: 생성할 파일의 경로/이름
         * - sz: 초기 파일 크기 (바이트)
         * 
         * 반환값: 성공시 true, 실패시 false
         */
        const char *path = (const char *)f->R.rdi;
        unsigned sz = (unsigned)f->R.rsi;

        /*
         * 파일 경로 주소의 유효성 검증
         * 
         * 사용자가 NULL이나 커널 영역 주소를 전달할 수 있으므로
         * 반드시 검증해야 함
         */
        check_address((void *)path);

        /*
         * 파일명의 기본적인 유효성 검사
         * 
         * 빈 문자열이나 NULL 경로는 파일 생성이 불가능함
         */
        if (!path || path[0] == '\0')
        {
            f->R.rax = false;
            break;
        }

        /*
         * 실제 파일 생성 작업
         * 
         * filesys_create: 파일시스템에 새로운 파일을 생성하는 함수
         * 락으로 보호하여 동시성 문제를 방지함
         */
        lock_acquire(&filesys_lock);
        bool result = filesys_create(path, sz);
        lock_release(&filesys_lock);

        f->R.rax = result;                         // 생성 결과 반환
        break;
    }
    
    case SYS_OPEN:
    {
        /*
         * 파일을 열어서 파일 디스크립터를 반환함
         * 
         * 인자: path (열 파일의 경로)
         * 반환값: 성공시 파일 디스크립터 번호, 실패시 -1
         * 
         * 이 시스템 콜은 파일을 열기만 할 뿐, 아직 읽거나 쓰지는 않음
         * 반환된 fd를 사용해서 나중에 read/write를 수행함
         */
        const char *path = (const char *)f->R.rdi;

        check_address((void *)path);               // 경로 주소 검증
        
        /*
         * 파일시스템에서 파일을 열기
         * 
         * filesys_open: 실제 파일을 열고 file 구조체를 반환
         * 파일이 존재하지 않으면 NULL을 반환함
         */
        lock_acquire(&filesys_lock);
        struct file *file = filesys_open(path);
        lock_release(&filesys_lock);

        if (file == NULL)
        {
            /*
             * 파일 열기 실패
             * 
             * 파일이 존재하지 않거나, 권한이 없거나,
             * 다른 오류로 인해 열 수 없는 경우
             */
            f->R.rax = -1;
        }
        else
        {
            /*
             * 파일이 성공적으로 열렸으면 파일 디스크립터 할당
             * 
             * allocate_fd: 현재 프로세스의 fd 테이블에서 빈 슬롯을 찾아
             * 새로운 fd 번호를 할당하고 file 구조체와 연결함
             */
            int fd = allocate_fd(file);
            if (fd == -1)
            {
                /*
                 * fd 테이블이 가득 참
                 * 
                 * 프로세스당 열 수 있는 파일 개수에는 한계가 있음
                 * 한계에 도달하면 파일을 닫고 에러 반환
                 */
                file_close(file);                  // 메모리 누수 방지
                f->R.rax = -1;
            }
            else
            {
                f->R.rax = fd;                     // 성공적으로 할당된 fd 반환
            }
        }
        break;
    }

    case SYS_CLOSE:
    {
        /*
         * 파일 디스크립터를 닫음
         * 
         * 인자: fd (닫을 파일 디스크립터)
         * 반환값: 없음 (void)
         * 
         * 파일을 닫으면 해당 fd는 재사용 가능해지고,
         * 파일의 메모리 자원도 해제됨
         */
        int fd = (int)f->R.rdi;

        /*
         * fd가 유효한지 확인하고 파일 닫기
         * 
         * get_file: fd 번호에 해당하는 file 구조체를 찾음
         * NULL이면 이미 닫혔거나 유효하지 않은 fd임
         */
        struct file *file = get_file(fd);
        if (file != NULL)
        {
            /*
             * 실제 파일 닫기와 fd 슬롯 해제
             * 
             * file_close: 파일의 메모리 자원을 해제하고 파일시스템에 변경사항 반영
             * release_fd: fd 테이블에서 해당 슬롯을 NULL로 만들어 재사용 가능하게 함
             */
            lock_acquire(&filesys_lock);
            file_close(file);
            lock_release(&filesys_lock);

            release_fd(fd);                        // fd 슬롯 해제
        }
        /*
         * close는 반환값이 없음 (유닉스 규약)
         * 
         * 유효하지 않은 fd를 닫으려 해도 에러를 반환하지 않고
         * 조용히 무시함 (실제 유닉스 동작과 동일)
         */
        break;
    }
    
    case SYS_READ:
    {
        /*
         * 파일 디스크립터에서 데이터를 읽음
         * 
         * 인자들:
         * - fd: 읽을 파일 디스크립터
         * - buffer: 읽은 데이터를 저장할 메모리 주소
         * - size: 읽을 최대 바이트 수
         * 
         * 반환값: 실제로 읽은 바이트 수 (EOF나 실패시 적은 값일 수 있음)
         */
        int fd = (int)f->R.rdi;
        void *buffer = (void *)f->R.rsi;
        unsigned size = (unsigned)f->R.rdx;

        /*
         * 버퍼 주소와 크기의 유효성 검증
         * 
         * 사용자가 커널 영역을 가리키거나 NULL을 전달하면
         * 커널이 크래시할 수 있으므로 미리 검사함
         */
        check_buffer(buffer, size);

        if (fd == 0)
        {
            /*
             * stdin(표준 입력)에서 읽기
             * 
             * 키보드 입력을 한 글자씩 받아서 버퍼에 저장
             * input_getc(): 키보드에서 한 문자를 입력받는 커널 함수
             */
            char *buf = (char *)buffer;
            for (unsigned i = 0; i < size; i++)
            {
                buf[i] = input_getc();             // 키보드에서 문자 하나 읽기
            }
            f->R.rax = size;                       // 요청한 만큼 다 읽었다고 가정
        }
        else if (fd == 1)
        {
            /*
             * stdout(표준 출력)에서 읽기 시도
             * 
             * 논리적으로 말이 안되므로 에러 반환
             * stdout은 쓰기 전용임
             */
            f->R.rax = -1;
        }
        else
        {
            /*
             * 일반 파일에서 읽기
             * 
             * 파일의 현재 위치에서부터 요청한 바이트 수만큼 읽음
             * 파일의 끝에 도달하면 실제로는 더 적은 바이트를 읽을 수 있음
             */
            struct file *file = get_file(fd);
            if (file == NULL)
            {
                /*
                 * 유효하지 않은 파일 디스크립터
                 */
                f->R.rax = -1;
                break;
            }

            /*
             * 락 보호 하에 파일 읽기 수행
             * 
             * file_read: 파일에서 실제 데이터를 읽는 함수
             * 반환값은 실제로 읽은 바이트 수임 (0이면 EOF)
             */
            lock_acquire(&filesys_lock);
            int bytes_read = file_read(file, buffer, size);
            lock_release(&filesys_lock);

            f->R.rax = bytes_read;
        }
        break;
    }
    
    case SYS_FILESIZE:
    {
        /*
         * 파일의 크기를 바이트 단위로 반환함
         * 
         * 인자: fd (크기를 알고 싶은 파일의 디스크립터)
         * 반환값: 파일 크기 (바이트), 실패시 -1
         */
        int fd = (int)f->R.rdi;

        struct file *file = get_file(fd);
        if (file == NULL)
        {
            f->R.rax = -1;
            break;
        }

        /*
         * 파일 크기 조회
         * 
         * file_length: 파일의 전체 크기를 반환하는 함수
         * 이는 파일의 현재 읽기/쓰기 위치와는 무관함
         */
        lock_acquire(&filesys_lock);
        off_t size = file_length(file);
        lock_release(&filesys_lock);

        f->R.rax = size;
        break;
    }

    /* ===== 프로세스 관리 시스템 콜들 - FORK 관련 핵심 구현 ===== */
    
    case SYS_FORK:
    {
        /*
         * 현재 프로세스를 복제하여 자식 프로세스를 생성함
         * 
         * 인자: thread_name (자식 프로세스의 스레드 이름)
         * 반환값: 부모에게는 자식의 PID, 자식에게는 0, 실패시 -1
         * 
         * Fork의 특별한 점:
         * - 같은 시스템 콜이 두 번 리턴함 (부모에게 한번, 자식에게 한번)
         * - 부모와 자식은 동일한 메모리 내용을 가지지만 독립적인 주소 공간
         * - 자식은 fork() 호출 직후부터 실행을 시작함
         * 
         * 이 시스템 콜이 process.c의 process_fork()와 연결됨
         */
        const char *thread_name = (const char *)f->R.rdi;
        
        /*
         * 스레드 이름의 유효성 검증
         * 
         * 사용자가 NULL이나 커널 주소를 전달할 수 있으므로 검사 필요
         */
        check_address((void *)thread_name);
        
        /*
         * 실제 fork 작업을 process_fork에게 위임
         * 
         * process_fork(name, f):
         * - name: 자식 프로세스의 이름
         * - f: 현재 interrupt frame (CPU 상태를 자식에게 복사하기 위해 필요)
         * 
         * 이 함수가 핵심인데, 다음과 같은 작업들을 수행함:
         * 1. 현재 CPU 상태를 저장
         * 2. 새로운 스레드 생성 (__do_fork 함수 실행)
         * 3. 자식의 초기화 완료까지 대기
         * 4. 부모는 자식 PID 반환, 자식은 0 반환
         */
        f->R.rax = process_fork(thread_name, f);
        break;
    }

    case SYS_EXEC:
    {
        /*
         * 현재 프로세스를 새로운 프로그램으로 교체함
         * 
         * 인자: cmd_line (실행할 프로그램과 인자들이 포함된 명령줄)
         * 반환값: 성공시 리턴하지 않음, 실패시 -1
         * 
         * Fork와의 차이점:
         * - Fork는 복제를 만듦 (기존 프로세스 + 새 프로세스)
         * - Exec은 교체를 함 (기존 프로세스가 새 프로그램으로 변신)
         * 
         * 일반적인 사용 패턴:
         * 1. fork()로 자식 생성
         * 2. 자식에서 exec()으로 새 프로그램 실행
         * 3. 부모는 wait()으로 자식 완료 대기
         */
        const char *cmd_line = (const char *)f->R.rdi;
        check_address((void *)cmd_line);

        /*
         * 명령줄을 커널 메모리에 복사
         * 
         * exec이 실행되면 현재 프로세스의 메모리가 모두 교체되므로
         * 사용자가 전달한 명령줄 문자열도 사라짐
         * 따라서 미리 커널 메모리에 복사해두어야 함
         */
        char *cmd_copy = palloc_get_page(0);       // 커널 메모리 할당
        if (cmd_copy == NULL)
        {
            /*
             * 메모리 할당 실패
             * 
             * 시스템에 메모리가 부족해서 명령줄을 복사할 수 없음
             */
            f->R.rax = -1;
            break;
        }
        strlcpy(cmd_copy, cmd_line, PGSIZE);       // 안전한 문자열 복사

        /*
         * 실제 exec 작업을 process_exec에게 위임
         * 
         * process_exec(cmd_copy):
         * - 현재 메모리 공간을 정리
         * - 새 프로그램을 메모리에 로드
         * - 인자들을 스택에 배치
         * - 새 프로그램의 시작점으로 점프
         * 
         * 성공하면 이 함수는 절대 리턴하지 않음 (새 프로그램으로 교체됨)
         * 실패하면 -1을 반환하고 기존 프로세스가 계속 실행됨
         */
        f->R.rax = process_exec(cmd_copy);
        break;
    }

    case SYS_WAIT:
    {
        /*
         * 자식 프로세스가 종료될 때까지 기다림
         * 
         * 인자: pid (기다릴 자식 프로세스의 ID)
         * 반환값: 자식의 종료 상태 코드, 실패시 -1
         * 
         * 제약 조건:
         * - 직계 자식만 기다릴 수 있음 (손자나 남의 자식 불가)
         * - 같은 자식에 대해 두 번 wait 불가
         * - 자식이 이미 종료되었어도 종료 상태를 반환해야 함 (좀비 프로세스)
         * 
         * 부모-자식 동기화의 핵심 메커니즘
         */
        tid_t pid = (tid_t)f->R.rdi;
        
        /*
         * 실제 대기 작업을 process_wait에게 위임
         * 
         * process_wait(pid):
         * - 자식 리스트에서 해당 PID 찾기
         * - 자식이 아직 살아있으면 대기 (세마포어 사용)
         * - 자식이 종료되면 종료 상태 수집
         * - 좀비 상태 정리 (자식의 메모리 자원 해제)
         * 
         * 이 함수는 자식이 종료될 때까지 블록될 수 있음
         */
        f->R.rax = process_wait(pid);
        break;
    }
    
    /* ===== 파일 위치 관련 시스템 콜들 ===== */
    
    case SYS_SEEK:
    {
        /*
         * 파일의 읽기/쓰기 위치를 변경함
         * 
         * 인자들:
         * - fd: 파일 디스크립터
         * - position: 새로운 위치 (파일 시작부터의 바이트 오프셋)
         * 
         * 반환값: 없음 (void)
         * 
         * 이후 read/write는 이 새로운 위치부터 시작됨
         */
        int fd = (int)f->R.rdi;
        unsigned position = (unsigned)f->R.rsi;

        struct file *file = get_file(fd);
        if (file != NULL)
        {
            /*
             * 파일 위치 변경
             * 
             * file_seek: 파일의 내부 포인터를 지정된 위치로 이동
             * 파일 크기를 넘어선 위치로 이동해도 에러가 발생하지 않음
             * (실제 읽기/쓰기할 때 처리됨)
             */
            lock_acquire(&filesys_lock);
            file_seek(file, position);
            lock_release(&filesys_lock);
        }
        /*
         * 유효하지 않은 fd에 대해서는 조용히 무시
         * (실제 유닉스 동작과 동일)
         */
        break;
    }
    
    case SYS_TELL:
    {
        /*
         * 파일의 현재 읽기/쓰기 위치를 반환함
         * 
         * 인자: fd (파일 디스크립터)
         * 반환값: 현재 위치 (파일 시작부터의 바이트 오프셋), 실패시 -1
         * 
         * seek의 반대 개념 - 현재 위치를 조회함
         */
        int fd = (int)f->R.rdi;
        struct file *file = get_file(fd);
        if (file == NULL)
        {
            f->R.rax = -1;
            break;
        }

        /*
         * 현재 파일 위치 조회
         * 
         * file_tell: 파일의 내부 포인터가 가리키는 현재 위치 반환
         */
        lock_acquire(&filesys_lock);
        f->R.rax = file_tell(file);
        lock_release(&filesys_lock);
        break;
    }
    
    case SYS_REMOVE:
    {
        /*
         * 파일을 삭제함
         * 
         * 인자: file (삭제할 파일의 경로)
         * 반환값: 성공시 true, 실패시 false
         * 
         * 주의사항:
         * - 열린 파일을 삭제하려 하면 결과는 시스템에 따라 다름
         * - 디렉토리는 비어있을 때만 삭제 가능
         */
        const char *file = (const char *)f->R.rdi;
        check_address((void *)file);

        /*
         * 실제 파일 삭제
         * 
         * filesys_remove: 파일시스템에서 파일을 제거하는 함수
         * 파일이 존재하지 않으면 false 반환
         */
        lock_acquire(&filesys_lock);
        f->R.rax = filesys_remove(file);
        lock_release(&filesys_lock);
        break;
    }
    
    default:
        /*
         * 알 수 없는 시스템 콜 번호
         * 
         * 사용자가 존재하지 않는 시스템 콜을 호출하거나,
         * 메모리 오염으로 인해 잘못된 번호가 전달된 경우
         * 
         * 이런 경우 프로세스를 종료시키는 것이 안전함
         */
        printf("Unknown system call: %d\n", (int)nr);
        printf("%s: exit(-1)\n", thread_current()->name);
        thread_current()->exit_status = -1;
        thread_exit();                                 // 프로세스 강제 종료
        break;
    }
}

/* ===== 보안 및 유효성 검사 함수들 ===== */

/*
 * 사용자가 전달한 주소의 유효성을 검사함
 * 
 * addr: 검사할 주소
 * 
 * 검사 항목:
 * 1. NULL 포인터 검사
 * 2. 사용자 주소 공간 범위 내에 있는지 검사
 * 
 * 유효하지 않으면 프로세스를 강제 종료시킴
 * 이는 커널 보안을 위해 매우 중요함
 */
static void check_address(void *addr)
{
    /*
     * 주소 유효성 검사
     * 
     * addr == NULL: NULL 포인터는 접근 불가
     * !is_user_vaddr(addr): 커널 주소 공간에는 사용자가 접근 불가
     * 
     * 이 검사를 통과하지 못하면 악의적이거나 버그가 있는 프로그램으로 판단
     */
    if (addr == NULL || !is_user_vaddr(addr))
    {
        /*
         * 유효하지 않은 주소 접근 시도
         * 
         * 디버깅용 메시지 출력 후 프로세스 종료
         * exit(-1)로 비정상 종료임을 표시
         */
        printf("%s: exit(-1)\n", thread_current()->name);
        thread_current()->exit_status = -1;
        thread_exit();
    }
}

/*
 * 파일 디스크립터를 위한 새로운 슬롯을 할당함
 * 
 * file: 할당할 파일 구조체
 * 반환값: 할당된 fd 번호, 실패시 -1
 * 
 * 파일 디스크립터 테이블 관리의 핵심 함수
 * 각 프로세스는 독립적인 fd 테이블을 가지며,
 * 0, 1, 2번은 표준 입출력으로 예약됨
 */
static int allocate_fd(struct file *file)
{
    struct thread *cur = thread_current();

    /*
     * 1단계: 기존 슬롯 중에서 빈 자리 찾기
     * 
     * fd 3번부터 시작 (0=stdin, 1=stdout, 2=stderr는 예약)
     * 이미 할당된 범위 내에서 NULL인 슬롯을 찾음
     * 
     * 이는 파일을 닫았다가 다시 열 때 fd를 재사용하기 위함
     */
    for (int fd = 3; fd < cur->fd_idx && fd < FDCOUNT_LIMIT; fd++)
    {
        if (cur->fdt[fd] == NULL)
        {
            /*
             * 빈 슬롯을 찾음
             * 
             * 파일을 슬롯에 할당하고 fd_idx를 조정
             */
            cur->fdt[fd] = file;
            if (fd >= cur->fd_idx)
                cur->fd_idx = fd + 1;              // 최대 인덱스 업데이트
            return fd;
        }
    }

    /*
     * 2단계: 새로운 슬롯 할당
     * 
     * 기존 슬롯에 빈 자리가 없으면 테이블을 확장
     * 단, FDCOUNT_LIMIT을 넘을 수는 없음
     */
    if (cur->fd_idx < FDCOUNT_LIMIT)
    {
        cur->fdt[cur->fd_idx] = file;
        return cur->fd_idx++;                      // 후위 증가로 현재값 반환 후 증가
    }

    /*
     * 3단계: 테이블이 가득 참
     * 
     * 더 이상 파일을 열 수 없는 상황
     * 프로세스당 파일 개수 제한에 도달
     */
    return -1;
}

/*
 * 파일 디스크립터로부터 파일 구조체를 찾음
 * 
 * fd: 찾을 파일 디스크립터 번호
 * 반환값: 해당하는 파일 구조체, 없으면 NULL
 * 
 * 모든 파일 관련 시스템 콜에서 사용하는 핵심 함수
 */
static struct file *get_file(int fd)
{
    struct thread *cur = thread_current();
    
    /*
     * fd 유효성 검사
     * 
     * fd < 0: 음수 fd는 존재하지 않음
     * fd >= FDCOUNT_LIMIT: 테이블 크기 초과
     * fd >= cur->fd_idx: 아직 할당되지 않은 영역
     */
    if (fd < 0 || fd >= FDCOUNT_LIMIT || fd >= cur->fd_idx)
    {
        return NULL;
    }

    /*
     * 파일 구조체 반환
     * 
     * NULL일 수도 있음 (닫힌 파일이거나 0,1,2번 표준 입출력)
     */
    return cur->fdt[fd];
}

/*
 * 파일 디스크립터 슬롯을 해제함
 * 
 * fd: 해제할 파일 디스크립터 번호
 * 
 * 파일을 닫을 때 호출되어 해당 슬롯을 재사용 가능하게 만듦
 */
static void release_fd(int fd)
{
    struct thread *cur = thread_current();

    /*
     * fd 유효성 확인 후 슬롯 해제
     * 
     * fd >= 3: 표준 입출력(0,1,2)은 해제하지 않음
     * 나머지 조건들: 유효한 범위 내의 fd인지 확인
     */
    if (fd >= 3 && fd < FDCOUNT_LIMIT && fd < cur->fd_idx)
    {
        cur->fdt[fd] = NULL;                       // 슬롯을 비워서 재사용 가능하게 함
    }
}

/*
 * 버퍼 주소와 크기의 유효성을 검사함
 * 
 * buffer: 검사할 버퍼의 시작 주소
 * size: 버퍼의 크기
 * 
 * 단순히 시작 주소만 검사하는 것이 아니라,
 * 버퍼 전체 영역이 유효한지 확인해야 함
 * 
 * 유효하지 않으면 프로세스 강제 종료
 */
static void check_buffer(void *buffer, unsigned size)
{
    /*
     * 1단계: 시작 주소 검사
     * 
     * buffer == NULL: NULL 포인터 검사
     * !is_user_vaddr(buffer): 사용자 주소 공간 내에 있는지 검사
     */
    if (buffer == NULL || !is_user_vaddr(buffer))
    {
        printf("%s: exit(-1)\n", thread_current()->name);
        thread_current()->exit_status = -1;
        thread_exit();
    }

    /*
     * 2단계: 버퍼 끝 주소 검사
     * 
     * 버퍼가 시작은 사용자 공간이지만 끝은 커널 공간일 수 있음
     * 이런 경우를 방지하기 위해 버퍼의 마지막 바이트도 검사
     * 
     * size - 1: 마지막 바이트의 오프셋 (0부터 시작하므로)
     */
    char *end = (char *)buffer + size - 1;
    if (!is_user_vaddr(end))
    {
        /*
         * 버퍼가 사용자 주소 공간을 벗어남
         * 
         * 악의적인 프로그램이 커널 메모리에 접근하려는 시도일 가능성
         */
        printf("%s: exit(-1)\n", thread_current()->name);
        thread_current()->exit_status = -1;
        thread_exit();
    }
}