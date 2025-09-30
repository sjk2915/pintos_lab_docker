/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "threads/mmu.h"
#include "vm/vm.h"
#include "vm/inspect.h"

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void vm_init(void)
{
    vm_anon_init();
    vm_file_init();
#ifdef EFILESYS /* For project 4 */
    pagecache_init();
#endif
    register_inspect_intr();
    /* DO NOT MODIFY UPPER LINES. */
    /* TODO: Your code goes here. */
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type page_get_type(struct page *page)
{
    int ty = VM_TYPE(page->operations->type);
    switch (ty)
    {
    case VM_UNINIT:
        return VM_TYPE(page->uninit.type);
    default:
        return ty;
    }
}

/* Helpers */
static struct frame *vm_get_victim(void);
static bool vm_do_claim_page(struct page *page);
static struct frame *vm_evict_frame(void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool vm_alloc_page_with_initializer(enum vm_type type, void *upage, bool writable,
                                    vm_initializer *init, void *aux)
{
    ASSERT(VM_TYPE(type) != VM_UNINIT)

    struct supplemental_page_table *spt = &thread_current()->spt;

    /* Check wheter the upage is already occupied or not. */
    if (spt_find_page(spt, upage) == NULL)
    {
        /* TODO: Create the page, fetch the initialier according to the VM type,
         * TODO: and then create "uninit" page struct by calling uninit_new. You
         * TODO: should modify the field after calling the uninit_new. */
        struct page *new_page = (struct page *)malloc(sizeof(struct page));
        if (new_page == NULL)
            goto err;

        bool (*initializer)(struct page *, enum vm_type, void *);
        switch (VM_TYPE(type))
        {
        case VM_ANON:
            initializer = anon_initializer;
            break;
        case VM_FILE:
            initializer = file_backed_initializer;
            break;
        default:
            free(new_page);
            goto err;
        }
        uninit_new(new_page, upage, init, type, aux, initializer);
        new_page->writable = writable;
        /* TODO: Insert the page into the spt. */
        if (spt_insert_page(spt, new_page))
            return true;
        else
        {
            free(new_page);
            goto err;
        }
    }
err:
    return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *spt_find_page(struct supplemental_page_table *spt, void *va)
{
    /* TODO: Fill this function. */
    struct page key = {
        .va = pg_round_down(va),
    };
    struct hash_elem *to_find = hash_find(&spt->pages, &key.elem);
    return to_find == NULL ? NULL : hash_entry(to_find, struct page, elem);
}

/* Insert PAGE into spt with validation. */
bool spt_insert_page(struct supplemental_page_table *spt, struct page *page)
{
    /* TODO: Fill this function. */
    if (hash_insert(&spt->pages, &page->elem) == NULL)
        return true;
    return false;
}

void spt_remove_page(struct supplemental_page_table *spt, struct page *page)
{
    hash_delete(&spt->pages, &page->elem);
    vm_dealloc_page(page);
}

/* Get the struct frame, that will be evicted. */
static struct frame *vm_get_victim(void)
{
    struct frame *victim = NULL;
    /* TODO: The policy for eviction is up to you. */

    return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *vm_evict_frame(void)
{
    struct frame *victim UNUSED = vm_get_victim();
    /* TODO: swap out the victim and return the evicted frame. */

    return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *vm_get_frame(void)
{
    /* TODO: Fill this function. */
    struct frame *frame = (struct frame *)malloc(sizeof(struct frame));
    frame->kva = palloc_get_page(PAL_USER | PAL_ZERO);
    // 여기에 할당 실패시 페이지 치우고 다시 할당받는 로직 필요
    // 현재는 없음
    frame->page = NULL;

    ASSERT(frame != NULL);
    ASSERT(frame->page == NULL);
    return frame;
}

/* Growing the stack. */
// 스택 확장이 필요할 때 호출되어, 폴트가 발생한 주소(addr)에 새로운 스택 페이지를 할당
static void vm_stack_growth(void *addr)
{
    vm_alloc_page(VM_ANON, pg_round_down(addr), true);
    vm_claim_page(addr);
}

/* Handle the fault on write_protected page */
static bool vm_handle_wp(struct page *page UNUSED)
{
}

/* Return true on success */
// page_fault 핸들러의 일부로, 발생한 페이지 폴트가 유효한지를 검사하고 처리하는 역할
bool vm_try_handle_fault(struct intr_frame *f, void *addr, bool user, bool write, bool not_present)
{
    struct supplemental_page_table *spt = &thread_current()->spt;
    // 주어진 addr로 보조 페이지 테이블에서 폴트가 발생한 페이지를 찾기
    struct page *page = spt_find_page(spt, addr);

    /* TODO: Validate the fault */
    /* TODO: Your code goes here */
    /* 유효성 검증 1.
     * !not_present : not_present가 false라는 것은 페이지가 메모리에 있지만 권한이 없는 접근(e.g.
     * 읽기 전용 페이지에 쓰기 시도)을 했다는 의미
     * is_kernel_vaddr(addr): 폴트 주소가 커널 영역인 경우, 이는 커널 버그 */
    if (!not_present || is_kernel_vaddr(addr))
    {
        return false;
    }

    // 페이지가 SPT에 없는 경우: page가 NULL이라는 것은 SPT에 해당 주소에 대한 정보가 없다는 의미
    // => 이 경우, 유일하게 허용되는 상황은 스택 확장
    if (page == NULL)
    {
        /* 스택 확장 조건 검사: 폴트 주소 addr가 현재 스택 포인터(f->rsp)보다 아래에 있고,
         * USER_STACK으로부터 일정 범위(KAIST Pintos에서는 보통 1MB) 내에 있는지 확인.
         * 이 조건을 만족하면 유효한 스택 확장 시도로 간주 */
        if ((addr >= (f->rsp - 8)) && ((USER_STACK - (1 << 20)) < addr) && (addr < USER_STACK))
        {
            vm_stack_growth(addr);
            return true;
        }
        return false;
    }

    // 페이지가 SPT에 있는 경우: page를 찾았다면, 이는 load_segment 등에서 지연 로딩을 위해 미리
    // 설정해 둔 페이지 => vm_do_claim_page()를 호출하여 물리 프레임을 할당
    return vm_do_claim_page(page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void vm_dealloc_page(struct page *page)
{
    destroy(page);
    free(page);
}

/* Claim the page that allocate on VA. */
bool vm_claim_page(void *va)
{
    /* TODO: Fill this function */
    struct page *page = spt_find_page(&thread_current()->spt, va);
    if (page == NULL)
        return false;
    return vm_do_claim_page(page);
}

/* Claim the PAGE and set up the mmu. */
static bool vm_do_claim_page(struct page *page)
{
    struct frame *frame = vm_get_frame();

    /* Set links */
    frame->page = page;
    page->frame = frame;

    /* TODO: Insert page table entry to map page's VA to frame's PA. */
    pml4_set_page(thread_current()->pml4, page->va, frame->kva, page->writable);

    return swap_in(page, frame->kva);
}

/* Initialize new supplemental page table */
void supplemental_page_table_init(struct supplemental_page_table *spt)
{
    hash_init(&spt->pages, spt_hash_func, spt_less_func, NULL);
}

/* Copy supplemental page table from src to dst */
bool supplemental_page_table_copy(struct supplemental_page_table *dst UNUSED,
                                  struct supplemental_page_table *src UNUSED)
{
}

/* Free the resource hold by the supplemental page table */
void supplemental_page_table_kill(struct supplemental_page_table *spt UNUSED)
{
    /* TODO: Destroy all the supplemental_page_table hold by thread and
     * TODO: writeback all the modified contents to the storage. */
}

uint64_t spt_hash_func(const struct hash_elem *e, void *aux UNUSED)
{
    struct page *p = hash_entry(e, struct page, elem);
    return hash_bytes(&p->va, sizeof p->va);
}

bool spt_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
    struct page *pa = hash_entry(a, struct page, elem);
    struct page *pb = hash_entry(b, struct page, elem);
    return pa->va < pb->va;
}