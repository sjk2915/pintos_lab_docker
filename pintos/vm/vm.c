/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "threads/mmu.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include <string.h>

struct list frame_list;
static struct list_elem *clock_ptr;

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
    list_init(&frame_list);
    clock_ptr = NULL;
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

static uint64_t spt_hash_func(const struct hash_elem *e, void *aux UNUSED);
static bool spt_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);
static void spt_destroy_func(struct hash_elem *e, void *aux UNUSED);

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
            return false;

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
            return false;
        }
        uninit_new(new_page, upage, init, type, aux, initializer);
        new_page->writable = writable;
        /* TODO: Insert the page into the spt. */
        if (spt_insert_page(spt, new_page))
            return true;
        else
        {
            free(new_page);
            return false;
        }
    }
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
    if (clock_ptr == NULL)
        clock_ptr = list_begin(&frame_list);

    struct list_elem *cur = clock_ptr;
    while (victim == NULL)
    {
        struct frame *cur_frame = list_entry(cur, struct frame, elem);

        // 참조 비트가 켜져있으면 끄고 (세컨드 찬스 주기)
        if (pml4_is_accessed(cur_frame->owner->pml4, cur_frame->page->va))
            pml4_set_accessed(cur_frame->owner->pml4, cur_frame->page->va, false);
        // 없으면 방출
        else
            victim = cur_frame;

        clock_ptr = list_next(clock_ptr);
        // 끝이면 시작으로 (원형 리스트)
        if (clock_ptr == list_end(&frame_list))
            clock_ptr = list_begin(&frame_list);
    }

    return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *vm_evict_frame(void)
{
    struct frame *victim = vm_get_victim();
    /* TODO: swap out the victim and return the evicted frame. */
    if (!swap_out(victim->page))
        PANIC("NO FRAME, NO SWAP SLOT");

    pml4_clear_page(victim->owner->pml4, victim->page->va);

    victim->page->frame = NULL;
    victim->page = NULL;
    memset(victim->kva, 0, PGSIZE);

    return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *vm_get_frame(void)
{
    /* TODO: Fill this function. */
    void *kva = palloc_get_page(PAL_USER | PAL_ZERO);
    if (kva == NULL)
    {
        struct frame *victim = vm_evict_frame();
        ASSERT(victim != NULL);

        return victim;
    }

    struct frame *frame = (struct frame *)malloc(sizeof(struct frame));
    frame->kva = kva;
    frame->page = NULL;

    list_push_back(&frame_list, &frame->elem);

    return frame;
}

/* Growing the stack. */
static void vm_stack_growth(void *addr)
{
    vm_alloc_page(VM_ANON | VM_STACK, pg_round_down(addr), true);
    vm_claim_page(addr);
}

/* Handle the fault on write_protected page */
static bool vm_handle_wp(struct page *page)
{
    struct frame *origin_frame = page->frame;
    if (origin_frame->ref_cnt > 1)
    {
        struct frame *cpy_frame = vm_get_frame();
        /* Set links */
        cpy_frame->page = page;
        page->frame = cpy_frame;
        cpy_frame->ref_cnt = 1;

        memcpy(cpy_frame->kva, origin_frame->kva, PGSIZE);
        origin_frame->ref_cnt--;

        return pml4_set_page(thread_current()->pml4, page->va, cpy_frame->kva, true);
    }

    else
    {
        origin_frame->page = page;
        return pml4_set_page(thread_current()->pml4, page->va, origin_frame->kva, true);
    }
}

/* Return true on success */
bool vm_try_handle_fault(struct intr_frame *f, void *addr, bool user, bool write, bool not_present)
{
    uintptr_t rsp = user ? f->rsp : thread_current()->user_rsp;
    struct supplemental_page_table *spt = &thread_current()->spt;
    // 주어진 addr로 보조 페이지 테이블에서 폴트가 발생한 페이지를 찾기
    struct page *page = spt_find_page(spt, addr);
    /* TODO: Validate the fault */
    /* TODO: Your code goes here */
    if (addr == NULL || is_kernel_vaddr(addr))
        return false;

    if (not_present)
    {
        if (page == NULL)
        {
            if (addr >= rsp - 8 && ((USER_STACK - (1 << 20)) < addr) && (addr < USER_STACK))
            {
                vm_stack_growth(addr);
                return true;
            }
            return false;
        }
        return vm_do_claim_page(page);
    }

    if (write && page->writable && page->frame != NULL)
        return vm_handle_wp(page);

    return false;
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
    frame->owner = thread_current();
    frame->ref_cnt = 1;

    /* TODO: Insert page table entry to map page's VA to frame's PA. */
    if (!pml4_set_page(thread_current()->pml4, page->va, frame->kva, page->writable))
        return false;

    return swap_in(page, frame->kva);
}

/* Initialize new supplemental page table */
void supplemental_page_table_init(struct supplemental_page_table *spt)
{
    hash_init(&spt->pages, spt_hash_func, spt_less_func, NULL);
}

/* Copy supplemental page table from src to dst */
bool supplemental_page_table_copy(struct supplemental_page_table *dst,
                                  struct supplemental_page_table *src)
{
    struct hash_iterator i;
    hash_first(&i, &src->pages);
    while (hash_next(&i))
    {
        struct page *src_page = hash_entry(hash_cur(&i), struct page, elem);
        struct page *dst_page;
        enum vm_type type = VM_TYPE(src_page->operations->type);
        switch (type)
        {
        // 로드 안된 페이지
        case VM_UNINIT:
            struct segment_info *src_aux = src_page->uninit.aux;
            struct segment_info *dst_aux =
                (struct segment_info *)malloc(sizeof(struct segment_info));
            if (dst_aux == NULL)
                return false;
            *dst_aux = (struct segment_info){
                .file = file_reopen(src_aux->file),
                .ofs = src_aux->ofs,
                .read_byte = src_aux->read_byte,
                .zero_byte = src_aux->zero_byte,
            };

            if (!vm_alloc_page_with_initializer(page_get_type(src_page), src_page->va,
                                                src_page->writable, src_page->uninit.init, dst_aux))
            {
                file_close(dst_aux->file);
                free(dst_aux);
                return false;
            }
            break;

        // 로드 된 페이지
        case VM_ANON:
        case VM_FILE:
            // COW 이전 기존코드
            // if (!(vm_alloc_page(type, src_page->va, src_page->writable) &&
            //       vm_claim_page(src_page->va)))
            //     return false;
            // dst_page = spt_find_page(dst, src_page->va);
            // memcpy(dst_page->frame->kva, src_page->frame->kva, PGSIZE);

            // COW
            if (!vm_alloc_page(type, src_page->va, src_page->writable))
                return false;

            // 자식과 부모의 프레임 공유
            dst_page = spt_find_page(dst, src_page->va);
            dst_page->frame = src_page->frame;
            src_page->frame->ref_cnt++;

            struct thread *cur = thread_current();

            // 부모의 프레임 쓰기 보호
            if (!pml4_set_page(cur->parent->pml4, src_page->va, src_page->frame->kva, false))
                return false;
            // 자식의 프레임 쓰기 보호
            if (!pml4_set_page(cur->pml4, dst_page->va, dst_page->frame->kva, false))
                return false;

            // uninit 페이지 -> 실제 type 페이지로 초기화
            swap_in(dst_page, dst_page->frame->kva);
            break;

        default:
            return false;
        }
    }
    return true;
}

/* Free the resource hold by the supplemental page table */
void supplemental_page_table_kill(struct supplemental_page_table *spt)
{
    /* TODO: Destroy all the supplemental_page_table hold by thread and
     * TODO: writeback all the modified contents to the storage. */
    hash_clear(&spt->pages, spt_destroy_func);
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

void spt_destroy_func(struct hash_elem *e, void *aux UNUSED)
{
    struct page *p = hash_entry(e, struct page, elem);
    vm_dealloc_page(p);
}

void frame_free(struct frame *frame, void *va)
{
    pml4_clear_page(thread_current()->pml4, va);
    frame->ref_cnt--;

    if (frame->ref_cnt < 1)
    {
        list_remove(&frame->elem);
        palloc_free_page(frame->kva);
        free(frame);
    }
}