/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "threads/mmu.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "lib/kernel/hash.h"
#include "threads/mmu.h"

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

        /* TODO: Insert the page into the spt. */
        // uninit_new()
    }
err:
    return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *spt_find_page(struct supplemental_page_table *spt UNUSED, void *va UNUSED)
{
    struct page page;
    /* TODO: Fill this function. */
    struct page key = {
        .va = pg_round_down(va),
    };
    struct hash_elem *to_find = hash_find(&spt->pages, &key.elem);

    return to_find == NULL ? NULL : hash_entry(to_find, struct page, elem);
}

/* Insert PAGE into spt with validation. */
bool spt_insert_page(struct supplemental_page_table *spt UNUSED, struct page *page UNUSED)
{
    int succ = false;
    /* TODO: Fill this function. */
    // 동일한 elem이 있는지 검색 -> 찾으면 삽입 후 NULL 반환, 이미 있다면 해당 elem반환
    if (hash_insert(spt->pages, &page->hash_elem) == NULL)
        succ = true;
    return succ;
}

void spt_remove_page(struct supplemental_page_table *spt, struct page *page)
{
    // 동일한 elem이 있는지 검색 -> 요소가 발견되면 제거 후 반환, 그렇지 않으면 NULL 반환
    hash_delete(spt, &page->hash_elem);
    vm_dealloc_page(page);
    return true;
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
    struct frame *frame = NULL;
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
bool vm_try_handle_fault(struct intr_frame *f, void *addr, bool user, bool write, bool not_present)
{
    struct supplemental_page_table *spt = &thread_current()->spt;
    // 주어진 addr로 보조 페이지 테이블에서 폴트가 발생한 페이지를 찾기
    struct page *page = spt_find_page(spt, addr);

    /* TODO: Validate the fault */
    /* TODO: Your code goes here */
    if (!not_present || is_kernel_vaddr(addr))
    {
        return false;
    }

    if (page == NULL)
    {
        if (addr >= f->rsp - 8 && ((USER_STACK - (1 << 20)) < addr) && (addr < USER_STACK))
        {
            vm_stack_growth(addr);
            return true;
        }
        return false;
    }

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
bool vm_claim_page(void *va UNUSED)
{
    struct page *page = NULL; // va를 이용해 페이지를 찾기
    struct thread *t = thread_current();
    // t->spt.
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
    // pml4_set_page()
    return swap_in(page, frame->kva);
}

/* Initialize new supplemental page table */
void supplemental_page_table_init(struct supplemental_page_table *spt UNUSED)
{
    hash_init(spt->pages, spt_hash_func, spt_less_func, NULL);
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
    struct page *p = hash_entry(e, struct page, hash_elem);
    return hash_bytes(p->va, sizeof(p->va));
}

bool spt_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
    struct page *pa = hash_entry(a, struct page, hash_elem);
    struct page *pb = hash_entry(b, struct page, hash_elem);
    return pa->va < pb->va;
}