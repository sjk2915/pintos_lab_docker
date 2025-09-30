/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "threads/mmu.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include <string.h>

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
        new_page->is_stack = type & VM_STACK;
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
    PANIC("TODO");

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

    pml4_clear_page(thread_current()->pml4, victim->page->va);

    victim->page->frame = NULL;
    victim->page = NULL;

    return victim;
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
    if (frame->kva == NULL)
    {
        struct frame *victim = vm_evict_frame();
        ASSERT(victim != NULL);

        frame->kva = victim->kva;
        free(victim);
    }
    frame->page = NULL;

    return frame;
}

/* Growing the stack. */
static bool vm_stack_growth(void *addr)
{
    return vm_alloc_page(VM_ANON | VM_STACK, pg_round_down(addr), true) && vm_claim_page(addr);
}

/* Handle the fault on write_protected page */
static bool vm_handle_wp(struct page *page UNUSED)
{
}

/* Return true on success */
bool vm_try_handle_fault(struct intr_frame *f, void *addr, bool user, bool write, bool not_present)
{
    /* TODO: Validate the fault */
    /* TODO: Your code goes here */
    if (!not_present || addr == NULL || is_kernel_vaddr(addr))
        return false;

    struct thread *cur = thread_current();
    struct supplemental_page_table *spt = &cur->spt;
    // 주어진 addr로 보조 페이지 테이블에서 폴트가 발생한 페이지를 찾기
    struct page *page = spt_find_page(spt, addr);
    if (page == NULL)
    {
        void *rsp = user ? f->rsp : cur->user_rsp;
        if (addr >= rsp - 8 && (USER_STACK - (1 << 20)) <= addr && addr < USER_STACK)
            return vm_stack_growth(addr);

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
bool supplemental_page_table_copy(struct supplemental_page_table *dst,
                                  struct supplemental_page_table *src)
{
    struct hash_iterator i;
    hash_first(&i, src);
    while (hash_next(&i))
    {
        struct page *src_page = hash_entry(hash_cur(&i), struct page, elem);
        switch (src_page->operations->type)
        {
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
                free(dst_aux);
                return false;
            }
            break;

        case VM_ANON:
            if (!(vm_alloc_page(VM_ANON, src_page->va, src_page->writable) &&
                  vm_claim_page(src_page->va)))
                return false;
            struct page *dst_page = spt_find_page(dst, src_page->va);
            memcpy(dst_page->frame->kva, src_page->frame->kva, PGSIZE);
            break;

        case VM_FILE:
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