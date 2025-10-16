/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "threads/mmu.h"
#include "devices/disk.h"
#include "lib/kernel/bitmap.h"

static struct disk *swap_disk;

static bool file_backed_swap_in(struct page *page, void *kva);
static bool file_backed_swap_out(struct page *page);
static void file_backed_destroy(struct page *page);

static bool lazy_file_segment(struct page *page, void *aux);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
    .swap_in = file_backed_swap_in,
    .swap_out = file_backed_swap_out,
    .destroy = file_backed_destroy,
    .type = VM_FILE,
};

/* The initializer of file vm */
void vm_file_init(void)
{
    swap_disk = disk_get(1, 1);
}

/* Initialize the file backed page */
bool file_backed_initializer(struct page *page, enum vm_type type, void *kva)
{
    /* Set up the handler */
    page->operations = &file_ops;

    struct file_page *file_page = &page->file;
    file_page->file_info = NULL;
    file_page->type = type;
    file_page->sector_idx = -1;
    return true;
}

/* Swap in the page by read contents from the file. */
static bool file_backed_swap_in(struct page *page, void *kva)
{
    struct file_page *file_page = &page->file;
    struct file_info *file_info = file_page->file_info;

    size_t page_read_byte = file_info->read_byte; // 읽을 바이트 수
    size_t page_zero_byte = file_info->zero_byte; // 제로 바이트 수

    /* TODO: VA is available when calling this function. */

    if (page_read_byte > 0)
        file_read_at(file_info->file, kva, page_read_byte, file_info->ofs);

    // 남은 영역 0으로 채우기
    if (page_zero_byte > 0)
        memset(kva + page_read_byte, 0, page_zero_byte);

    return true;
}

/* Swap out the page by writeback contents to the file. */
static bool file_backed_swap_out(struct page *page)
{
    struct file_page *file_page = &page->file;
    struct file_info *file_info = file_page->file_info;

    if (file_info)
    {
        // dirty(수정된) 페이지는 파일에 저장해야함
        if (pml4_is_dirty(thread_current()->pml4, page->va))
            file_write_at(file_info->file, page->frame->kva, file_info->read_byte, file_info->ofs);
    }

    return true;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void file_backed_destroy(struct page *page)
{
    struct file_page *file_page = &page->file;
    struct file_info *file_info = file_page->file_info;

    if (file_info)
    {
        // dirty(수정된) 페이지는 파일에 저장해야함
        if (pml4_is_dirty(thread_current()->pml4, page->va))
            file_write_at(file_info->file, page->frame->kva, file_info->read_byte, file_info->ofs);

        // 더 이상 file_info 쓰지 않으면 free
        file_close(file_info->file);
        free(file_info);
    }

    // 프레임 해제
    if (page->frame)
        frame_free(page->frame, page->va);
}

/* Do the mmap */
void *do_mmap(void *addr, size_t length, int writable, struct file *file, off_t offset)
{
    void *start_addr = addr;
    int page_map_count = 0;

    while (length > 0)
    {
        /* Do calculate how to fill this page.
         * We will read PAGE_READ_BYTES bytes from FILE
         * and zero the final PAGE_ZERO_BYTES bytes. */
        size_t page_read_bytes = length < PGSIZE ? length : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        /* TODO: Set up aux to pass information to the lazy_load_segment. */
        struct file_info *aux = (struct file_info *)malloc(sizeof(struct file_info));
        if (aux == NULL)
            return;
        *aux = (struct file_info){
            .file = file_duplicate2(file),
            .ofs = offset,
            .read_byte = page_read_bytes,
            .zero_byte = page_zero_bytes,
            .map_count = page_map_count,
        };

        if (!vm_alloc_page_with_initializer(VM_FILE, addr, writable, lazy_file_segment, aux))
            return NULL;

        /* Advance. */
        length -= page_read_bytes;
        offset += page_read_bytes;
        page_map_count++;
        addr += PGSIZE;
    }

    return start_addr;
}

/* Do the munmap */
void do_munmap(void *addr)
{
    struct thread *cur = thread_current();
    struct supplemental_page_table *spt = &cur->spt;
    struct page *target_page = spt_find_page(spt, addr);
    if (target_page == NULL)
        return;
    struct file_info *file_info = target_page->file.file_info;
    struct file *target_file = file_info->file;
    int target_map_count = file_info->map_count;

    addr += PGSIZE;
    struct page *page = spt_find_page(spt, addr);
    target_map_count++;
    while (page != NULL)
    {
        file_info = page->operations->type == VM_UNINIT ? page->uninit.aux : page->file.file_info;
        if (!(file_info->file == target_file && file_info->map_count == target_map_count))
            break;
        spt_remove_page(spt, page);

        addr += PGSIZE;
        page = spt_find_page(spt, addr);
        target_map_count++;
    }

    // 첫페이지 제거
    spt_remove_page(spt, target_page);
}

static bool lazy_file_segment(struct page *page, void *aux)
{
    /* TODO: Load the segment from the file */
    struct file_info *p_aux = aux;

    /* TODO: This called when the first page fault occurs on address VA. */

    void *p_kva = page->frame->kva; // 물리 프레임의 커널 주소

    size_t page_read_byte = p_aux->read_byte; // 읽을 바이트 수
    size_t page_zero_byte = p_aux->zero_byte; // 제로 바이트 수

    /* TODO: VA is available when calling this function. */

    if (page_read_byte > 0)
        file_read_at(p_aux->file, p_kva, page_read_byte, p_aux->ofs);

    // 남은 영역 0으로 채우기
    if (page_zero_byte > 0)
        memset(p_kva + page_read_byte, 0, page_zero_byte);

    // file_info 받아오기
    page->file.file_info = p_aux;

    return true;
}
