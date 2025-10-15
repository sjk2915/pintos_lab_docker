/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"
#include "lib/kernel/bitmap.h"

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in(struct page *page, void *kva);
static bool anon_swap_out(struct page *page);
static void anon_destroy(struct page *page);

// 디스크 섹터 사용여부를 01010101010101(예시)로 표현
struct bitmap *swap_bitmap;

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
    .swap_in = anon_swap_in,
    .swap_out = anon_swap_out,
    .destroy = anon_destroy,
    .type = VM_ANON,
};

/* Initialize the data for anonymous pages */
void vm_anon_init(void)
{
    /* TODO: Set up the swap_disk. */
    /* 0:0 boot_loader, command line args, os kernel
       0:1 file system
       1:0 scratch
       1:1 swap <- 이거쓰면됨 */
    swap_disk = disk_get(1, 1);
    swap_bitmap = bitmap_create(disk_size(swap_disk));
}

/* Initialize the file mapping */
bool anon_initializer(struct page *page, enum vm_type type, void *kva)
{
    /* Set up the handler */
    page->operations = &anon_ops;

    struct anon_page *anon_page = &page->anon;
    anon_page->sector_idx = -1;
    return true;
}

/* Swap in the page by read contents from the swap disk. */
static bool anon_swap_in(struct page *page, void *kva)
{
    struct anon_page *anon_page = &page->anon;
    if (anon_page->sector_idx == -1)
        return false;

    // 1페이지 읽어올때도 8섹터단위로
    for (int i = 0; i < 8; i++)
        disk_read(swap_disk, anon_page->sector_idx + i, kva + (DISK_SECTOR_SIZE * i));

    bitmap_set_multiple(swap_bitmap, anon_page->sector_idx, 8, false);
    anon_page->sector_idx = -1;
    return true;
}

/* Swap out the page by writing contents to the swap disk. */
static bool anon_swap_out(struct page *page)
{
    struct anon_page *anon_page = &page->anon;
    /* 1페이지를 넣으려면 8섹터 필요함
       1PAGE = 4096B, 1SECTOR = 512B */
    size_t sector = bitmap_scan_and_flip(swap_bitmap, 0, 8, false);
    if (sector == BITMAP_ERROR)
        return false;

    for (int i = 0; i < 8; i++)
        disk_write(swap_disk, sector + i, page->frame->kva + (DISK_SECTOR_SIZE * i));

    anon_page->sector_idx = sector;
    return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void anon_destroy(struct page *page)
{
    struct anon_page *anon_page = &page->anon;
    // 스왑 디스크에 할당된 공간이 있으면 해제
    if (anon_page->sector_idx != -1)
        bitmap_set_multiple(swap_bitmap, anon_page->sector_idx, 8, false);

    // 프레임 해제
    if (page->frame)
        frame_free(page->frame, page->va);
}
