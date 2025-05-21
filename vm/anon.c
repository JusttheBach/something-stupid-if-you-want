/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "bitmap.h"
#include "vm/vm.h"
#include "devices/disk.h"

extern struct frame_table;
extern struct frame_lock;

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static struct bitmap *swap_map;
static struct lock bitlock;
const size_t SEC_PPAGE = 8;
static struct lock bitmap_lock;
static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
	/* TODO: Set up the swap_disk. */
	swap_disk = disk_get(1, 1);
    swap_map = bitmap_create((size_t)disk_size(swap_disk));
    lock_init(&bitlock);
}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &anon_ops;
	struct anon_page *anon_page = &page->anon;
	anon_page->swap = SIZE_MAX;
	anon_page->thread = thread_current();
	return true;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_page *panon = &page->anon;
	if (panon->swap == SIZE_MAX) return false;

	lock_acquire(&bitlock);
	bool valid = !bitmap_contains(swap_map, panon->swap, 8, false);
	lock_release(&bitlock);

	if(!valid) return false;

	int i = 0;
	while (i < 8) {
		disk_read(swap_disk, panon->swap + i, kva + i * DISK_SECTOR_SIZE);
		i++;
	}

	lock_acquire(&bitlock);
	bitmap_set_multiple(swap_map, panon->swap, 8, false);
	lock_release(&bitlock);

	return true;

}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out (struct page *page) {
	struct anon_page *panon = &page->anon;

	lock_acquire(&bitlock);
	int pg_num = bitmap_scan(swap_map, 0, 1, false);
	lock_release(&bitlock);
	if (pg_num == BITMAP_ERROR) return false;

	panon->swap = pg_num;

	int i = 0;
	while (i < SEC_PPAGE) {
    disk_write(swap_disk,pg_num + i,page->frame->kva + i * DISK_SECTOR_SIZE);
    i++;
	}
	pml4_clear_page(panon->thread->pml4, page->va);
    pml4_set_dirty(panon->thread->pml4, page->va, false);
    page->frame = NULL;
		
	return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
	struct anon_page *panon = &page->anon;
	if (page->frame != NULL) {
		lock_acquire(&frame_lock);
		list_remove(&page->frame->frelem);
		lock_release(&frame_lock);
		free(page->frame);
	}


	if (panon->swap != SIZE_MAX) {
		bitmap_set_multiple(swap_map, panon->swap, 8, false);
	}

}
