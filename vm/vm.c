/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"

extern struct list frame_table;
extern struct lock frame_lock;
extern struct lock dead_lock;


/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
	list_init(&frame_table);
	struct list_elem *start;
	lock_init(&frame_lock);
	lock_init(&dead_lock);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		// 1: Create a page
		struct page* Page = (struct page *)malloc(sizeof(struct page));
		if (Page == NULL) goto err;

		// 2: allocate the page with proper initializer function
		// get page boundary address
		void *upage_boundary = pg_round_down(upage);
		switch(VM_TYPE(type)){
			case VM_ANON:
				uninit_new(Page, upage_boundary, init, type, aux, anon_initializer);
				break;
			case VM_FILE:
				uninit_new(Page, upage_boundary, init, type, aux, file_backed_initializer);
				break;
			default:
				NOT_REACHED();
				break;
		}
		Page->isWritable = writable;
		/* TODO: Insert the page into the spt. */
		spt_insert_page(spt, Page);

		//Done
		return true;
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt, void *va) {
	struct page *page = NULL;
	/* TODO: Fill this function. */
	struct page temp; // for hash search
	temp.va = pg_round_down(va);
	
	struct hash_elem *elem = hash_find(&(spt->hash_table), &(temp.page_hash_elem));
	if(elem==NULL) return NULL; //return NULL on error

	// return the page
	return hash_entry(elem, struct page, page_hash_elem);
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	int succ = false;
	/* TODO: Fill this function. */
	if (hash_insert(&(spt->hash_table), &(page->page_hash_elem)) == NULL) succ = true;
	if(!succ) exit(-1);
	return succ;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	if (hash_delete(&(spt->hash_table), &(page->page_hash_elem)) == NULL) return;

	vm_dealloc_page (page);
	return;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */
	lock_acquire(&frame_lock);
	size_t remaining = list_size(&frame_table);
	struct list_elem *e = list_begin(&frame_table);
	struct frame *f;
	struct list_elem *next;

	
	for (size_t i = 0; i < remaining; i ++) {
		f = list_entry(e, struct frame, frelem);
		if(pml4_is_accessed(thread_current()->pml4, f->page->va)) {
			pml4_set_accessed(thread_current()->pml4, f->page->va, false);
			next = list_next(e);
			list_remove(e);
			list_push_back(&frame_table, e);
			e = next;
			continue;
		}
		if (victim == NULL) {
			victim = f;
			next = list_next(e);
			list_remove(e);
			e = next;
			continue;
		}
		e = list_next(e);
	}

	if (victim == NULL) {
		struct list_elem *e = list_pop_front(&frame_table);
		victim = list_entry(e, struct frame, frelem);
	}
	lock_release(&frame_lock);

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */
	if (!swap_out(victim->page)) return NULL;
	victim->page = NULL;
	memset(victim->kva, 0, PGSIZE);
	return victim ;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	struct frame *frame = NULL;
	/* TODO: Fill this function. */
	//get frame
	void *kva = palloc_get_page(PAL_USER);
	if (kva == NULL) return vm_evict_frame(); // if full evict a frame

	//create frame struct
	frame = (struct frame *)malloc(sizeof(struct frame));
	frame->kva = kva;
	frame->page = NULL;

	ASSERT(frame != NULL);
	ASSERT(frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
	// check allocation and allocate the page
	while(spt_find_page(&thread_current()->spt, addr)==NULL){
		vm_alloc_page(VM_ANON, addr, true);
		vm_claim_page(addr);
		addr += PGSIZE;
	}
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
	void *par_kva = page->frame->kva;
	page->frame->kva = palloc_get_page(PAL_USER);

	memcpy(page->frame->kva, par_kva, PGSIZE);
	struct thread *curr = thread_current();
	pml4_set_page(curr->pml4, page->va, page->frame->kva, page->copiable);
	return true;
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt = &thread_current ()->spt;
	struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */

	// 1:User access kernel space
	if(is_kernel_vaddr(addr) && user) return false;
	
	// 2:Stack growth
	page = spt_find_page(spt, addr);
	if(page == NULL){
		struct thread *current_thread = thread_current();
		void *stack_bottom = pg_round_down(thread_current()->usrsp);
		if ((addr >= pg_round_down(thread_current()->usrsp - PGSIZE)) && (addr < USER_STACK) && write){
			// limit stack to 1MB
			addr = pg_round_down(addr);
			if(((uintptr_t)USER_STACK - (uintptr_t)addr) <= (1 << 20)) vm_stack_growth(addr);
			return true;
		}
		return false;
	}

	// 3:writing to an unwritable page
	if(write && !page->isWritable) return false;

	// 4: writing to a protected page
	if(write && !not_present && page->copiable && page) return vm_handle_wp(page);

	// lazy-load & swapped-out accesses
	return vm_do_claim_page (page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function */
	page = spt_find_page(&thread_current()->spt, va);
	if (page == NULL) return false;

	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();

	/* Set links */
	frame->page = page;
	page->frame = frame;
	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	struct thread *curr = thread_current();
	
	lock_acquire(&frame_lock);
	list_push_back(&frame_table, &(frame->frelem));
	lock_release(&frame_lock);

	//check existing mapping
	if (pml4_set_page(curr->pml4, page->va, frame->kva, page->isWritable) == false) return false;

	return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
static uint64_t page_hash (const struct hash_elem *e, void *aux)
{
  const struct page *pg = hash_entry(e, struct page, page_hash_elem);
  return hash_int(pg->va);
}

static bool page_less (const struct hash_elem *a, const struct hash_elem *b)
{
  const struct page *pg_a = hash_entry(a, struct page, page_hash_elem);
  const struct page *pg_b = hash_entry(b, struct page, page_hash_elem);
  return pg_a->va < pg_b->va;
}

void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	hash_init(&(spt->hash_table), page_hash, page_less, NULL);
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {

		struct hash_iterator i;
		hash_first (&i, &src->hash_table);

		//iterate and copy
		while (hash_next(&i)){
			struct page* Page = hash_entry(hash_cur(&i), struct page, page_hash_elem);
			struct page *copy = NULL;
			
			switch(VM_TYPE(Page->operations->type)) {
				case VM_UNINIT:
					if (VM_TYPE(Page->uninit.type) == VM_ANON) {
						struct seg_aux *data = (struct seg_aux *)malloc(sizeof(struct seg_aux));
						memcpy(data, Page->uninit.aux, sizeof(struct seg_aux));
						data->file = file_duplicate(data->file);
						vm_alloc_page_with_initializer(Page->uninit.type, Page->va, Page->isWritable, Page->uninit.init, (void *)data);
					}
					break;
				case VM_ANON:
					vm_alloc_page(Page->operations->type, Page->va, Page->isWritable);
					copy = spt_find_page(dst, Page->va);

					if (copy==NULL) {
						return false;
					}

					copy->copiable = Page->isWritable;
					struct frame *copy_frame = malloc(sizeof(struct frame));
					copy->frame = copy_frame;
					copy_frame->page = copy;
					copy_frame->kva = Page->frame->kva;

					lock_acquire(&frame_lock);
					list_push_back(&frame_table, &copy_frame->frelem);
					lock_release(&frame_lock);

					if (pml4_set_page(thread_current()->pml4, copy->va, copy_frame->kva, 0) == false) {
						return false;
					}
					swap_in(copy, copy_frame->kva);
					break;
				case VM_FILE:
					break;
				default:
					break;
			}
		}
		return true;
}

/*function to be passed for hash_destroy*/
void
hash_destroy_func(struct hash_elem* hash_elem, void* aux){
	const struct page* Page = hash_entry(hash_elem, struct page, page_hash_elem);
  	vm_dealloc_page(Page);
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	lock_acquire(&frame_lock);
	hash_destroy(&(spt->hash_table), hash_destroy_func);
	lock_release(&frame_lock);
}
