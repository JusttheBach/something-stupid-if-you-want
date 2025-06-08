/* file.c: Implementation of memory backed file object (mmaped object). */
#include "vm/vm.h"
#include "userprog/syscall.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"


extern struct lock frame_lock;
extern struct lock filesys_lock;

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &file_ops;

	struct file_page *file_page = &page->file;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page = &page->file;
    if (page==NULL) return false;

    lock_acquire(&filesys_lock);
    off_t vol = file_read_at(file_page->file, kva, (off_t)file_page->read_bytes, file_page->offset);
    lock_release(&filesys_lock);
    
    if (vol != file_page->read_bytes) return false;

    memset(kva + file_page->read_bytes, 0, file_page->zero_bytes);

    return true;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page = &page->file;

    struct thread *curr = thread_current();

    if (pml4_is_dirty(curr->pml4, page->va)) {
        lock_acquire(&filesys_lock);
        file_write_at(file_page->file, page->va, file_page->read_bytes, file_page->offset);
        lock_release(&filesys_lock);
        pml4_set_dirty(curr->pml4, page->va, false);
    }
    pml4_clear_page(curr->pml4, page->va);
    page->frame = NULL;

    return true;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
    list_remove(&(file_page->file_page_elem));
    if (page->frame != NULL) {
        //lock_acquire(&frame_lock);
        list_remove(&(page->frame->frelem));
        //lock_release(&frame_lock);
        free(page->frame);
    }
}

//initialize file_page struct
void init_file_page(struct page *page, struct aux_load_file *aux){
    page->file.page = page;
    page->file.file = aux->file;
    page->file.offset = aux->offset;
    page->file.read_bytes = aux->read_bytes;
    page->file.zero_bytes = aux->zero_bytes;
    page->file.start = aux->start;
    page->file.length = aux->length;

    // struct page *page;
    // struct file *file;
    // off_t offset;
    // size_t read_bytes;
    // size_t zero_bytes;
    // void* start;
    // size_t length;
}

static bool lazy_load_file (struct page *page, void *aux){
    struct aux_load_file* aux_lazy = (struct aux_load_file *)aux;  
    bool succ = true;  

    list_push_back(&(thread_current()->mmlist), &(page->file.file_page_elem)); //20-5 17:36

    lock_acquire(&filesys_lock);
    off_t file_read = file_read_at(aux_lazy->file, page->frame->kva, (off_t)aux_lazy->read_bytes, aux_lazy->offset);
    lock_release(&filesys_lock);

    /*Set page according to read&zero bytes*/
    if (file_read != (off_t)aux_lazy->read_bytes) {
        vm_dealloc_page(page);
        succ = false;
    } else {
        memset(page->frame->kva + aux_lazy->read_bytes, 0, aux_lazy->zero_bytes);
        init_file_page(page, aux_lazy);
    }
    free(aux);
    pml4_set_dirty(thread_current()->pml4, page->va, false);
    return succ;
}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {
	
    // get file
    struct file *mmap_file = file_reopen(file);
    if(mmap_file == NULL) return NULL;

    size_t read_bytes = length;
    size_t zero_bytes = PGSIZE - (length % PGSIZE);
    void *upage = addr;

    //load_segment
    while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/*Set up aux to pass information to the lazy_load_file. */
		struct aux_load_file *aux = malloc(sizeof(struct aux_load_file));
        if(aux==NULL) return NULL;
        aux->file = mmap_file;
        aux->offset = offset;
        aux->read_bytes = page_read_bytes;
        aux->zero_bytes = page_zero_bytes;
        aux->start = addr;
        aux->length = length;

		if (!vm_alloc_page_with_initializer (VM_FILE, upage,
					writable, lazy_load_file, (void *)aux)){
				file_close(mmap_file);
				return NULL;
			}
		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
		offset += PGSIZE;
	}
    return addr;
}

/* Do the munmap */
void
do_munmap (void *addr) {
    struct thread *curr = thread_current();
    struct page *page = spt_find_page(&(curr->spt), addr);

    //check validity
    if(page == NULL) return;
    if(addr == NULL) return;
    if(page->operations->type != VM_FILE) return;
    if((addr != page->file.start) || is_kernel_vaddr(addr)) return;
    ASSERT(thread_current()->spt.hash_table.bucket_cnt > 0);

    //******************************** */
    //starts unmapping
    //******************************** */
    struct file_page file_page = page->file;
    size_t bytes_left = file_page.length;
    //int count=0;
    size_t chunk;
    for(bytes_left = file_page.length; bytes_left>0; bytes_left-=chunk){
        struct page* Page = spt_find_page(&curr->spt, addr);
        //count++;
        // if(Page==NULL){
        //     printf("Terminate at iteration: %d\n", count);
        //     exit(-1);
        // }exit(-1);
        //if(page==NULL) break;
        //if(page==NULL) printf("NULL page\n");

        //if dirty, write back
        if (pml4_is_dirty(curr->pml4, addr)){
            void *kaddr = pml4_get_page (curr->pml4, addr);
            lock_acquire(&filesys_lock);
            file_write_at(file_page.file, kaddr, Page->file.read_bytes, Page->file.offset);
            lock_release(&filesys_lock);
        }

        //remove page from spt and destroy it
        spt_remove_page(&curr->spt, Page);

        //advance
        chunk = bytes_left < PGSIZE ? bytes_left : PGSIZE;
        addr += PGSIZE;
    }
    //User handle file cleanup
}
