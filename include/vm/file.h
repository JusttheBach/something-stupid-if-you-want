#ifndef VM_FILE_H
#define VM_FILE_H
#include "filesys/file.h"
#include "vm/vm.h"

struct page;
enum vm_type;

struct file_page {
	struct page *page;
    struct file *file;
	off_t offset;
	size_t read_bytes;
	size_t zero_bytes;
	void* start;
	size_t length;
	struct list_elem file_page_elem;
};

struct aux_load_file{
	struct file* file;
	off_t offset;
	size_t read_bytes;
	size_t zero_bytes;
	void* start;
	size_t length;
};

void vm_file_init (void);
bool file_backed_initializer (struct page *page, enum vm_type type, void *kva);
void *do_mmap(void *addr, size_t length, int writable,
		struct file *file, off_t offset);
void do_munmap (void *va);
#endif
