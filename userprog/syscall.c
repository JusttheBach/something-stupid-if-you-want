#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "threads/palloc.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/synch.h"
#include "threads/vaddr.h"


#define MAX_FILE_NUMBER 128
void syscall_entry (void);
void syscall_handler (struct intr_frame *);
static void munmap(void *addr);
static void *mmap(void *addr, size_t length, int writable, int fd, off_t offset);

#define SET_RAX (f, val) (f->R.rax = (uint64_t)val)

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

extern struct lock filesys_lock;

// check whether user pointer address is valid
int isValid(void *ptr){
	//check if ptr points to user address space, is properly mapped to a page, and is not a NULL pointer.
	bool succ = false;
	if(ptr!=NULL){
		if(is_user_vaddr(ptr)){
			succ = (spt_find_page(&thread_current()->spt, ptr) != NULL) && (pml4_get_page(thread_current()->pml4, ptr)!=NULL);
		}
	}
	return succ;
}

void buf_val(void *buf, size_t size, bool write) {
	if (buf == NULL) exit(-1);
	void *start = pg_round_down(buf);
	void *end = pg_round_down(buf + size);

	ASSERT(start <= end);
	for (void *addr = end; addr >= start; addr -= PGSIZE) {
		struct page *page = spt_find_page(&thread_current()->spt, addr);
		if (page == NULL) {
			exit(-1);
		}
		if (page->isWritable == false && write == true) {
			exit(-1);
		}
	}
}

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	lock_init(&filesys_lock); //initialize global lock for file accesses

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	// memset(&stdin_file, 0, sizeof(struct file));
    // memset(&stdout_file, 0, sizeof(struct file));

	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	// pass with the order %rdi, %rsi, %rdx, %r10, %r8, and %r9.
	uint64_t args[5] = {f->R.rdi, f->R.rsi, f->R.rdx, f->R.r10, f->R.r8};
	thread_current()->usrsp = f->rsp;
	switch (f->R.rax) {
		case SYS_HALT:
			halt();
			break;
		case SYS_EXIT:
			exit(f->R.rdi);
			break;
		case SYS_FORK:
			/*make a copy of parent's if before calling fork() to pass to child*/
			memcpy(&thread_current()->copy_if, f, sizeof(struct intr_frame));
			f->R.rax = fork(f->R.rdi);
			break;
		case SYS_CREATE:
			f->R.rax = create(f->R.rdi, f->R.rsi);
			break;
		case SYS_REMOVE:
			f->R.rax = remove(f->R.rdi);
			break;
		case SYS_OPEN:
			f->R.rax = open(f->R.rdi);
			break;
		case SYS_FILESIZE:
			f->R.rax = filesize(f->R.rdi);
			break;
		case SYS_READ:
			f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
			break;  
		case SYS_WRITE:      
			f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_EXEC:
			exec(f->R.rdi);
			break;
		case SYS_WAIT:
			f->R.rax = wait(f->R.rdi);
			break; 
		case SYS_SEEK:
			seek(f->R.rdi, f->R.rsi);
			break;
		case SYS_TELL:
			f->R.rax = tell(f->R.rdi);
			break;
		case SYS_CLOSE:
			close(f->R.rdi);
			break;
		case SYS_DUP2:
			dup2(f->R.rdi, f->R.rsi);
			break;

		//project 3
		case SYS_MMAP:
			f->R.rax = (uint64_t) mmap((void *) args[0],(size_t)args[1],(int)args[2],(int)args[3],(off_t)args[4]);
			break;
		case SYS_MUNMAP:
			munmap((void *)args[0]);
			break;
		default:
			thread_exit();
	}
}

void halt(void) {
	power_off();
}

void exit(int status) {
	/*print exit messages*/
	//print them here to not fail thread tests
	struct thread *curr = thread_current();
	curr->exit_status = status;
	printf("%s: exit(%d)\n", curr->name, status);

	/*EXIT*/
	thread_exit(); //destroy thread, inherently calls process_exit()
}
//copy for now

tid_t fork (const char *thread_name) {
	if(!isValid(thread_name)) exit(-1);
	lock_acquire (&filesys_lock);
	tid_t result = process_fork(thread_name, &thread_current()->copy_if);
	lock_release(&filesys_lock);
	return result;
}

int exec (const char *cmd_line) {
	if(!isValid(cmd_line)) exit(-1);

	//copy cmd_line to kernel memory region to avoid change in user memory
	char *cmd_line_kernel = palloc_get_page(0); //will be freed in process_exec after load is done
	if (cmd_line_kernel == NULL) {
		exit(-1);
		return -1;
	}
	strlcpy(cmd_line_kernel, cmd_line, PGSIZE);

	/*execute*/
	if (process_exec(cmd_line_kernel) == -1) {
		exit(-1);
		return -1;
	}
	
	/*doesn't return anything by default*/
}

int wait (tid_t pid) {
  	return process_wait(pid);
}
// end not done

bool create (const char *file, unsigned initial_size) {
	if(!isValid(file)) exit(-1);
	lock_acquire(&filesys_lock);
	bool creation = filesys_create(file, initial_size);
	lock_release(&filesys_lock);
	return creation;
}

bool remove (const char *file) {
	if(!isValid(file)) exit(-1);
	lock_acquire(&filesys_lock);
	bool removal = filesys_remove(file);
	lock_release(&filesys_lock);
	return removal;
}

int open (const char *file) {
	if(!isValid(file)) exit(-1);
	/*open file*/
	lock_acquire(&filesys_lock);
	struct file *opened_file = filesys_open(file);
	lock_release(&filesys_lock);


	/*allocate fd*/
	struct thread *cur = thread_current();
	if (opened_file) {
		int fd;
		for (fd = 0; fd < MAX_FILE_NUMBER; fd++) {
			if (!cur->fdt[fd]) {
				cur->fdt[fd] = opened_file;
				cur->next_fd = fd + 1;
				return fd;
			}
		}
		/*fdt is full*/
		file_close(opened_file);
	}
	return -1;
}

int filesize (int fd) {
	struct file *file = thread_current()->fdt[fd];
	if (file)
		return file_length(file);
	return -1;
}

int read (int fd, void *buffer, unsigned size) {
	buf_val(buffer, size, true);

	if(fd>128) exit(-1);

	//not stdout
	if (fd == 1) {
		return -1;
	}

	//read from keyboard
	if (fd == 0) { 
		lock_acquire(&filesys_lock);
		int byte = input_getc();
		lock_release(&filesys_lock);
		return byte;
	}
	//read from file
	struct file *file = thread_current()->fdt[fd];
	if (file) {
		lock_acquire(&filesys_lock);
		int read_byte = file_read(file, buffer, size);
		lock_release(&filesys_lock);
		return read_byte;
	}
	return -1;
}

int write (int fd UNUSED, const void *buffer, unsigned size) {
	// if (pml4_get_page(thread_current()->pml4, buffer)==NULL) printf("not mapped!\n");
	// if(pml4_get_page(thread_current()->pml4, buffer)!=NULL) printf("mapped!\n");
	// if(is_user_vaddr(buffer)) printf("is user address?\n");
	// printf("buffer: %s\n", buffer);
	buf_val(buffer, size, false);
	if(fd>128) exit(-1);
	
	if (fd == 0)
		return -1;

	if (fd == 1) {
		lock_acquire(&filesys_lock);
		/*write all of buffer in one go to not confuse readers*/
		putbuf(buffer, size);
		lock_release(&filesys_lock);
		return size;
	}

	struct file *file = thread_current()->fdt[fd];
	if (file) {
		lock_acquire(&filesys_lock);
		int bytes_written = file_write(file, buffer, size);
		lock_release(&filesys_lock);
		return bytes_written;
	}
}

void seek (int fd, unsigned position) {
	if(fd>128) exit(-1);
	struct file *file = thread_current()->fdt[fd];
	if (file){
		lock_acquire(&filesys_lock);
		file_seek(file, position);
		lock_release(&filesys_lock);
	}
}

unsigned tell (int fd) {
	struct file *file = thread_current()->fdt[fd];
	if (file){
		unsigned out;
		lock_acquire(&filesys_lock);
		out = file_tell(file);
		lock_release(&filesys_lock);
		return out;
	}
}

void close (int fd) {
	if(fd>128) exit(-1); // invalid fd
	struct file * file = thread_current()->fdt[fd];
	if (file) {
		lock_acquire(&filesys_lock);
		thread_current()->fdt[fd] = NULL;
		file_close(file);
		lock_release(&filesys_lock);
	}
}

int dup2(int oldfd, int newfd){
	return 0;
}

// Helper function for mmap to determine if the address is already mapped to a page
bool isMapped(void* addr, size_t length){
	struct thread* curr = thread_current();
    for (void *i_addr = pg_round_down(addr+length); i_addr >= pg_round_down(addr); i_addr -= PGSIZE)
    {	
		// check mapping
		if(spt_find_page(&curr->spt, addr)!=NULL){
			return false;
		}
    }
	return true;
}


//Project 3
static void *mmap(void *addr, size_t length, int writable, int fd, off_t offset){	
	/***************CHECK VALIDITY******************* */
	// check addr
	if(addr==NULL) return NULL;
    if (is_kernel_vaddr(addr)|| is_kernel_vaddr((size_t)addr + length) || (addr!=pg_round_down(addr))) return NULL;

    if(!isMapped(addr, length)) return NULL;

	if (offset % PGSIZE != 0) return NULL;
	if ((long)length <= 0)return NULL;
	/***************get file from fd******************* */
	//check for validity
	if((fd==0)||(fd==1)) return NULL;
	struct file *file = thread_current()->fdt[fd];
	if(file==NULL) return NULL;

    off_t file_len = file_length(file);
    if (file_len == 0) return NULL;

    if (file_len <= offset) return NULL;
    struct thread *curr_thread = thread_current();
    file_len = file_len < length ? file_len : length;
    lock_acquire(&filesys_lock);
    void *success = do_mmap(addr, (size_t)file_len, writable, file, offset);
    lock_release(&filesys_lock);

    return success;
}

static void munmap(void *addr){
    do_munmap(addr);
}