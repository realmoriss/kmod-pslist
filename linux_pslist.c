#include <linux/module.h>
#include <linux/sched.h>
#include <linux/init_task.h>
#include <linux/highmem.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <linux/mm.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/fs_struct.h>
#include <linux/version.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Istvan Telek <moriss@realmoriss.me>");

/* User defines */
#define ALGO_NAME "sha256"
#define ALGO_OUT_LEN 32
#define PATH_BUF_LEN 256
#define ENV_BUF_LEN 512

/* User types */
struct sdesc {
	struct shash_desc shash;
	char ctx[];
};

/* Function definitions */
static struct sdesc *init_sdesc(struct crypto_shash *alg);

int snprintf_bytearray(char *buf, unsigned long maxlen, unsigned char *arr,
		       unsigned long len);

long hash_mem_region(struct task_struct *task, unsigned long start_address,
		     unsigned long end_address, unsigned char *digest);

long pagefault_mem_range(struct task_struct *task, unsigned long start_address,
			 unsigned long end_address);

void print_pslist(struct task_struct *task, int level, char *buf);

long print_taskinfo(struct task_struct *task, long pid, char *buf);

static int __init pslist_init(void);

static void __exit pslist_exit(void);

static ssize_t pslist_all_show(struct kobject *kobj,
			       struct kobj_attribute *attr, char *buf);

static ssize_t pslist_all_store(struct kobject *kobj,
				struct kobj_attribute *attr, const char *buf,
				size_t count);

static ssize_t pslist_by_pid_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf);

static ssize_t pslist_by_pid_store(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   const char *buf, size_t count);

/* Global variables */
//static int all_request = -1;
static long int by_pid_request = -1;

static struct kobj_attribute pslist_all_attribute = __ATTR(all, 0600,
							   pslist_all_show,
							   pslist_all_store);
static struct kobj_attribute pslist_by_pid_attribute = __ATTR(by_pid, 0600,
							      pslist_by_pid_show,
							      pslist_by_pid_store);

static struct attribute *pslist_attrs[] = {
	&pslist_all_attribute.attr,
	&pslist_by_pid_attribute.attr,
	NULL,
};

static struct attribute_group pslist_attr_group = {
	.attrs = pslist_attrs,
};

static struct kobject *pslist_kobject;

// These two variables should be managed by get_hasher and destroy_hasher only.
static struct crypto_shash *_shash_algorithm = NULL;
static struct sdesc *_shash_desc = NULL;

/* Function implementations */
static struct sdesc *init_sdesc(struct crypto_shash *alg)
{
	struct sdesc *sdesc;
	size_t size;

	size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
	sdesc = kmalloc(size, GFP_KERNEL);
	if (!sdesc)
		return ERR_PTR(-ENOMEM);
	sdesc->shash.tfm = alg;
	sdesc->shash.flags = 0x0;
	return sdesc;
}

struct sdesc *get_hasher(void)
{
	if (_shash_desc)
		return _shash_desc;

	if (!_shash_algorithm)
		_shash_algorithm = crypto_alloc_shash(ALGO_NAME,
						      CRYPTO_ALG_TYPE_SHASH, 0);

	if (IS_ERR(_shash_algorithm))
		return ERR_CAST(_shash_algorithm);

	_shash_desc = init_sdesc(_shash_algorithm);

	return _shash_desc;
}

void destroy_hasher(void)
{
	if (_shash_desc) {
		kfree(_shash_desc);
		_shash_desc = NULL;
	}
}

/**
 * Prints an array of bytes in a readable format
 */
int snprintf_bytearray(char *buf, unsigned long maxlen, unsigned char *arr,
		       unsigned long len)
{
	char *tmp;
	int i;

	if (!arr || !buf || (len <= 0))
		return -EINVAL;

	tmp = kmalloc((len * 2 + 1) * sizeof(*tmp), GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;

	tmp[0] = '\0';
	for (i = 0; i < len; ++i)
		snprintf(tmp, len * 2 + 1, "%s%02hhx", tmp, arr[i]);

	snprintf(buf, maxlen, "%s%s\n", buf, tmp);

	kfree(tmp);
	return 0;
}

/**
 * Prints an array of characters in a readable format
 */
int snprintf_chararray(char *buf, unsigned long maxlen, unsigned char *arr,
		       unsigned long len)
{
	char *tmp;
	int i;

	if (!arr || !buf || (len <= 0))
		return -EINVAL;

	tmp = kmalloc((len * 2 + 1) * sizeof(*tmp), GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;

	tmp[0] = '\0';
	for (i = 0; i < len; ++i) {
		if (arr[i] == 0)
			arr[i] = ' ';
		snprintf(tmp, len * 2 + 1, "%s%c", tmp, arr[i]);
	}

	snprintf(buf, maxlen, "%s%s\n", buf, tmp);

	kfree(tmp);
	return 0;
}

/**
 * Ensures that the pages for the memory region are present in the physical
 * memory. start_address and end_address are virtual addresses from the task's
 * address space. Returns 0 if all pages are loaded, or an error code (< 0)
 */
long pagefault_mem_range(struct task_struct *task, unsigned long start_address,
			 unsigned long end_address)
{
	unsigned long page_count;
	long user_pages;
	unsigned long address_range = end_address - start_address;

	if (!task || (start_address >= end_address))
		return -EINVAL;
	// This is the number of pages for the address range
	page_count = (address_range / PAGE_SIZE) + 1;
	// Do page fault for all pages
	user_pages = get_user_pages_remote(task, task->mm, start_address,
					   page_count, 0, 1, NULL, NULL);

	if (IS_ERR_VALUE(user_pages))
		return user_pages;

	if (page_count != user_pages)
		return -EFAULT;

	return 0;
}

/**
 * Calculates a digest for a given memory region of a task's virtual memory.
 */
long hash_mem_region(struct task_struct *task, unsigned long start_address,
		     unsigned long end_address, unsigned char *digest)
{
	struct sdesc *sdesc;
	// From first page start_address to last page end_address
	unsigned long page_count;
	struct page **pages;
	long result;
	unsigned long page_len;
	int i;
	unsigned char *page_ptr;

	if (!task || (start_address > end_address))
		return -EINVAL;

	// Initialize hashing and make sure it is working
	sdesc = get_hasher();

	if (IS_ERR(sdesc))
		return PTR_ERR(sdesc);

	result = crypto_shash_init(&sdesc->shash);
	if (IS_ERR_VALUE(result))
		return result;

	page_count = ((end_address - start_address) / PAGE_SIZE) + 1;

	// Reserve memory for the page structs
	pages = kmalloc(page_count * sizeof(*pages), GFP_KERNEL);
	if (!pages)
		return -ENOMEM;

	// Get the pages
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,6,3)
	result = get_user_pages_remote(task, task->mm, start_address,
				       page_count, 0, 1, pages, NULL);
#else
	int lock = 0;
	result = get_user_pages_remote(task, task->mm, start_address,
		page_count, 0, pages, NULL, &lock);
#endif
	if (IS_ERR_VALUE(result))
		goto out_free_pages;

	if (page_count != result) {
		result = -EFAULT;
		goto out_put_pages;
	}

	if ((start_address & ~(PAGE_SIZE - 1)) + PAGE_SIZE > end_address)
		page_len = end_address - start_address;
	else
		page_len = PAGE_SIZE - (start_address & (PAGE_SIZE - 1));
	// Calculate the digest for the whole address range
	for (i = 0; i < page_count; ++i) {
		page_ptr = kmap_atomic(pages[i]);
		if (!page_ptr) {
			result = -EFAULT;
			goto out_put_pages;
		}
		result = crypto_shash_update(&sdesc->shash,
					     &(page_ptr[start_address &
							(PAGE_SIZE - 1)]),
					     (unsigned int) page_len);
		kunmap_atomic(page_ptr);
		if (IS_ERR_VALUE(result))
			goto out_put_pages;
		start_address += page_len;
		if (start_address + PAGE_SIZE > end_address)
			page_len = (end_address - start_address);
		else
			page_len = PAGE_SIZE;
	}
	result = crypto_shash_final(&sdesc->shash, digest);
out_put_pages:
	for (i = 0; i < page_count; ++i)
		put_page(pages[i]);
out_free_pages:
	kfree(pages);
	return result;
}

/**
 * Reads a specified region from the task's memory into the buffer.
 */
long read_mem_region(struct task_struct *task, unsigned long start_address,
		     unsigned long end_address, unsigned char *buf)
{
	// From first page start_address to last page end_address
	unsigned long page_count;
	struct page **pages;
	long result;
	unsigned long page_len;
	int i;
	unsigned char *page_ptr;

	if (!task || (start_address > end_address))
		return -EINVAL;

	page_count = ((end_address - start_address) / PAGE_SIZE) + 1;
	// Reserve memory for the page structs
	pages = kmalloc(page_count * sizeof(*pages), GFP_KERNEL);
	if (!pages)
		return -ENOMEM;

	// Get the pages
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,6,3)
	result = get_user_pages_remote(task, task->mm, start_address,
				       page_count, 0, 1, pages, NULL);
#else
	int lock = 0;
	result = get_user_pages_remote(task, task->mm, start_address,
		page_count, 0, pages, NULL, &lock);
#endif

	if (IS_ERR_VALUE(result))
		goto out_free_pages;

	if (page_count != result) {
		result = -EFAULT;
		goto out_put_pages;
	}

	if ((start_address & ~(PAGE_SIZE - 1)) + PAGE_SIZE > end_address)
		page_len = end_address - start_address;
	else
		page_len = PAGE_SIZE - (start_address & (PAGE_SIZE - 1));
	// Calculate the digest for the whole address range
	for (i = 0; i < page_count; ++i) {
		page_ptr = kmap_atomic(pages[i]);
		if (!page_ptr) {
			result = -EFAULT;
			goto out_put_pages;
		}
		memcpy(buf, &(page_ptr[start_address & (PAGE_SIZE - 1)]),
		       page_len);
		buf = &(buf[page_len]);
		kunmap_atomic(page_ptr);
		start_address += page_len;
		if (start_address + PAGE_SIZE > end_address)
			page_len = end_address - start_address;
		else
			page_len = PAGE_SIZE;
	}
	result = 0;
out_put_pages:
	for (i = 0; i < page_count; ++i)
		put_page(pages[i]);
out_free_pages:
	kfree(pages);
	return result;
}

/**
* Recursive DFS for traversing 'task_struct' tree
* Prints out information about the running processes
* @param task the root of the process tree
* @param level the current level of indentation
*/
void print_pslist(struct task_struct *task, int level, char *buf)
{
	struct list_head *list;
	struct list_head *head;
	// Memory management data of process
	struct mm_struct *mm = task->mm;
	struct task_struct *child;
	// struct vm_area_struct *vma;
	// char hash[ALGO_OUT_LEN];
	// Print process id and short cmdline
	snprintf(buf, PAGE_SIZE, "%s%*s[%u] %s\n", buf, 2 * level, "",
		 task->pid, task->comm);
	if (mm) {
		// Print PGD value
		snprintf(buf, PAGE_SIZE, "%s%*sPGD: %p [%llx]\n", buf,
			 2 * (level + 1), "", pgd_val(mm->pgd),
			 *pgd_val(mm->pgd));
		// Print code and data segment location
		snprintf(buf, PAGE_SIZE,
			 "%s%*sCode: %lx-%lx, Data: %lx-%lx\n", buf,
			 2 * (level + 1), "", mm->start_code, mm->end_code,
			 mm->start_data, mm->end_data);
		// Print heap location, mmap and stack base address
		snprintf(buf, PAGE_SIZE,
			 "%s%*sHeap: %lx-%lx, Mmap: %lx, Stack: %lx\n", buf,
			 2 * (level + 1), "", mm->start_brk, mm->brk,
			 mm->mmap_base, mm->start_stack);
	}
	// Traverse children list and recursively print info about them
	head = &task->children;
	for (list = head->next; list != head; list = list->next) {
		child = list_entry(list, struct task_struct, sibling);
		print_pslist(child, level + 1, buf);
	}
}

/**
 * Generates page faults for every task's code segment pages.
 * This ensures that all pages are loaded into memory and can be used.
 */
long pagefault_pslist(struct task_struct *task)
{
	struct list_head *list;
	struct list_head *head;
	struct task_struct *child;
	struct mm_struct *mm;
	long res = 0;
	long tmp_res;

	if (!task)
		return -EINVAL;

	mm = task->mm;
	head = &(task->children);
	for (list = head->next; list != head; list = list->next) {
		child = list_entry(list, struct task_struct, sibling);
		tmp_res = pagefault_pslist(child);
		if (IS_ERR_VALUE(tmp_res))
			res = tmp_res;
	}

	if (!mm)
		return res;

	tmp_res = pagefault_mem_range(task, mm->start_code, mm->end_code);
	if (IS_ERR_VALUE(tmp_res))
		res = tmp_res;

	return res;
}

/**
 * Finds the process with the given pid by traversing the process tree starting
 * from the given task_struct. Prints information about the task into the given
 * buffer.
 */
long print_taskinfo(struct task_struct *task, long pid, char *buf)
{
	struct list_head *list;
	struct list_head *head;
	struct mm_struct *mm = task->mm;
	struct task_struct *child;
	unsigned char *hash;
	unsigned char *path_buf;
	unsigned char *env_buf;
	long result = 0;
	unsigned long arg_end;
	unsigned long env_end;

	// Check for valid arguments
	if (!task || pid <= 0 || !buf)
		return -EINVAL;

	// Search amongst child tasks if we are not matching
	if (task->pid != pid) {
		head = &task->children;
		for (list = head->next; list != head; list = list->next) {
			child = list_entry(list, struct task_struct, sibling);
			result = print_taskinfo(child, pid, buf);
			// If we found the process, we have nothing to do
			if (!IS_ERR_VALUE(result))
				return result;
		}
		// We haven't found any matching process.
		return -ESRCH;
	}

	// Print basic task info
	snprintf(buf, PAGE_SIZE, "%s[%u] %s\n", buf, task->pid, task->comm);

	// If no memory management info is available, we're done.
	if (!mm)
		return 0;

	// Print memory layout info
	snprintf(buf, PAGE_SIZE, "%sCode: %lx-%lx, Data: %lx-%lx\n", buf,
		 mm->start_code, mm->end_code, mm->start_data, mm->end_data);
	snprintf(buf, PAGE_SIZE, "%sHeap: %lx-%lx, Mmap: %lx, Stack: %lx\n",
		 buf, mm->start_brk, mm->brk, mm->mmap_base, mm->start_stack);

	struct vm_area_struct *vma_curr;
	for (vma_curr = mm->mmap;
	     vma_curr != NULL; vma_curr = vma_curr->vm_next) {
		snprintf(buf, PAGE_SIZE, "%sVMA: %lx-%lx\n", buf,
			 vma_curr->vm_start, vma_curr->vm_end);
		if (vma_curr->vm_file) {
			char *pathbuf = kmalloc(sizeof(*pathbuf) * PATH_BUF_LEN,
						GFP_KERNEL);
			char *real_path = d_path(&vma_curr->vm_file->f_path,
						 pathbuf, PATH_BUF_LEN);
			snprintf(buf, PAGE_SIZE, "%sFile: %s\n", buf,
				 real_path);
			kfree(pathbuf);
		}
	}

	// Print the hash of the code segment
	hash = kmalloc(ALGO_OUT_LEN * sizeof(*hash), GFP_KERNEL);
	if (!hash)
		return -ENOMEM;

	// Force load all pages for the task's code segment
	result = pagefault_mem_range(task, mm->start_code, mm->end_code);
	if (IS_ERR_VALUE(result))
		goto err_free_hash;

	// Produce a digest of the code segment
	result = hash_mem_region(task, mm->start_code, mm->end_code, hash);
	if (IS_ERR_VALUE(result))
		goto err_free_hash;

	// Print the digest
	snprintf(buf, PAGE_SIZE, "%sSHA-256 sum of code segment:\n", buf);
	snprintf_bytearray(buf, PAGE_SIZE, hash, ALGO_OUT_LEN);

err_free_hash:
	// printk(KERN_INFO "Hashing done.\n");
	kfree(hash);

	// Print the cmdline of the process
	path_buf = kmalloc(PATH_BUF_LEN * sizeof(*path_buf), GFP_KERNEL);
	if (!path_buf)
		return -ENOMEM;
	arg_end = mm->arg_end;

	// Do not read more than the buffer size
	if ((arg_end - mm->arg_start) >= PATH_BUF_LEN) {
		arg_end = mm->arg_start + PATH_BUF_LEN - 1;
	}

	// Read the command line
	result = read_mem_region(task, mm->arg_start, arg_end, path_buf);
	if (IS_ERR_VALUE(result))
		goto err_free_path_buf;

	snprintf(buf, PAGE_SIZE, "%sCmdline: %lx (%ld bytes)\n", buf,
		 mm->arg_start, mm->arg_end - mm->arg_start);
	snprintf_chararray(buf, PAGE_SIZE, path_buf,
			   arg_end - mm->arg_start);

err_free_path_buf:
	kfree(path_buf);

	// Print the envvars of the process
	env_buf = kmalloc(ENV_BUF_LEN * sizeof(*env_buf), GFP_KERNEL);
	if (!env_buf)
		return -ENOMEM;
	env_end = mm->env_end;

	// Do not read more than the buffer size
	if ((env_end - mm->env_start) >= ENV_BUF_LEN) {
		env_end = mm->env_start + ENV_BUF_LEN - 1;
	}

	// Read the command line
	result = read_mem_region(task, mm->env_start, env_end, env_buf);
	if (IS_ERR_VALUE(result))
		goto err_free_env_buf;

	snprintf(buf, PAGE_SIZE, "%sEnvvars: %lx (%ld bytes)\n", buf,
		 mm->env_start, mm->env_end - mm->env_start);
	snprintf_chararray(buf, PAGE_SIZE, env_buf,
			   env_end - mm->env_start);

err_free_env_buf:
	kfree(env_buf);

	return result;
}


static ssize_t pslist_all_show(struct kobject *kobj,
			       struct kobj_attribute *attr, char *buf)
{
	snprintf(buf, PAGE_SIZE, "Process tree:\n");
	print_pslist(&init_task, 0, buf);
	return strlen(buf);
}

static ssize_t pslist_all_store(struct kobject *kobj,
				struct kobj_attribute *attr, const char *buf,
				size_t count)
{
	printk(KERN_INFO "pagefault_pslist result: %ld\n",
	       pagefault_pslist(&init_task));
	return count;
}

static ssize_t pslist_by_pid_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	buf[0] = '\0';
	print_taskinfo(&init_task, by_pid_request, buf);
	return strlen(buf);
}

static ssize_t pslist_by_pid_store(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   const char *buf, size_t count)
{
	if (sscanf(buf, "%ld", &by_pid_request) != 1)
		by_pid_request = -1;
	return count;
}

static int __init pslist_init(void)
{
	int error = 0;
	// Create sysfs for all
	pslist_kobject = kobject_create_and_add("pslist", kernel_kobj);
	if (!pslist_kobject)
		return -ENOMEM;
	error = sysfs_create_group(pslist_kobject, &pslist_attr_group);
	if (IS_ERR_VALUE(error))
		kobject_put(pslist_kobject);
	return error;
}

static void __exit pslist_exit(void)
{
	kobject_put(pslist_kobject);
	destroy_hasher();
}

module_init(pslist_init);

module_exit(pslist_exit);
