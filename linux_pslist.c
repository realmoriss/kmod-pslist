#include <linux/module.h>
#include <linux/sched.h>
#include <linux/init_task.h>
#include <linux/highmem.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <linux/mm.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/version.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Istvan Telek <moriss@realmoriss.me>");

#define ALGO_NAME "sha256"
#define ALGO_OUT_SIZE 32
#define PATH_BUF_SIZE 512
#define ENV_BUF_SIZE 512

#define DEBUG_ON

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

struct sdesc {
	struct shash_desc shash;
	char ctx[];
};

static struct kobj_attribute pslist_all_attribute = __ATTR(all, 0600,
							   pslist_all_show,
							   pslist_all_store);
static struct kobj_attribute pslist_by_pid_attribute = __ATTR(by_pid, 0600,
							      pslist_by_pid_show,
							      pslist_by_pid_store);

static long int by_pid_request = -1;

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

/**
 * Initializes the hasher algorithm
 */
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

/**
 * Returns the global hasher
 */
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

/**
 * Destroys the global hasher
 */
void destroy_hasher(void)
{
	if (_shash_desc) {
		kfree(_shash_desc);
		_shash_desc = NULL;
	}
}

/**
 * Prints an array of bytes in a readable format
 * @param buf pointer to a buffer where the array will be printed
 * @param size maximum number of bytes to be used in the buffer
 * @param arr the array which contains the data to be printed
 * @param arr_size the size of the data array
 * @return 0 or an error code
 */
int snprint_bytearray(char *buf, size_t size, u8 *arr, size_t arr_size)
{
	char *tmp;
	int i;

	if (!arr || !buf || (arr_size <= 0))
		return -EINVAL;

	// 2 characters per byte, plus the terminator
	tmp = kmalloc((arr_size * 2 + 1) * sizeof(*tmp), GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;

	tmp[0] = '\0';
	for (i = 0; i < arr_size; ++i)
		snprintf(tmp, arr_size * 2 + 1, "%s%02hhx", tmp, arr[i]);

	snprintf(buf, size, "%s%s\n", buf, tmp);

	kfree(tmp);
	return 0;
}

/**
 * Prints an array of characters in a readable format
 */
int snprint_chararray(char *buf, size_t size, char *arr, size_t arr_size)
{
	char *tmp;
	int i;

	if (!arr || !buf || (arr_size <= 0))
		return -EINVAL;

	// 1 character per char, plus the terminator
	tmp = kmalloc((arr_size + 1) * sizeof(*tmp), GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;

	tmp[0] = '\0';
	for (i = 0; i < arr_size; ++i) {
		if (arr[i] == '\0')
			arr[i] = ' ';
		snprintf(tmp, arr_size + 1, "%s%c", tmp, arr[i]);
	}

	snprintf(buf, size, "%s%s\n", buf, tmp);

	kfree(tmp);
	return 0;
}

/**
 * Ensures that the pages for the memory region are present in the physical
 * memory. start_address and end_address are virtual addresses from the task's
 * address space. Returns 0 if all pages are loaded, or an error code (< 0)
 */
long pagefault_task_range(struct task_struct *task, unsigned long start_address,
			  size_t count)
{
	size_t page_count;
	long user_pages;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
	int lock = 1;
#endif

	if (!task || !count)
		return -EINVAL;
	// This is the number of pages for the address range
	page_count = (count / PAGE_SIZE) + 1;
	// Do page fault for all pages
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
	user_pages = get_user_pages_remote(task, task->mm, start_address,
					   page_count, 0, 1, NULL, NULL);
#else
	user_pages = get_user_pages_remote(task, task->mm, start_address,
					   page_count, 0, NULL, NULL, &lock);
#endif

	if (IS_ERR_VALUE(user_pages))
		return user_pages;

	if (page_count != user_pages)
		return -EFAULT;

	return 0;
}

/**
 * Calculates a digest for a given memory region of a task's virtual memory.
 */
long hash_task_vmem(struct task_struct *task, unsigned long start_address,
		    size_t count, u8 *digest)
{
	struct sdesc *sdesc;
	struct page **pages;
	size_t page_count;
	size_t page_size;
	size_t page_offset;
	u8 *page_ptr;
	long result;
	int i;

	if (!task || !count)
		return -EINVAL;

	sdesc = get_hasher();

	if (IS_ERR(sdesc))
		return PTR_ERR(sdesc);

	result = crypto_shash_init(&sdesc->shash);
	if (IS_ERR_VALUE(result))
		return result;

	page_count = (count / PAGE_SIZE) + 1;

	pages = kmalloc(page_count * sizeof(*pages), GFP_KERNEL);
	if (!pages)
		return -ENOMEM;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
	result = get_user_pages_remote(task, task->mm, start_address,
				       page_count, 0, 1, pages, NULL);
#else
	int lock = 1;
	result = get_user_pages_remote(task, task->mm, start_address,
				       page_count, 0, pages, NULL, &lock);
#endif
	if (IS_ERR_VALUE(result))
		goto out_free_pages;

	if (page_count != result) {
		result = -EFAULT;
		goto out_put_pages;
	}

	for (i = 0; i < page_count; ++i) {
		page_offset = start_address & (PAGE_SIZE - 1);
		// Check if the whole address range is on the first page
		if (page_offset + count <= PAGE_SIZE)
			page_size = count;
		else
			page_size = PAGE_SIZE - page_offset;
#ifdef DEBUG_ON
		printk(KERN_INFO "Start: %lx, Count: %lu, Page size: %lu, Page offset: %lx\n",
		       start_address,
		       count, page_size, page_offset);
#endif
		page_ptr = kmap_atomic(pages[i]);
		if (!page_ptr) {
			result = -EFAULT;
			goto out_put_pages;
		}
		/* Since we mapped the entire page, we need to make sure to only
		 * append relevant data
		 */
		result = crypto_shash_update(&sdesc->shash,
					     &page_ptr[page_offset],
					     (unsigned int) page_size);
		kunmap_atomic(page_ptr);
		if (IS_ERR_VALUE(result))
			goto out_put_pages;
		start_address += page_size;
		count -= page_size;
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
long memcpy_task_vmem(char *buf, struct task_struct *task,
		      unsigned long start_address, size_t count)
{
	size_t page_count;
	size_t page_size;
	size_t page_offset;
	char *page_ptr;
	struct page **pages;
	long result;
	int i = 1;

	if (!task || !count)
		return -EINVAL;

	page_count = (count / PAGE_SIZE) + 1;

	pages = kmalloc(page_count * sizeof(*pages), GFP_KERNEL);
	if (!pages)
		return -ENOMEM;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
	result = get_user_pages_remote(task, task->mm, start_address,
				       page_count, 0, 1, pages, NULL);
#else
	result = get_user_pages_remote(task, task->mm, start_address,
				       page_count, 0, pages, NULL, &i);
#endif

	if (IS_ERR_VALUE(result))
		goto out_free_pages;

	if (page_count != result) {
		result = -EFAULT;
		goto out_put_pages;
	}

	for (i = 0; i < page_count; ++i) {
		page_offset = start_address & (PAGE_SIZE - 1);
		// Check if the whole address range is on the first page
		if (page_offset + count <= PAGE_SIZE)
			page_size = count;
		else
			page_size = PAGE_SIZE - page_offset;
#ifdef DEBUG_ON
		printk(KERN_INFO "Start: %lx, Count: %lu, Page size: %lu, Page offset: %lx\n",
		       start_address,
		       count, page_size, page_offset);
#endif
		page_ptr = kmap_atomic(pages[i]);
		if (!page_ptr) {
			result = -EFAULT;
			goto out_put_pages;
		}
		/* Since we mapped the entire page, we need to make sure to only
		 * append relevant data
		 */
		memcpy(buf, &page_ptr[page_offset], page_size);
		buf = &buf[page_size];
		kunmap_atomic(page_ptr);
		start_address += page_size;
		count -= page_size;
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
void snprint_pslist(char *buf, size_t size, struct task_struct *task,
		    int level)
{
	struct list_head *list;
	struct list_head *head;
	struct mm_struct *mm = task->mm;
	struct task_struct *child;

	// Print process id and short cmdline
	snprintf(buf, size, "%s%*s[%u] %s\n", buf, 2 * level, "",
		 task->pid, task->comm);
	if (mm) {
		// Print PGD value
		snprintf(buf, size, "%s%*sPGD: %p [%llx]\n", buf,
			 2 * (level + 1), "", pgd_val(mm->pgd),
			 *pgd_val(mm->pgd));
		// Print code and data segment location
		snprintf(buf, size, "%s%*sCode: %lx-%lx, Data: %lx-%lx\n", buf,
			 2 * (level + 1), "", mm->start_code, mm->end_code,
			 mm->start_data, mm->end_data);
		// Print heap location, mmap and stack base address
		snprintf(buf, size,
			 "%s%*sHeap: %lx-%lx, Mmap: %lx, Stack: %lx\n", buf,
			 2 * (level + 1), "", mm->start_brk, mm->brk,
			 mm->mmap_base, mm->start_stack);
	}
	// Traverse children list and recursively print info about them
	head = &task->children;
	for (list = head->next; list != head; list = list->next) {
		child = list_entry(list, struct task_struct, sibling);
		snprint_pslist(buf, size, child, level + 1);
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

	tmp_res = pagefault_task_range(task, mm->start_code,
				       mm->end_code - mm->start_code);
	if (IS_ERR_VALUE(tmp_res))
		res = tmp_res;

	return res;
}

/**
 * Prints the digest of the given task's code segment into the buffer
 */
long snprint_task_digest(char *buf, size_t size, struct task_struct *task)
{
	struct mm_struct *mm = task->mm;
	u8 *hash;
	long result;

	if (!task || !mm)
		return -EINVAL;

	// Print the hash of the code segment
	hash = kmalloc(ALGO_OUT_SIZE * sizeof(*hash), GFP_KERNEL);
	if (!hash)
		return -ENOMEM;

	// Produce a digest of the code segment
	result = hash_task_vmem(task, mm->start_code,
				mm->end_code - mm->start_code, hash);
	if (IS_ERR_VALUE(result)) {
#ifdef DEBUG_ON
		printk(KERN_INFO "err in hash_task_vmem %ld\n", result);
#endif
		goto err_free_hash;
	}

	// Print the digest
	snprintf(buf, size, "%sSHA-256 sum of code segment:\n", buf);
	snprint_bytearray(buf, size, hash, ALGO_OUT_SIZE);

err_free_hash:
	kfree(hash);

	return result;
}

/**
 * Prints the command line of the given task into the buffer
 */
long snprint_task_cmdline(char *buf, size_t size, struct task_struct *task)
{
	struct mm_struct *mm = task->mm;
	size_t arg_size;
	char *path_buf;
	long result;

	if (!task || !mm)
		return -EINVAL;

	// Print the cmdline of the process
	path_buf = kmalloc(PATH_BUF_SIZE * sizeof(*path_buf), GFP_KERNEL);
	if (!path_buf)
		return -ENOMEM;

	arg_size = mm->arg_end - mm->arg_start;
	if (arg_size >= PATH_BUF_SIZE) {
		arg_size = PATH_BUF_SIZE;
	}

	result = memcpy_task_vmem(path_buf, task, mm->arg_start, arg_size);
	if (IS_ERR_VALUE(result))
		goto err_free_path_buf;

	snprintf(buf, size, "%sCmdline: %lx-%lx (%ld bytes)\n", buf,
		 mm->arg_start, mm->arg_end, arg_size);
	snprint_chararray(buf, size, path_buf, arg_size);

err_free_path_buf:
	kfree(path_buf);

	return result;
}

/**
 * Prints the environment variables of the given task into the buffer
 */
long snprint_task_envvars(char *buf, size_t size, struct task_struct *task)
{
	struct mm_struct *mm = task->mm;
	char *env_buf;
	size_t env_size;
	long result;

	if (!task || !task->mm)
		return -EINVAL;

	// Print the envvars of the process
	env_buf = kmalloc(ENV_BUF_SIZE * sizeof(*env_buf), GFP_KERNEL);
	if (!env_buf)
		return -ENOMEM;
	env_size = mm->env_end - mm->env_start;

	// Do not read more than the buffer size
	if (env_size >= ENV_BUF_SIZE) {
		env_size = ENV_BUF_SIZE;
	}

	// Read the command line
	result = memcpy_task_vmem(env_buf, task, mm->env_start, env_size);
	if (IS_ERR_VALUE(result))
		goto err_free_env_buf;

	snprintf(buf, size, "%sEnvvars: %lx-%lx (%ld bytes)\n", buf,
		 mm->env_start, mm->env_end, env_size);
	snprint_chararray(buf, size, env_buf, env_size);

err_free_env_buf:
	kfree(env_buf);

	return result;
}

/**
 * Prints the VMA info of the given task into the buffer
 */
long snprint_task_vmas(char *buf, size_t size, struct task_struct *task)
{
	struct mm_struct *mm = task->mm;
	struct vm_area_struct *vma;
	char *path;
	char *path_d;

	for (vma = mm->mmap; vma != NULL; vma = vma->vm_next) {
		snprintf(buf, size, "%sVMA: %lx-%lx\n", buf, vma->vm_start,
			 vma->vm_end);
		if (!vma->vm_file)
			continue;

		path = kmalloc(sizeof(*path) * PATH_BUF_SIZE, GFP_KERNEL);
		if (!path)
			return -ENOMEM;

		path_d = d_path(&vma->vm_file->f_path, path, PATH_BUF_SIZE);
		if (IS_ERR(path_d))
			goto free_vma_path_buf;

		snprintf(buf, size, "%sFile: %s\n", buf, path_d);
free_vma_path_buf:
		kfree(path);
	}

	return 0;
}

/**
 * Finds the process with the given pid by traversing the process tree starting
 * from the given task_struct. Prints information about the task into the given
 * buffer.
 */
long snprint_task_info(char *buf, size_t size, struct task_struct *task,
		       long pid)
{
	struct mm_struct *mm = task->mm;
	struct task_struct *child;
	struct list_head *list;
	struct list_head *head;
	long result = -ESRCH;

	if (!task || pid <= 0 || !buf)
		return -EINVAL;

	// Search amongst child tasks if we are not matching
	if (task->pid != pid) {
		head = &task->children;
		for (list = head->next; list != head; list = list->next) {
			child = list_entry(list, struct task_struct, sibling);
			result = snprint_task_info(buf, size, child, pid);
		}
		return result;
	}

	// Print basic task info
	snprintf(buf, size, "%s[%u] %s\n", buf, task->pid, task->comm);

	// If no memory management info is available, we're done.
	if (!mm)
		return 0;

	// Print memory layout info
	snprintf(buf, size, "%sCode: %lx-%lx, Data: %lx-%lx\n", buf,
		 mm->start_code, mm->end_code, mm->start_data, mm->end_data);
	snprintf(buf, size, "%sHeap: %lx-%lx, Mmap: %lx, Stack: %lx\n",
		 buf, mm->start_brk, mm->brk, mm->mmap_base, mm->start_stack);

	// Print VMA info
	result = snprint_task_vmas(buf, size, task);
#ifdef DEBUG_ON
	printk(KERN_INFO "VMA result: %ld\n", result);
#endif
	// Print the code segment digest
	result = snprint_task_digest(buf, size, task);
#ifdef DEBUG_ON
	printk(KERN_INFO "Digest result: %ld\n", result);
#endif
	// Print the process command line
	result = snprint_task_cmdline(buf, size, task);
#ifdef DEBUG_ON
	printk(KERN_INFO "Cmdline result: %lu\n", result);
#endif
	// Print the environment variables
	result = snprint_task_envvars(buf, size, task);
#ifdef DEBUG_ON
	printk(KERN_INFO "Envvar result: %lu\n", result);
#endif

	return result;
}


static ssize_t pslist_all_show(struct kobject *kobj,
			       struct kobj_attribute *attr, char *buf)
{
	snprintf(buf, PAGE_SIZE, "Process tree:\n");
	snprint_pslist(buf, PAGE_SIZE, &init_task, 0);
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
	snprint_task_info(buf, PAGE_SIZE, &init_task, by_pid_request);
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
