#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/version.h>
#include <linux/syscalls.h>
#include <linux/security.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/kallsyms.h>

//include for the read/write semaphore
#include <linux/rwsem.h>

//needed for set_memory_rw
#include <asm/cacheflush.h>

#include "offsets.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,0,0)
#error "NOT YET SUPPORTED"
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
#define KERNEL_VERSION_4
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0)
#define KERNEL_VERSION_3_7
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
#define KERNEL_VERSION_3_5
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
#define KERNEL_VERSION_3
#elif
#error "KERNEL 2 is not yet supported"
#endif


//These two definitions and the one for set_addr_rw and ro are from
// http://stackoverflow.com/questions/2103315/linux-kernel-system-call-hooking-example
#define GPF_DISABLE() write_cr0(read_cr0() & (~0x10000))
#define GPF_ENABLE() write_cr0(read_cr0() | 0x10000)

#if defined(KERNEL_VERSION_3_5) || defined(KERNEL_VERSION_3_7) || defined(KERNEL_VERSION_4)
// > Linux >3.5 uses a struct kuid_t wrapper for uid_t and INVALID_UID is now the struct for (-1) -- see include/linux/uidgid.h .. apparently they do this so the compiler can help do some additional checks, cool stuff

#define CURRENT_UID() current_uid()
#define GET_UID(_x) _x.val

#elif defined(_LINUX_VERSION_3)

#define CURRENT_UID() current_uid()
#define GET_UID(_x) _x

#endif


#if defined(KERNEL_VERSION_4) || defined(KERNEL_VERSION_3_7) 
#define PUTNAME_NOT_EXPORTED

//current_uid returns the kuid -- see include/linux/cred.h

//it appears that putname and getname are no longer exported, so will have to use the configure kallsyms trick
// This is true since 3.7 it appears
typedef void (*fs_putname_func)(struct filename*);
static fs_putname_func sym_putname = NULL;

typedef struct filename* (*fs_getname_func)(const char __user*);
static fs_getname_func sym_getname= NULL;

#endif

//task_struct is defined in include/linux/sched.h

//Here is a function to get the filename given a fd -- from
// http://stackoverflow.com/questions/8250078/how-can-i-get-a-filename-from-a-file-descriptor-inside-a-kernel-module
#include <linux/fdtable.h>
char* getFilenameFromFD(unsigned int fd, char** pPage)
{
  char *tmp;
  char *pathname;
  struct file *file;
  struct path path;

  if (current->files == NULL) 
  {
    return (NULL);
  }

  spin_lock(&(current->files->file_lock));
  file = fcheck_files(current->files, fd);
  if (file == NULL) 
  {
    spin_unlock(&(current->files->file_lock));
    return NULL;
  }

  path = file->f_path;
  path_get(&file->f_path);
  spin_unlock(&(current->files->file_lock));

  tmp = (char *)__get_free_page(GFP_TEMPORARY);

  if (tmp == NULL) 
  {
    path_put(&path);
    return (NULL);
  }

  pathname = d_path(&path, tmp, PAGE_SIZE);
  path_put(&path);

  if (IS_ERR(pathname)) 
  {
    free_page((unsigned long)tmp);
    return (NULL);
  }

  if (pPage != NULL)
  {
    *pPage = tmp;
  }

  return (pathname);
 
  //dont forget to free the page afterwards
  //free_page((unsigned long)tmp);
}



//seed@ubuntu:~/Downloads/hw5$ sudo grep sys_call_table /proc/kallsyms
//c1513160 R sys_call_table
static long* sys_call_table = NULL;

typedef asmlinkage long (* sys_open_func_ptr)(const char __user* filename, int flags, int mode);
sys_open_func_ptr sys_open_orig = NULL;

typedef asmlinkage long (* sys_read_func_ptr)(unsigned int fd, char __user* buf, size_t count);
sys_read_func_ptr sys_read_orig = NULL;

typedef asmlinkage long (* sys_write_func_ptr)(unsigned int fd, char __user* buf, size_t count);
sys_write_func_ptr sys_write_orig = NULL;

typedef asmlinkage long (* sys_close_func_ptr)(unsigned int fd);
sys_close_func_ptr sys_close_orig = NULL;

static struct rw_semaphore myrwsema; 

/** RULES **/
#define MAX_FILENAME_LEN 128
#define MAX_RULES_IN_POLICY 10

typedef struct _label
{
  uid_t owner_uid;
  int bSecret;
  char filename[MAX_FILENAME_LEN];
} Label;

Label theLabels[MAX_RULES_IN_POLICY];

/** From adore.c **/
#ifndef PID_MAX
#define PID_MAX 0x8000
#endif

static char hidden_procs[PID_MAX/8+1];

inline void hide_proc(pid_t x)
{
  if (x >= PID_MAX || x == 1)
  {
    return;
  }
  hidden_procs[x/8] |= 1<<(x%8);
}

inline void unhide_proc(pid_t x)
{
  if (x >= PID_MAX)
  {
    return;
  }
  hidden_procs[x/8] &= ~(1<<(x%8));
}

inline char is_invisible(pid_t x)
{
  if (x >= PID_MAX)
  {
    return (0);
  }
  return hidden_procs[x/8]&(1<<(x%8));
}

/** END FROM adore.c **/

/** My hooked versions of the system calls **/
//don't forget the asmlinkage declaration. This is a particular calling convention
asmlinkage long my_sys_open(const char __user* filename, int flags, int mode)
{
  long ret = 0;

#ifdef PUTNAME_NOT_EXPORTED
  //Linux >3.7 now uses a struct filename so getname and putname uses struct filenames -- see include/linux/fs.h
  struct filename* tmpFN = NULL;
#else
  //Nothing to do there
#endif
  const char* tmp = NULL;

  int i = 0;
  int bAllowed = 1;

  down_read(&myrwsema);

  //get the filename from userspace memory
#ifdef PUTNAME_NOT_EXPORTED
  tmpFN = sym_getname(filename);
  if (IS_ERR(tmpFN))
  {
    tmp = (char *)tmpFN; //ERR_PTR should be generic so we can cast it
  }
  else
  {
    tmp = tmpFN->name;
  }
#else
  tmp = getname(filename);
#endif

  //if there wasn't an error then we continue
  if (!IS_ERR(tmp))
  {
    //Now that we have the filename, we should see if we have permissions to open the file.
    for (i = 0; i < MAX_RULES_IN_POLICY; i++)
    {
      if (theLabels[i].owner_uid == -1)
      {
        continue;
      }
      if (strcmp(tmp, theLabels[i].filename) == 0) //if filenames match
      {
        bAllowed = 0; //if there is a rule for the filename - then default to deny
        if (theLabels[i].bSecret)  //if its secret
        {
          if (theLabels[i].owner_uid == GET_UID(current_uid())) 
          {
            bAllowed = 1; //its allowed since the uids match
            break;
          }
          else
          {
            bAllowed = 0; //not allowed since the uids don't match
          }
        }
        else 
        {
          //this should not happen, so right now default back to allow
          bAllowed = 1;
        }
      }
    }
    //we are done with the filename so lets free the memory
#ifdef PUTNAME_NOT_EXPORTED
    sym_putname(tmpFN);
    tmpFN = NULL;
    tmp = NULL;
#else
    putname(tmp);
    tmp = NULL;
#endif
  }
   
  if (bAllowed)
  {
    ret = sys_open_orig(filename, flags, mode);
  }
  else 
  {
    ret = -1;
  }

  //release the reader lock (or one of them) right before the return
  // to limit the possibility of unloading the module
  // when there is still code to be executed
  up_read(&myrwsema);

  return (ret);
}

asmlinkage long my_sys_read(unsigned int fd, char __user* buf, size_t count)
{
  long ret = 0;
  /** Sample
  char* filename = NULL;
  char* filenamePage = NULL;
  char* tmp = NULL;
  **/

  down_read(&myrwsema);

  //we want to first read the contents
  ret = sys_read_orig(fd, buf, count);

  /** Sample
    filename = getFilenameFromFD(fd, &filenamePage);
    tmp = strrchr(filename, '/');
    if (tmp == NULL)
    {
      tmp = filename;
    }
    else
    {
      tmp++;
    }

    free_page((unsigned long)filenamePage);
  **/

  up_read(&myrwsema);
  return (ret);
}

/** The following functions are needed to hook the system call table **/

int set_addr_rw(unsigned long addr)
{
  unsigned int level; 
  pte_t* pte = lookup_address(addr, &level);
  if (pte == NULL)
  {
    return (-1);
  }

  pte->pte |= _PAGE_RW;

  return (0);
}

int set_addr_ro(unsigned long addr)
{
  unsigned int level; 
  pte_t* pte = lookup_address(addr, &level);
  if (pte == NULL)
  {
    return (-1);
  }

  pte->pte = pte->pte & ~_PAGE_RW;

  return (0);
}

/** Helper functions **/
void printkRules(void)
{
  size_t i = 0;
  for (i = 0; i < MAX_RULES_IN_POLICY; i++)
  {
    if (theLabels[i].owner_uid != -1)
    {
      printk(KERN_INFO "Rule [%d] : UID [%d] : file [%s] has label <%d>\n", i, theLabels[i].owner_uid,  theLabels[i].filename, theLabels[i].bSecret);
    }  
  }
}

int init_module(void)
{
  size_t i = 0;

  
  #if defined(PUTNAME_NOT_EXPORTED)
  sym_putname = (fs_putname_func)kallsyms_lookup_name("putname");
  if (sym_putname == NULL)
  {
    sym_putname = (fs_putname_func)FS_PUTNAME_ADDR;
  }

  if (sym_putname == NULL)
  {
    printk(KERN_INFO "RefMon: Couldn't set putname. Did configure run successfully?\n");
    return (-1);
  }

  sym_getname = (fs_getname_func)kallsyms_lookup_name("getname");
  if (sym_getname == NULL)
  {
    sym_getname = (fs_getname_func)FS_GETNAME_ADDR;
  }

  if (sym_getname == NULL)
  {
    printk(KERN_INFO "RefMon: Couldn't set getname. Did configure run successfully?\n");
    return (-1);
  }
  #endif

  sys_call_table = (long*)kallsyms_lookup_name("sys_call_table");
  if (sys_call_table == NULL)
  {
    sys_call_table = (long*)SYS_CALL_TABLE_ADDR;
  }

  if (sys_call_table == NULL)
  {
    printk(KERN_INFO "RefMon: Don't know where the sys_call_table is. Did configure run successfully?\n");
    return (-1);
  }

  //FROM adore.c
  memset(hidden_procs, 0, sizeof(hidden_procs));

  //sys_close is exported, so we can use it to make sure we have the
  // right address for sys_call_table
  //printk(KERN_INFO "sys_close is at [%p] == [%p]?.\n", sys_call_table[__NR_close], &sys_close);
  if (sys_call_table[__NR_close] != (long)(&sys_close))
  {
    printk(KERN_INFO "Seems like we don't have the right addresses [0x%08lx] vs [%p]\n", sys_call_table[__NR_close], &sys_close);
    return (-1); 
  }

  //initialize the rules 
  for (i = 0; i < MAX_RULES_IN_POLICY; i++)
  {
    theLabels[i].owner_uid = -1;
    theLabels[i].bSecret = 0;
    theLabels[i].filename[0] = '\0';
  }

  //Default Policy
  theLabels[0].owner_uid = 0;
  theLabels[0].bSecret = 1;
  strcpy(theLabels[0].filename, "secret.txt");

  theLabels[1].owner_uid = 1000;
  theLabels[1].bSecret = 1;
  strcpy(theLabels[1].filename, "secret2.txt");

  //initialize the rw semahore
  init_rwsem(&myrwsema);

  //make sure the table is writable
  set_addr_rw( (unsigned long)sys_call_table);
  //GPF_DISABLE();

  printk(KERN_INFO "Saving sys_open @ [0x%08lx]\n", sys_call_table[__NR_open]);
  sys_open_orig = (sys_open_func_ptr)(sys_call_table[__NR_open]);
  sys_call_table[__NR_open] = (long)&my_sys_open;

  printk(KERN_INFO "Saving sys_read @ [0x%08lx]\n", sys_call_table[__NR_read]);
  sys_read_orig = (sys_read_func_ptr)(sys_call_table[__NR_read]);
  sys_call_table[__NR_read] = (long)&my_sys_read;

  set_addr_ro( (unsigned long)sys_call_table);
  //GPF_ENABLE();

  return (0);
}

void cleanup_module(void)
{
  if (sys_open_orig != NULL)
  {
    set_addr_rw( (unsigned long)sys_call_table);

    printk(KERN_INFO "Restoring sys_open\n");
    sys_call_table[__NR_open] = (long)sys_open_orig; 

    printk(KERN_INFO "Restoring sys_read\n");
    sys_call_table[__NR_read] = (long)sys_read_orig; 

    set_addr_ro( (unsigned long)sys_call_table);
  }

  //after the system call table has been restored - we will need to wait
  printk(KERN_INFO "Checking the semaphore as a write ...\n");
  down_write(&myrwsema);
  
  printk(KERN_INFO "Have the write lock - meaning all read locks have been released\n");
  printk(KERN_INFO " So it is now safe to remove the module\n");

  printk(KERN_INFO "The final rules were: \n");
  printkRules();
}

MODULE_LICENSE("GPL");
