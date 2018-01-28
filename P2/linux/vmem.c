/*
 * In the name of Allah
 * Sharif University of Technology
 * Department of Computer Engineering
 * Operating Systems course (40-424)
 * Project # 3
 * Part 2
 * Writing Virtual Memory Monitor Kernel Module
 *
 * Mohammadmahdi Faryabi:	93101951
 * Mohammadhosein A'lami:	94104401
 *
 * @file	vmem_monitor_module.c
 * @author	Mohammadmahdi Faryabi / Mohammadhosein A'lami
 * @date	Saturday Dey 30 1396
 * @brief	a Loadable Kernel Module (LKM) that will Monitor ALL process virtual memory allocation
 *          states and logs the changes in /var/log/kern.log file.
 *          this file can be read with dmesg bash command with super user access privilages
 */

#include <linux/module.h>		// added for creating a kernel module (kernel info macros).
#include <linux/kernel.h>		// added for specifing kernel message severity level.
#include <linux/init.h>			// added for using load and unload macros.
#include <linux/string.h>
#include <linux/dirent.h>
#include <linux/ctype.h>
#include <linux/zconf.h>
#include <linux/unistd.h>
#include <linux/delay.h>
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/timer.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");			// GNU public license v2 or later
MODULE_AUTHOR("Mohammadmahdi Faryabi");
MODULE_AUTHOR("Mohammadhosein A'lami");
MODULE_DESCRIPTION("a Loadable Kernel Module (LKM) that will Monitor ALL process virtual memory\n"
				   "allocation states and logs the changes in /var/log/kern.log file.\n"
				   "this file can be read with dmesg bash command with super user access privilages\n");

MODULE_VERSION("1.0");

#define TRUE 1
#define FALSE 0
#define VMEM_INFO_LINE_IN_PROC_STATUS_FILE 16
#define MAX_PID_COUNT 32768
#define MONITOR_LOG_HEADER "---> [VMEM_MONITOR]"
#define REPORT_INTERVAL_MS 5000
#define FILE_BUFFER_SIZE 5000

// 32768

enum status {
    created, updated, deleted
};

typedef struct vmem_info_t {
    char name[50];
    unsigned int vmem_curr;
    unsigned int vmem_max;
    int changed_value;
    int new_process;
    int dead_process;
} vmem_info;


struct timer_list g_timer;

vmem_info *processes[MAX_PID_COUNT];






struct file *file_open(const char *path, int flags, int rights) {
    struct file *filp = NULL;
    mm_segment_t oldfs;
    int err = 0;

    oldfs = get_fs();
    set_fs(get_ds());
    filp = filp_open(path, flags, rights);
    set_fs(oldfs);
    if (IS_ERR(filp)) {
        err = PTR_ERR(filp);
        return NULL;
    }
    return filp;
}


void file_close(struct file *file) {
    filp_close(file, NULL);
}

int file_read(struct file *file, unsigned long long offset, unsigned char *data, unsigned int size) {
    mm_segment_t oldfs;
    int ret;

    oldfs = get_fs();
    set_fs(get_ds());

    ret = vfs_read(file, data, size, &offset);

    set_fs(oldfs);
    return ret;
}




void get_process_info(int pid) {
    // printk(KERN_INFO"%s[DEBUG] %s %d\n", MONITOR_LOG_HEADER, "getting process info", pid);
    char path[40], line[500], name[50], file_buffer[FILE_BUFFER_SIZE];
    struct file *proc_status_file;

    memset(file_buffer, NULL, FILE_BUFFER_SIZE);

    snprintf(path, 40, "/proc/%d/status", pid);

    proc_status_file = file_open(path, O_RDONLY, 0);

    if (proc_status_file == NULL) {
        printk(KERN_ALERT "%sfopen(%s, \"r\")\n\n", MONITOR_LOG_HEADER, path);
        return;
    }
    // printk(KERN_INFO"%s[DEBUG] %s %d\n", MONITOR_LOG_HEADER, "BEFORE READ", pid);
    int ret = file_read(proc_status_file, 0, file_buffer, FILE_BUFFER_SIZE);
    // printk(KERN_INFO"%s[DEBUG] %s %d\n", MONITOR_LOG_HEADER, "BEFORE READ", pid);
    file_close(proc_status_file);


    if (processes[pid] == NULL) {
        // printk(KERN_INFO"%s[DEBUG] %s %d\n", MONITOR_LOG_HEADER, "sizeof(vmem_info)", sizeof(vmem_info));
        processes[pid] = (vmem_info *) kmalloc(sizeof(vmem_info), GFP_NOWAIT);
        processes[pid]->new_process = TRUE;
        processes[pid]->changed_value = FALSE;
        processes[pid]->dead_process = FALSE;
    }

    // printk(KERN_INFO"%s[DEBUG] %s %d\n", MONITOR_LOG_HEADER, "after allocation", sizeof(vmem_info));


    // printk(KERN_INFO"%s[DEBUG] %s %s\n", MONITOR_LOG_HEADER, "READ DATA: ", file_buffer);

    int string_cursor = 0;


    string_cursor += sscanf(file_buffer + string_cursor, "%*s%s", name);

    // printk(KERN_INFO"%s[DEBUG] %s %s\n", MONITOR_LOG_HEADER, "process name", name);



    strcpy(processes[pid]->name, name);

    char temp;
    int skip_line = VMEM_INFO_LINE_IN_PROC_STATUS_FILE;

    while (skip_line) {
        string_cursor += sscanf(file_buffer + string_cursor, "%c", &temp);
        if (temp == '\n') skip_line--;
    }

    unsigned int vmem_max, vmem_curr;

    string_cursor += sscanf(file_buffer + string_cursor, "%*s%d%*s", &vmem_max);
    string_cursor += sscanf(file_buffer + string_cursor, "%*s%d%*s", &vmem_curr);

    if (processes[pid]->vmem_curr != vmem_curr || processes[pid]->vmem_max != vmem_max) processes[pid]->changed_value = TRUE;

    processes[pid]->vmem_curr = vmem_curr;
    processes[pid]->vmem_max = vmem_max;

    // printk(KERN_INFO"%s[DEBUG] %s\n", MONITOR_LOG_HEADER, "end of get_process_info");
}



void log_changes(int pid, enum status what) {
    vmem_info *proc = processes[pid];
    switch (what) {
        case created:
            printk(KERN_INFO
            "%s[PROCESS CREATED][NAME: %s][PID: %d][VMEM: %d][MAX_VMEM: %d]", MONITOR_LOG_HEADER, proc->name, pid, proc->vmem_curr, proc->vmem_max);
            break;
        case deleted:
            printk(KERN_INFO
            "%s[PROCESS DELETED][NAME: %s][PID: %d][VMEM: %d][MAX_VMEM: %d]", MONITOR_LOG_HEADER, proc->name, pid, proc->vmem_curr, proc->vmem_max);
            break;
        case updated:
            printk(KERN_INFO
            "%s[PROCESS UPDATED][NAME: %s][PID: %d][VMEM: %d][MAX_VMEM: %d]", MONITOR_LOG_HEADER, proc->name, pid, proc->vmem_curr, proc->vmem_max);
            break;
        default:
            printk(KERN_INFO
            "%s[PROCESS WTF????][NAME: %s][PID: %d][VMEM: %d][MAX_VMEM: %d]", MONITOR_LOG_HEADER, proc->name, pid, proc->vmem_curr, proc->vmem_max);
    }

}


void _TimerHandler(unsigned long data) {

    printk(KERN_INFO"%s[PERFORMING CHECK]\n", MONITOR_LOG_HEADER);
    int pid, i;
    char path[40];
    struct file * proc_directory;
    memset(path, NULL, 40);

    for (pid = 0; pid < MAX_PID_COUNT; ++pid) {

        sprintf(path, "/proc/%d/status", pid);
        // printk(KERN_INFO"%s[DEBUG] %s\n", MONITOR_LOG_HEADER, path);
        if (processes[pid] != NULL) {
            processes[pid]->dead_process = TRUE;
            // printk(KERN_INFO"%s[DEBUG] %s\n", MONITOR_LOG_HEADER, "sth is not null!");
        }

        proc_directory = file_open(path, O_RDONLY, 0);
        if (proc_directory == NULL) {
            // printk(KERN_INFO"%s[DEBUG] %s\n", MONITOR_LOG_HEADER, "sth is null! :D");
            // printk(KERN_INFO"%s[DEBUG] %s %d\n", MONITOR_LOG_HEADER, "no process with pid", pid);
            continue;
        }
        // printk(KERN_INFO"%s[DEBUG] %s %d\n", MONITOR_LOG_HEADER, "FOUND ONE!", pid);
        file_close(proc_directory);
        get_process_info(pid);
    }

    for (i = 0; i < MAX_PID_COUNT; ++i) {
        if (processes[i] != NULL) {
            if (processes[i]->dead_process == TRUE) {
                log_changes(i, deleted);
                kfree(processes[i]);
                processes[i] = NULL;
            } else if (processes[i]->new_process == TRUE) {
                log_changes(i, created);
                processes[i]->new_process = FALSE;
                processes[i]->changed_value = FALSE;
            } else if (processes[i]->changed_value == TRUE) {
                log_changes(i, updated);
                processes[i]->changed_value = FALSE;
            }
        }
    }

    /*Restarting the timer...*/
    mod_timer( &g_timer, jiffies + msecs_to_jiffies(REPORT_INTERVAL_MS));
 
    printk(KERN_INFO"%s[CHECK COMPLETED!]\n", MONITOR_LOG_HEADER);
}

static int __init

vmem_monitor_lkm_start(void) {
    memset(processes, NULL, sizeof(processes));

    printk(KERN_INFO"%s[BOOTING UP]\n", MONITOR_LOG_HEADER);

    /*Starting the timer.*/
    setup_timer(&g_timer, _TimerHandler, 0);
    mod_timer( &g_timer, jiffies + msecs_to_jiffies(REPORT_INTERVAL_MS));

    // this function will be called upon loading the module in kernel.

    return 0;
}

/*
 * kernel module severity levels defined in linux/kernel.h:
 * 1 -> KERN_EMERG: used for emergency messages that usually produce a crash.
 * 2 -> KERN_ALERT: a message indicating that immediate action is required.
 * 3 -> KERN_CRIT: critical situation related to hardware/software malfunction.
 * 4 -> KERN_ERR: error conditions. usually device drivers issue this type of message to indicate hardware problems.
 * 5 -> KERN_WARNING: a problematic situation not causing serious system problems.
 * 6 -> KERN_NOTICE: normal situations worth noticing.
 * 7 -> KERN_INFO: information messages about anything important.
 * 8 -> KERN_DEBUG: used for debugging messages.
 */
static void __exit

vmem_monitor_lkm_end(void) {
    // cleanup function.
    // this function will be called upon unloading the module from kernel.
    int i;
    for (i = 0; i < MAX_PID_COUNT; ++i) {
        if (processes[i] != NULL) {
            kfree(processes[i]);
        }
    }

    del_timer(&g_timer);
    printk(KERN_INFO"%s[SHUTTING DOWN]\n", MONITOR_LOG_HEADER);
}

// assigning the functions to be called upon loading/unloading the module.
module_init(vmem_monitor_lkm_start);
module_exit(vmem_monitor_lkm_end);
