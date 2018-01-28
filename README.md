# Reference Monitor Example

This is the base source for a simple interpositioning based reference monitor. The main idea is to quickly show that there really isn't much difference between a rootkit and a reference monitor. In fact, a rootkit is a reference monitor -- it still enforces a policy.

The main idea behind the assignment is to have the implement a reference monitor that can enforce an information flow based policy. The *open* system call has already been hooked (interpositioned) as a quick example. Some sample output can be seen below.

Running the base module.

	NYUISP_RefMon$ more secret.txt
	This file contains a secret.
	NYUISP_RefMon$ more secret2.txt
	This file contains another secret.
	NYUISP_RefMon$ sudo insmod refmon.ko
	NYUISP_RefMon$ more secret.txt
	more: cannot open secret.txt: Operation not permitted
	NYUISP_RefMon$ more secret2.txt
	This file contains another secret.
	NYUISP_RefMon$ sudo rmmod refmon.ko
	NYUISP_RefMon$ more secret.txt
	This file contains a secret.
	NYUISP_RefMon$ more secret2.txt
	This file contains another secret.

The output from dmesg (kern.log) shows:

	[ 3289.099283] Saving sys_open @ [0xc11de6e0]
	[ 3289.099286] Saving sys_read @ [0xc11e00a0]
	[ 3300.809692] Restoring sys_open
	[ 3300.809695] Restoring sys_read
	[ 3300.809696] Checking the semaphore as a write ...
	[ 3300.813073] Have the write lock - meaning all read locks have been released
	[ 3300.813074]  So it is now safe to remove the module
	[ 3300.813075] The final rules were: 
	[ 3300.813076] Rule [0] : UID [0] : file [secret.txt] has label <1>
	[ 3300.813078] Rule [1] : UID [1000] : file [secret2.txt] has label <1>
	[ 3315.729899] Saving sys_open @ [0xc11de6e0]
	[ 3315.729902] Saving sys_read @ [0xc11e00a0]
	[ 3332.810003] Restoring sys_open
	[ 3332.810006] Restoring sys_read
	[ 3332.810007] Checking the semaphore as a write ...
	[ 3332.812942] Have the write lock - meaning all read locks have been released
	[ 3332.812944]  So it is now safe to remove the module

