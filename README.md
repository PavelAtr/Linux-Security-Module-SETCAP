# Linux-Security-Module-SETCAP
Creates files in the /proc/sys/setcap file system branch to manage system capabilities(7).

inux Security Module "setcap". Enabled when compiling the kernel with the build option CONFIG_SETCAP=y. Creates files in the /proc/sys/setcap file system branch to manage system capabilities(7):
$ ls -la /proc/sys/setcap/
total 0
dr-xr-xr-x. 1 root root 0 Jun 12 15:33 .
dr-xr-xr-x. 1 root root 0 Jun 12 15:32 ..
-rw-rw----. 1 root root 0 Jun 12 15:33 disabled_caps
-rw-------. 1 root root 0 Jun 12 15:37 disabled_caps_gid
-rw-rw----. 1 root root 0 Jun 12 15:34 enabled_caps
-rw-------. 1 root root 0 Jun 12 15:34 enabled_caps_gid
-rw-------. 1 root root 0 Jun 12 15:37 lock
As you can see from the permissions, members of the root group can disable and enable capabilities; only the root user can lock and set groups.
For example the command
# sysctl -w setcap.disabled_caps=0,1,2,3
 will disable the system capabilities CAP_CHOWN(0), CAP_DAC_OVERRIDE(1), CAP_DAC_READ_SEARCH(2), CAP_FOWNER(3). When trying to use them, an -EPERM error occurs for any user in the sysctl setcap.disabled_caps_gid group (default 0).
Enabling capabilities for users who are members of the sysctl group setcap.enabled_caps_gid (default 0) works in a similar way.
If you use a lock
# sysctl -w setcap.lock=1
, then it will be impossible to change the behavior of the system until the next reboot
This security module can be used to limit system capabilities, to give a group of users elevated privileges, even creating a system with several superusers.

