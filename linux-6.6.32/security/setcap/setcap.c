/*  
 *  setcap.c - The simplest kernel module disable some root capabilities.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/security.h>
#include <linux/capability.h>
#include <linux/lsm_hooks.h>
#include <linux/cred.h>
#include <linux/user_namespace.h>
#include <linux/delay.h>
#include <linux/lsm_hooks.h>
#include <linux/sysctl.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Pavel V Samsonov <pvsamsonov76@gmail.com>");

#define SETCAP_BUFLEN	256

char sysctl_disabled_caps[SETCAP_BUFLEN] = "";
char sysctl_enabled_caps[SETCAP_BUFLEN] = "";
int sysctl_lock = 0;
int sysctl_disabled_caps_gid = 0;
int sysctl_enabled_caps_gid = 0;

char disabled_caps[SETCAP_BUFLEN] = "";
char enabled_caps[SETCAP_BUFLEN] = "";
int lock = 0;
int disabled_caps_gid = 0;
int enabled_caps_gid = 0;

int disabled[CAP_LAST_CAP + 1];
int enabled[CAP_LAST_CAP + 1];

int setcap_cap_capable(const struct cred *cred, struct user_namespace *targ_ns,
	int cap, unsigned int audit)
{
    kgid_t disabled_gid;
    kgid_t enabled_gid;
    disabled_gid.val = disabled_caps_gid;
    enabled_gid.val = enabled_caps_gid;

    if (disabled[cap] && in_group_p(disabled_gid))
	return -EPERM;

    if (enabled[cap] && in_group_p(enabled_gid))
	return -EGRANTED;

    return 0;
}

static int lock_changed(struct ctl_table *ctl, int write,
                           void __user *buffer, size_t *lenp, loff_t *ppos)
{
    int ret;

    ret = proc_dointvec(ctl, write, buffer, lenp, ppos);
    
    if (write)
    {
	if (lock == 0) 
	    lock = sysctl_lock;
	else
	    sysctl_lock = lock;
    }

    return ret;
}

static int disabled_caps_gid_changed(struct ctl_table *ctl, int write,
                           void __user *buffer, size_t *lenp, loff_t *ppos)
{
    int ret;

    ret = proc_dointvec(ctl, write, buffer, lenp, ppos);
    
    if (write)
    {
	if (lock == 0)
	    disabled_caps_gid = sysctl_disabled_caps_gid;
	else
	    sysctl_disabled_caps_gid = disabled_caps_gid;
    }

    return ret;
}

static int enabled_caps_gid_changed(struct ctl_table *ctl, int write,
                           void __user *buffer, size_t *lenp, loff_t *ppos)
{
    int ret;

    ret = proc_dointvec(ctl, write, buffer, lenp, ppos);
    
    if (write)
    {
	if (lock == 0)
	    enabled_caps_gid = sysctl_enabled_caps_gid;
	else
	    sysctl_enabled_caps_gid = enabled_caps_gid;
    }

    return ret;
}

static int disabled_caps_changed(struct ctl_table *ctl, int write,
                           void __user *buffer, size_t *lenp, loff_t *ppos)
{
    int ret;
    unsigned int i;
    unsigned int cap;
    char* tok;
    char* str;
    char* ch = ",";
    char temp[SETCAP_BUFLEN];

    ret = proc_dostring(ctl, write, buffer, lenp, ppos);

    if (write)
    {
	if (lock == 0)
	{
	    strncpy(disabled_caps, sysctl_disabled_caps, sizeof(disabled_caps));

	    for (i = 0; i <= CAP_LAST_CAP; i++)
	    {
		disabled[i] = 0;
	    }
            printk(KERN_INFO "Setcap: reset \"disabled\" setcap settings \n");

	    str = disabled_caps;

	    i = 1;
	    temp[0] = '\0';
	    sysctl_disabled_caps[0] = '\0';
	    
	    while((tok=strsep(&str,",")) != NULL)
	    {
		if (kstrtouint(tok, 0, &cap) != 0) continue;
		if (cap_valid(cap))
		{

		    printk(KERN_INFO "Setcap: disabling capability %u\n", cap);
		    disabled[cap] = 1;

		    /* Deleting garbage from strings */
		    if (i == 1) ch = "";
		    else ch = ",";
		    sprintf(sysctl_disabled_caps, "%s%s%d", temp, ch, cap);
		    strncpy(temp, sysctl_disabled_caps, sizeof(temp));
		    i++;
		}
	    }
	    strncpy(disabled_caps, sysctl_disabled_caps, sizeof(disabled_caps));
	}
	else
	{
	    strncpy(sysctl_disabled_caps, disabled_caps, sizeof(sysctl_disabled_caps));
	}
    }

    return ret;
}

static int enabled_caps_changed(struct ctl_table *ctl, int write,
                           void __user *buffer, size_t *lenp, loff_t *ppos)
{
    int ret;
    unsigned int i;
    unsigned int cap;
    char* tok;
    char* str;
    char* ch = ",";
    char temp[SETCAP_BUFLEN];

    ret = proc_dostring(ctl, write, buffer, lenp, ppos);

    if (write)
    {
	if (lock == 0)
	{
	    strncpy(enabled_caps, sysctl_enabled_caps, sizeof(enabled_caps));

	    for (i = 0; i <= CAP_LAST_CAP; i++)
	    {
		enabled[i] = 0;
	    }
            printk(KERN_INFO "Setcap: reset \"enabled\" setcap settings \n");

	    str = enabled_caps;

	    i = 1;
	    temp[0] = '\0';
	    sysctl_enabled_caps[0] = '\0';

	    while((tok=strsep(&str,",")) != NULL)
	    {
		if (kstrtouint(tok, 0, &cap) != 0) continue;
		if (cap_valid(cap))
		{
		    printk(KERN_INFO "Setcap: allways capability %u\n", cap);
		    enabled[cap] = 1;

		    /* Deleting garbage from strings */
		    if (i == 1) ch = "";
		    else ch = ",";
		    sprintf(sysctl_enabled_caps, "%s%s%d", temp, ch, cap);
		    strncpy(temp, sysctl_enabled_caps, sizeof(temp));
		    i++;
		}
	    }
	    strncpy(enabled_caps, sysctl_enabled_caps, sizeof(enabled_caps));
	}
	else
	{
	    strncpy(sysctl_enabled_caps, enabled_caps, sizeof(sysctl_enabled_caps));
	}
    }

    return ret;
}

static struct ctl_table setcap_table[] = {
    {
	.procname	= "disabled_caps",
	.data		= &sysctl_disabled_caps,
	.maxlen		= sizeof(sysctl_disabled_caps),
	.mode		= 0660,
	.proc_handler	= disabled_caps_changed,
    },
    {
	.procname	= "enabled_caps",
	.data		= &sysctl_enabled_caps,
	.maxlen		= sizeof(sysctl_enabled_caps),
	.mode		= 0660,
	.proc_handler	= enabled_caps_changed,
    },
    {
	.procname	= "disabled_caps_gid",
	.data		= &sysctl_disabled_caps_gid,
	.maxlen		= sizeof(int),
	.mode		= 0600,
	.proc_handler	= disabled_caps_gid_changed,
    },
    {
	.procname	= "enabled_caps_gid",
	.data		= &sysctl_enabled_caps_gid,
	.maxlen		= sizeof(int),
	.mode		= 0600,
	.proc_handler	= enabled_caps_gid_changed,
    },
    {
	.procname	= "lock",
	.data		= &sysctl_lock,
	.maxlen		= sizeof(int),
	.mode		= 0600,
	.proc_handler	= lock_changed,
    },
    { }
};

static struct ctl_table_header *setcap_sysctl_header;

static struct security_hook_list capability_hooks_list[] = 
{
    LSM_HOOK_INIT(capable, setcap_cap_capable),
};

static __init int init_setcap(void)
{
    unsigned int i;
    unsigned int cap;
    char* tok;
    char* str;


    for (i = 0; i <= CAP_LAST_CAP; i++)
    {
	disabled[i] = 0;
	enabled[i] = 0;
    }

    str = sysctl_disabled_caps;

    while((tok=strsep(&str,",")) != NULL)
    {
	if (kstrtouint(tok, 0, &cap) != 0) continue;
	if (cap_valid(cap))
	{
	    printk(KERN_INFO "Setcap: disabling capability %u\n", cap);
	    disabled[cap] = 1;
	}
    }

    str = sysctl_enabled_caps;

    while((tok=strsep(&str,",")) != NULL)
    {
	if (kstrtouint(tok, 0, &cap) != 0) continue;
	if (cap_valid(cap))
	{
	    printk(KERN_INFO "Setcap: allways on capability %u\n", cap);
	    enabled[cap] = 1;
	}
    }


    setcap_sysctl_header = register_sysctl("setcap", setcap_table);

    security_add_hooks(capability_hooks_list, ARRAY_SIZE(capability_hooks_list), "setcap");
    printk(KERN_INFO "Security module setcap up\n");

    return 0;
}

void cleanup_setcap(void)
{
#ifdef CONFIG_SECURITY_SELINUX_DISABLE
    security_delete_hooks(capability_hooks_list, ARRAY_SIZE(capability_hooks_list));
#endif
    printk(KERN_INFO "Security module setcap unloaded\n");
}

module_init(init_setcap);
module_exit(cleanup_setcap);

