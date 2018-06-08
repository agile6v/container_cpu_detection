/*
 * Copyright (C) agile6v
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libgen.h>
#include <string.h>
#include <errno.h>

#define DETECTION_TARGETS      "DETECTION_TARGETS"

#define MAXPATHLEN              4096

#define DETECTION_OK            0
#define DETECTION_ERROR        -1

#define PER_CPU_SHARES          1024

#define SET_SUBSYSTEM_INFO(subsystem_info, value) \
    subsystem_info.data = strdup(value); \
    subsystem_info.len = strlen(value);

#define DETECTION_MIN(val1, val2)  ((val1 > val2) ? (val2) : (val1))

#ifdef INJECT_DEBUG
#define DEBUG_LOG(...) do {                     \
                       fprintf(stderr, "%s@%d: ", __FILE__, __LINE__); \
                       fprintf(stderr, __VA_ARGS__);        \
                       fprintf(stderr, "\n");           \
                       } while(0)
#else
#define DEBUG_LOG(...)
#endif

#define d_string(str)     { sizeof(str) - 1, (char *) str }

typedef long (*glibc_sysconf)(int name);

typedef struct {
    int    len;
    char  *data;
} d_string_t;

typedef struct {
    d_string_t  root;
    d_string_t  path;
    d_string_t  mount_point;
} cgroup_subsystem_info;

static cgroup_subsystem_info cpu_subsystem;
static cgroup_subsystem_info cpuset_subsystem;

static d_string_t cpu_cfs_period  = d_string("/cpu.cfs_period_us");
static d_string_t cpu_cfs_quota   = d_string("/cpu.cfs_quota_us");
static d_string_t cpu_cfs_shares  = d_string("/cpu.shares");
static d_string_t cpu_cpuset_cpus = d_string("/cpuset.cpus");

static void __attribute__((constructor)) _init();
static void __attribute__((destructor)) _fini();

static glibc_sysconf _orig_sysconf;
static int detection_open;
static int detection_initialized;


static long orig_sysconf(int name)
{
    if (!_orig_sysconf) {
        _orig_sysconf = (glibc_sysconf)dlsym(RTLD_NEXT, "sysconf");
    }

    return _orig_sysconf(name);
}


static int is_detection_target()
{
    char exe[1024];
    char *base;
    ssize_t ret;

    ret = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (ret == DETECTION_ERROR) {
        return 0;
    }

    exe[ret] = 0;
    base = basename(exe);

    char *targets = getenv(DETECTION_TARGETS);
    if (targets) {
        char *target = strtok(targets, ":");

        while (target) {
            if (0 == strcmp(base, target)) {
                return 1;
            }

            target = strtok(NULL, ":");
        }
    }

    return 0;
}


static int set_subsystem_path(cgroup_subsystem_info *subsystem_info,
                              char *cgroup_path)
{
    int    len;
    char   buf[MAXPATHLEN + 1];

    if (subsystem_info->root.len != 0 && cgroup_path != NULL) {
        if (strcmp(subsystem_info->root.data, "/") == 0) {
            len = subsystem_info->mount_point.len;
            if (strcmp(cgroup_path, "/") != 0) {
                len += strlen(cgroup_path);
            }

            if (len > MAXPATHLEN) {
                DEBUG_LOG("The length of the cgroup path exceeds the maximum " \
                          "length of the path (%d) ", MAXPATHLEN);
                return DETECTION_ERROR;
            }

            if (strcmp(cgroup_path, "/") != 0) {
                len = sprintf(buf, "%s%s", subsystem_info->mount_point.data, cgroup_path);
            } else {
                len = sprintf(buf, "%s", subsystem_info->mount_point.data);
            }

            buf[len] = '\0';

            subsystem_info->path.data = strdup(buf);
            subsystem_info->path.len = len;

        } else if (strcmp(subsystem_info->root.data, cgroup_path) == 0) {
            subsystem_info->path = subsystem_info->mount_point;
        }
    }

    return DETECTION_OK;
}

static void detection_free(cgroup_subsystem_info *subsystem)
{
    int skip = (subsystem->mount_point.data == subsystem->path.data) ? 1 : 0;

    if (!skip && subsystem->mount_point.data != NULL) {
        free(subsystem->mount_point.data);
        subsystem->mount_point.data = NULL;
    }

    if (subsystem->path.data != NULL) {
        free(subsystem->path.data);
        subsystem->path.data = NULL;
    }

    if (subsystem->root.data != NULL) {
        free(subsystem->root.data);
        subsystem->root.data = NULL;
    }
}

static int detection_init()
{
    int mountid;
    int parentid;
    int major;
    int minor;
    char *p;
    char buf[MAXPATHLEN];
    char tmproot[MAXPATHLEN];
    char tmpmount[MAXPATHLEN];
    char fstype[MAXPATHLEN];
    FILE *mntinfo = NULL;
    FILE *cgroup = NULL;

    if (detection_initialized) {
        return DETECTION_OK;
    }

    /*
     * parse mountinfo file
     */
    mntinfo = fopen("/proc/self/mountinfo", "r");
    if (mntinfo == NULL) {
        DEBUG_LOG("Failed to open /proc/self/mountinfo, %s", strerror(errno));
        return DETECTION_ERROR;
    }

    while ((p = fgets(buf, MAXPATHLEN, mntinfo)) != NULL) {
        fstype[0] = '\0';

        char *s = strstr(p, " - ");
        if (s == NULL
            || sscanf(s, " - %s", fstype) != 1
            || strcmp(fstype, "cgroup") != 0)
        {
            continue;
        }

        if (strstr(p, "cpuset") != NULL) {
            int matched = sscanf(p, "%d %d %d:%d %s %s",
                                 &mountid,
                                 &parentid,
                                 &major,
                                 &minor,
                                 tmproot,
                                 tmpmount);
            if (matched == 6) {
                SET_SUBSYSTEM_INFO(cpuset_subsystem.root, tmproot);
                SET_SUBSYSTEM_INFO(cpuset_subsystem.mount_point, tmpmount);
            } else {
                DEBUG_LOG("Incompatible string containing cgroup and cpuset: %s", p);
            }
        } else if (strstr(p, "cpu,cpuacct") != NULL) {
            int matched = sscanf(p, "%d %d %d:%d %s %s",
                                 &mountid,
                                 &parentid,
                                 &major,
                                 &minor,
                                 tmproot,
                                 tmpmount);
            if (matched == 6) {
                SET_SUBSYSTEM_INFO(cpu_subsystem.root, tmproot);
                SET_SUBSYSTEM_INFO(cpu_subsystem.mount_point, tmpmount);
            } else {
                DEBUG_LOG("Incompatible str containing cgroup and cpu,cpuacct: %s", p);
            }
        } else if (strstr(p, "cpuacct") != NULL) {
            /*
             * In order to maintain the matching order.
             * Actually this matching method is not strict enough,
             * need to refactor this matching method.
             */
        } else if (strstr(p, "cpu") != NULL) {
            int matched = sscanf(p, "%d %d %d:%d %s %s",
                                 &mountid,
                                 &parentid,
                                 &major,
                                 &minor,
                                 tmproot,
                                 tmpmount);
            if (matched == 6) {
                SET_SUBSYSTEM_INFO(cpu_subsystem.root, tmproot);
                SET_SUBSYSTEM_INFO(cpu_subsystem.mount_point, tmpmount);
            } else {
                DEBUG_LOG("Incompatible str containing cgroup and cpu: %s", p);
            }
        }
    }

    if (mntinfo != NULL) {
        fclose(mntinfo);
    }

    /*
     * parse cgroup file
     */
    cgroup = fopen("/proc/self/cgroup", "r");
    if (cgroup == NULL) {
        DEBUG_LOG("Failed to open /proc/self/cgroup, %s", strerror(errno));
        return DETECTION_ERROR;
    }

    while ((p = fgets(buf, MAXPATHLEN, cgroup)) != NULL) {
        char *controller;
        char *base;

        // Skip cgroup number
        strsep(&p, ":");

        // Get controller and base
        controller = strsep(&p, ":");
        base = strsep(&p, "\n");

        if (controller != NULL) {
            if (strstr(controller, "cpuset") != NULL) {
                set_subsystem_path(&cpuset_subsystem, base);
            } else if (strstr(controller, "cpu,cpuacct") != NULL) {
                set_subsystem_path(&cpu_subsystem, base);
            } else if (strstr(controller, "cpuacct") != NULL) {
                /*
                 * In order to maintain the matching order.
                 * Actually this matching method is not strict enough,
                 * need to refactor this matching method.
                 */
            } else if (strstr(controller, "cpu") != NULL) {
                set_subsystem_path(&cpu_subsystem, base);
            }
        }
    }

    if (cgroup != NULL) {
        fclose(cgroup);
    }

    if (cpuset_subsystem.root.data == NULL || cpu_subsystem.root.data == NULL) {
        DEBUG_LOG("Required cgroup subsystems not found");
        return DETECTION_ERROR;
    }

    detection_initialized = 1;

    return DETECTION_OK;
}


static inline float ceilf(float x)
{
    long r = x;

    if (r < 0) {
        return r;
    } else {
        return (r + ((r < x) ? 1 : 0));
    }
}


static int read_subsystem_file(const char *filename, char *value,
                               size_t value_len)
{
    FILE    *fp;
    int      ret;
    ssize_t  len;

    fp = fopen(filename, "r");
    if (!fp) {
        DEBUG_LOG("Failed to open %s\n", filename);
        return DETECTION_ERROR;
    }

    len = getline(&value, &value_len, fp);
    if (len == DETECTION_ERROR) {
        ret = DETECTION_ERROR;
    } else {
        ret = DETECTION_OK;
    }

    fclose(fp);

    return ret;
}


static char *cpuset_nexttok(const char *c)
{
    char *r = strchr(c+1, ',');
    if (r) {
        return r + 1;
    }
    return NULL;
}


static int cpuset_getrange(const char *c, int *a, int *b)
{
    return sscanf(c, "%d-%d", a, b);
}


static int read_cpu_subsystem_info(cgroup_subsystem_info *subsystem,
                                   d_string_t *filename, int *value, int cpuset)
{
    char *p;
    int   ret;
    char  buf[MAXPATHLEN + 1];
    char  full_path[MAXPATHLEN + 1];

    if (subsystem->path.data == NULL) {
        return DETECTION_ERROR;
    }

    if ((subsystem->path.len + filename->len) > MAXPATHLEN) {
        DEBUG_LOG("The subsystem filename exceeds normal range (%d + %d).",
                  subsystem->path.len, filename->len);
        return DETECTION_ERROR;
    }

    sprintf(full_path, "%s%s", subsystem->path.data, filename->data);

    ret = read_subsystem_file(full_path, buf, MAXPATHLEN);
    if (ret == DETECTION_ERROR) {
        DEBUG_LOG("Failed to read file : %s.", full_path);
        return ret;
    }

    if (cpuset) {
        ret = 0;
        for (p = buf; p; p = cpuset_nexttok(p)) {
            int a, b;

            if (cpuset_getrange(p, &a, &b) == 1) {
                ret++;
            } else {
                ret += (b - a) + 1;
            }
        }
        *value = ret;
    } else {
        *value = atoi(buf);
    }

    return DETECTION_OK;
}


static void _init()
{
    DEBUG_LOG("Detection: init.");
    detection_open = is_detection_target();
}

static void _fini()
{
    DEBUG_LOG("Detection: fini.");
    detection_free(&cpu_subsystem);
    detection_free(&cpuset_subsystem);
}


long sysconf(int name)
{
    int    ret;
    int    cpuset_count, quota, period, shares;
    int    quota_count = 0, share_count = 0;
    int    cpu_count, limit_count;

    DEBUG_LOG("Detection: sysconf is called.");
    if (!detection_open || name != _SC_NPROCESSORS_ONLN) {
        return orig_sysconf(name);
    }

    long total_cpu_num = orig_sysconf(name);

    do {
        ret = detection_init();
        if (ret == DETECTION_ERROR) {
            break;
        }

        ret = read_cpu_subsystem_info(&cpuset_subsystem, &cpu_cpuset_cpus,
                                      &cpuset_count, 1);
        if (ret == DETECTION_ERROR) {
            break;
        }

        cpu_count = limit_count = cpuset_count;

        ret = read_cpu_subsystem_info(&cpu_subsystem, &cpu_cfs_shares,
                                      &shares, 0);
        if (ret == DETECTION_ERROR) {
            break;
        }

        ret = read_cpu_subsystem_info(&cpu_subsystem, &cpu_cfs_quota,
                                      &quota, 0);
        if (ret == DETECTION_ERROR) {
            break;
        }

        ret = read_cpu_subsystem_info(&cpu_subsystem, &cpu_cfs_period,
                                      &period, 0);
        if (ret == DETECTION_ERROR) {
            break;
        }
    } while (0);

    if (ret == DETECTION_ERROR) {
        return total_cpu_num;
    }

    DEBUG_LOG("cpuset: %d, shares: %d, quota: %d, period: %d\n",
              cpuset_count, shares, quota, period);

    if (shares == PER_CPU_SHARES) {
        shares = -1;
    }

    if (quota > -1 && period > 0) {
        quota_count = ceilf((float) quota / (float) period);
    }

    if (shares > -1) {
        share_count = ceilf((float) shares / (float) PER_CPU_SHARES);
    }

    if (quota_count != 0 && share_count != 0) {
        limit_count = DETECTION_MIN(quota_count, share_count);
    } else if (quota_count != 0) {
        limit_count = quota_count;
    } else if (share_count != 0) {
        limit_count = share_count;
    }

    return DETECTION_MIN(cpu_count, limit_count);
}