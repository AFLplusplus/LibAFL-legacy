#ifndef _GNU_SOURCE
  #define _GNU_SOURCE 1
#endif

#include <signal.h>
#include <assert.h>
#include <types.h>
#include <unistd.h>
#include <stdbool.h>
#include <dirent.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include <sched.h>
#include <ctype.h>
#include "os.h"
#include "engine.h"
#include "xxh3.h"

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || \
    defined(__NetBSD__) || defined(__DragonFly__)
  #include <sys/sysctl.h>
#endif                           /* __APPLE__ || __FreeBSD__ || __OpenBSD__ */

#if defined(__linux__) || defined(__FreeBSD__) || defined(__NetBSD__) || \
    defined(__DragonFly__) || defined(__sun)
  #define HAVE_AFFINITY 1
  #if defined(__FreeBSD__) || defined(__DragonFly__)
    #include <sys/param.h>
    #if defined(__FreeBSD__)
      #include <sys/cpuset.h>
    #endif
    #include <sys/user.h>
    #include <pthread.h>
    #include <pthread_np.h>
    #define cpu_set_t cpuset_t
  #elif defined(__NetBSD__)
    #include <pthread.h>
  #elif defined(__sun)
    #include <sys/types.h>
    #include <kstat.h>
    #include <sys/sysinfo.h>
    #include <sys/pset.h>
  #endif
#endif                                                         /* __linux__ */

// Process related functions

void _afl_process_init_internal(afl_os_t *afl_os) {

  afl_os->fork = afl_proc_fork;

  afl_os->resume = afl_proc_resume;
  afl_os->wait = afl_proc_wait;
  afl_os->suspend = afl_proc_suspend;

}

afl_fork_result_t afl_proc_fork(afl_os_t *afl_os) {

  pid_t child = fork();

  if (child == 0)
    return CHILD;
  else if (child < 0)
    return FORK_FAILED;

  afl_os->handler_process = child;
  return PARENT;

}

void afl_proc_suspend(afl_os_t *afl_os) {

  kill(afl_os->handler_process, SIGSTOP);

}

void afl_proc_resume(afl_os_t *afl_os) {

  kill(afl_os->handler_process, SIGCONT);

}

afl_exit_t afl_proc_wait(afl_os_t *afl_os, bool untraced) {

  int status = 0;
  if (waitpid((afl_os->handler_process), &status, untraced ? WUNTRACED : 0) < 0)
    return -1;  // Waitpid fails here, how should we handle this?

  if (WIFEXITED(status)) return AFL_EXIT_OK;

  // If the afl_os was simply stopped , we return AFL_EXIT_STOP
  if (WIFSTOPPED(status)) return AFL_EXIT_STOP;

  // If the afl_os exited with a signal, we check the corresponsing signum of
  // the afl_os and return values correspondingly
  if (WIFSIGNALED(status)) {

    int signal_num = WTERMSIG(status);  // signal number
    switch (signal_num) {

      case SIGKILL:
        return AFL_EXIT_TIMEOUT;
      case SIGSEGV:
        return AFL_EXIT_SEGV;
      case SIGABRT:
        return AFL_EXIT_ABRT;
      case SIGBUS:
        return AFL_EXIT_BUS;
      case SIGILL:
        return AFL_EXIT_ILL;
      default:
        /* Any other SIGNAL we need to take care of? */
        return AFL_EXIT_CRASH;

    }

  }

  else {

    FATAL("BUG: Currently Unhandled");

  }

}

static afl_ret_t __afl_for_each_file(char *dirpath, bool (*handle_file)(char *filename, void *data), void *data) {

  DIR *          dir_in = NULL;
  struct dirent *dir_ent = NULL;
  char           infile[PATH_MAX];
  uint32_t       ok = 0;

  if (!(dir_in = opendir(dirpath))) { return AFL_RET_FILE_OPEN_ERROR; }

  while ((dir_ent = readdir(dir_in))) {

    if (dir_ent->d_name[0] == '.') {

      continue;  // skip anything that starts with '.'

    }

    snprintf((char *)infile, sizeof(infile), "%s/%s", dirpath, dir_ent->d_name);
    infile[sizeof(infile) - 1] = '\0';

    /* TODO: Error handling? */
    struct stat st;
    if (access(infile, R_OK) != 0 || stat(infile, &st) != 0) { continue; }
    if (S_ISDIR(st.st_mode)) {

      if (__afl_for_each_file(infile, handle_file, data) == AFL_RET_SUCCESS) { ok = 1; }
      continue;

    }

    if (!S_ISREG(st.st_mode) || st.st_size == 0) { continue; }

    if (handle_file(infile, data) == true) { ok = 1; }

  }

  closedir(dir_in);

  if (ok) {

    return AFL_RET_SUCCESS;

  } else {

    return AFL_RET_EMPTY;

  }

}

/* Run `handle_file` for each file in the dirpath, recursively.
void *data will be passed to handle_file as 2nd param.
if handle_file returns false, further execution stops. */
afl_ret_t afl_for_each_file(char *dirpath, bool (*handle_file)(char *filename, void *data), void *data) {

  size_t dir_name_size = strlen(dirpath);
  if (dirpath[dir_name_size - 1] == '/') { dirpath[dir_name_size - 1] = '\0'; }
  if (access(dirpath, R_OK | X_OK) != 0) return AFL_RET_FILE_OPEN_ERROR;

  return __afl_for_each_file(dirpath, handle_file, data);

}


/* WIP: Let's implement a simple function which binds the cpu to the current process
   The code is very similar to how we do it in AFL++ */

/* bind process to a specific cpu. Returns 0 on failure. */

static u8 bind_cpu(s32 cpuid) {

  #if defined(__linux__) || defined(__FreeBSD__) || defined(__DragonFly__)
  cpu_set_t c;
  #elif defined(__NetBSD__)
  cpuset_t *c;
  #elif defined(__sun)
  psetid_t c;
  #endif

  #if defined(__linux__) || defined(__FreeBSD__) || defined(__DragonFly__)

  CPU_ZERO(&c);
  CPU_SET(cpuid, &c);

  #elif defined(__NetBSD__)

  c = cpuset_create();
  if (c == NULL) { PFATAL("cpuset_create failed"); }
  cpuset_set(cpuid, c);

  #elif defined(__sun)

  pset_create(&c);
  if (pset_assign(c, cpuid, NULL)) { PFATAL("pset_assign failed"); }

  #endif

  #if defined(__linux__)

  return (sched_setaffinity(0, sizeof(c), &c) == 0);

  #elif defined(__FreeBSD__) || defined(__DragonFly__)

  return (pthread_setaffinity_np(pthread_self(), sizeof(c), &c) == 0);

  #elif defined(__NetBSD__)

  if (pthread_setaffinity_np(pthread_self(), cpuset_size(c), c)) {

    cpuset_destroy(c);
    return 0;

  }

  cpuset_destroy(c);
  return 1;

  #elif defined(__sun)

  if (pset_bind(c, P_PID, getpid(), NULL)) {

    pset_destroy(c);
    return 0;

  }

  pset_destroy(c);
  return 1;

  #else

  // this will need something for other platforms
  // TODO: Solaris/Illumos has processor_bind ... might worth a try
  WARNF("Cannot bind to CPU yet on this platform.");
  return 1;

  #endif

}



/* Get the number of runnable processes, with some simple smoothing. */

double get_runnable_processes(void) {

  double res = 0;

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || \
    defined(__NetBSD__) || defined(__DragonFly__)

  /* I don't see any portable sysctl or so that would quickly give us the
     number of runnable processes; the 1-minute load average can be a
     semi-decent approximation, though. */

  if (getloadavg(&res, 1) != 1) return 0;

#else

  /* On Linux, /proc/stat is probably the best way; load averages are
     computed in funny ways and sometimes don't reflect extremely short-lived
     processes well. */

  FILE *f = fopen("/proc/stat", "r");
  char tmp[1024];
  u32 val = 0;

  if (!f) { return 0; }

  while (fgets(tmp, sizeof(tmp), f)) {

    if (!strncmp(tmp, "procs_running ", 14) ||
        !strncmp(tmp, "procs_blocked ", 14)) {

      val += atoi(tmp + 14);

    }

  }

  fclose(f);

  if (!res) {

    res = val;

  } else {

    res = res * (1.0 - 1.0 / AVG_SMOOTHING) +
          ((double)val) * (1.0 / AVG_SMOOTHING);

  }

#endif          /* ^(__APPLE__ || __FreeBSD__ || __OpenBSD__ || __NetBSD__) */

  return res;

}

/* Count the number of logical CPU cores. */

s32 get_core_count() {

  s32 cpu_core_count = 0;

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || \
    defined(__DragonFly__)

  size_t s = sizeof(cpu_core_count);

  /* On *BSD systems, we can just use a sysctl to get the number of CPUs. */

  #ifdef __APPLE__

  if (sysctlbyname("hw.logicalcpu", &cpu_core_count, &s, NULL, 0) < 0)
    return 0;

  #else

  int s_name[2] = {CTL_HW, HW_NCPU};

  if (sysctl(s_name, 2, &cpu_core_count, &s, NULL, 0) < 0) return 0;

  #endif                                                      /* ^__APPLE__ */

#else

  #ifdef HAVE_AFFINITY

  cpu_core_count = sysconf(_SC_NPROCESSORS_ONLN);

  #else

  FILE *f = fopen("/proc/stat", "r");
  char    tmp[1024];

  if (!f) return 0;

  while (fgets(tmp, sizeof(tmp), f))
    if (!strncmp(tmp, "cpu", 3) && isdigit(tmp[3])) ++cpu_core_count;

  fclose(f);

  #endif                                                  /* ^HAVE_AFFINITY */

#endif                        /* ^(__APPLE__ || __FreeBSD__ || __OpenBSD__) */

  if (cpu_core_count > 0) {

    u32 cur_runnable = 0;

    cur_runnable = (u32)get_runnable_processes();

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || \
    defined(__DragonFly__)

    /* Add ourselves, since the 1-minute average doesn't include that yet. */

    ++cur_runnable;

#endif                           /* __APPLE__ || __FreeBSD__ || __OpenBSD__ */

    OKF("You have %d CPU core%s and %u runnable tasks (utilization: %0.0f%%).",
        cpu_core_count, cpu_core_count > 1 ? "s" : "", cur_runnable,
        cur_runnable * 100.0 / cpu_core_count);

    if (cpu_core_count > 1) {

      if (cur_runnable > cpu_core_count * 1.5) {

        WARNF("System under apparent load, performance may be spotty.");

      } else if ((s64)cur_runnable + 1 <= (s64)cpu_core_count) {

        OKF("Try parallel jobs");

      }

    }

  } else {

    cpu_core_count = 0;
    WARNF("Unable to figure out the number of CPU cores.");

  }

  return cpu_core_count;

}


afl_ret_t bind_to_cpu() {

  u8 cpu_used[4096];

  s32 i;

  #if defined(__linux__)

  // Let's open up /proc and check if there are any CPU cores available
  DIR * proc;
  struct dirent * dir_entry;

  proc = opendir("/proc");

  while ((dir_entry = readdir(proc))) {

    if (!isdigit(dir_entry->d_name[0])) { continue; } // Leave files which aren't process files

    char fn[PATH_MAX];
    char tmp[MAX_LINE];

    FILE *f;
    u8 has_vmsize = 0;

    snprintf(fn, PATH_MAX, "/proc/%s/status", dir_entry->d_name);

    if (!(f = fopen(fn, "r"))) { continue; }

    while (fgets(tmp, MAX_LINE, f)) {

      u32 hval;

      /* Processes without VmSize are probably kernel tasks. */

      if (!strncmp(tmp, "VmSize:\t", 8)) { has_vmsize = 1; }

      if (!strncmp(tmp, "Cpus_allowed_list:\t", 19) && !strchr(tmp, '-') &&
          !strchr(tmp, ',') && sscanf(tmp + 19, "%u", &hval) == 1 &&
          hval < sizeof(cpu_used) && has_vmsize) {

        cpu_used[hval] = 1;
        break;

      }

    }

    fclose(f);
 

  }

  closedir(proc);


  #elif defined(__FreeBSD__) || defined(__DragonFly__)

  struct kinfo_proc *procs;
  size_t             nprocs;
  s32                proccount;
  int                s_name[] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL};
  size_t             s_name_l = sizeof(s_name) / sizeof(s_name[0]);

  if (sysctl(s_name, s_name_l, NULL, &nprocs, NULL, 0) != 0) {

    return AFL_RET_UNKNOWN_ERROR;

  }

  proccount = nprocs / sizeof(*procs);
  nprocs = nprocs * 4 / 3;

  procs = ck_alloc(nprocs);
  if (sysctl(s_name, s_name_l, procs, &nprocs, NULL, 0) != 0) {

    ck_free(procs);
    return AFL_RET_UNKNOWN_ERROR;

  }

  for (i = 0; i < proccount; i++) {

    #if defined(__FreeBSD__)

    if (!strcmp(procs[i].ki_comm, "idle")) continue;

    // fix when ki_oncpu = -1
    int oncpu;
    oncpu = procs[i].ki_oncpu;
    if (oncpu == -1) oncpu = procs[i].ki_lastcpu;

    if (oncpu != -1 && (size_t)oncpu < sizeof(cpu_used) && procs[i].ki_pctcpu > 60)
      cpu_used[oncpu] = 1;

    #elif defined(__DragonFly__)

    if (procs[i].kp_lwp.kl_cpuid < (s32)(sizeof(cpu_used)) &&
        procs[i].kp_lwp.kl_pctcpu > 10)
      cpu_used[procs[i].kp_lwp.kl_cpuid] = 1;

    #endif

  }

  ck_free(procs);

  #elif defined(__NetBSD__)

  struct kinfo_proc2 *procs;
  size_t              nprocs;
  size_t              proccount;
  int                 s_name[] = {

      CTL_KERN, KERN_PROC2, KERN_PROC_ALL, 0, sizeof(struct kinfo_proc2), 0};
  size_t s_name_l = sizeof(s_name) / sizeof(s_name[0]);

  if (sysctl(s_name, s_name_l, NULL, &nprocs, NULL, 0) != 0) {

    return AFL_RET_UNKNOWN_ERROR;

  }

  proccount = nprocs / sizeof(struct kinfo_proc2);
  procs = ck_alloc(nprocs * sizeof(struct kinfo_proc2));
  s_name[5] = proccount;

  if (sysctl(s_name, s_name_l, procs, &nprocs, NULL, 0) != 0) {

    ck_free(procs);
    return AFL_RET_UNKNOWN_ERROR;

  }

  for (i = 0; i < proccount; i++) {

    if (procs[i].p_cpuid < sizeof(cpu_used) && procs[i].p_pctcpu > 0)
      cpu_used[procs[i].p_cpuid] = 1;

  }

  ck_free(procs);

  #elif defined(__sun)

  kstat_named_t *n;
  kstat_ctl_t *  m;
  kstat_t *      k;
  cpu_stat_t     cs;
  u32            ncpus;

  m = kstat_open();

  if (!m) FATAL("kstat_open failed");

  k = kstat_lookup(m, "unix", 0, "system_misc");

  if (!k) {

    kstat_close(m);
    return AFL_RET_UNKNOWN_ERROR;

  }

  if (kstat_read(m, k, NULL)) {

    kstat_close(m);
    return AFL_RET_UNKNOWN_ERROR;

  }

  n = kstat_data_lookup(k, "ncpus");
  ncpus = n->value.i32;

  if (ncpus > sizeof(cpu_used)) ncpus = sizeof(cpu_used);

  for (i = 0; i < ncpus; i++) {

    k = kstat_lookup(m, "cpu_stat", i, NULL);
    if (kstat_read(m, k, &cs)) {

      kstat_close(m);
      return AFL_RET_UNKNOWN_ERROR;

    }

    if (cs.cpu_sysinfo.cpu[CPU_IDLE] > 0) continue;

    if (cs.cpu_sysinfo.cpu[CPU_USER] > 0 || cs.cpu_sysinfo.cpu[CPU_KERNEL] > 0)
      cpu_used[i] = 1;

  }

  kstat_close(m);

  #else
    #warning \
        "For this platform we do not have free CPU binding code yet. If possible, please supply a PR to https://github.com/AFLplusplus/libAFL"
  #endif
  size_t cpu_start = 0;
  s32 cpu_core_count = get_core_count();

  #if !defined(__ANDROID__)

  for (i = cpu_start; i < cpu_core_count; i++) {

  #else

  /* for some reason Android goes backwards */

  for (i = cpu_core_count - 1; i > -1; i--) {

  #endif

    if (cpu_used[i]) { continue; }

    OKF("Found a free CPU core, try binding to #%u.", i);

    if (bind_cpu(i)) {

      /* Success :) */
      break;

    }

    WARNF("setaffinity failed to CPU %d, trying next CPU", i);
    cpu_start++;

  }

  return AFL_RET_SUCCESS;


}
