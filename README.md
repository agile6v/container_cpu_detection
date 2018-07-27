# container_cpu_detection

## About

This program is used to autuomatically calculate the number of available CPU cores in the container based on the cgroup information by hijacking the `sysconf` system call. (This method of hijacking uses a Unix system trick `LD_PRELOAD` to hijack dynamic link library)

I have known the secnario of the usage is that Nginx calculates the number of available CPU cores by sysconf(_SC_NPROCESSORS_ONLN) and starts the corresponding number of worker processes. In addition, there must be many others usage scenarios.


## Algorithm

There are three ways that Docker limits CPU resources.

* cpuset
* cpu quota & cpu period
* cpu shares

Docker mounts cgroup information into container starting with version 1.8, so it is possible to determine the appropriate number of CPUs based on the
cgroup information in the container.

Assume that the cgroup information is mounted in the /sys/fs/cgroup/:

##### Step 1 - Get the value of the `cpuset`

By reading /sys/fs/cgroup/cpuset/cpuset.cpus. By default, this value is equal to the number of the host CPU cores.

##### Step 2 - Get the value of the `cpu quota & cpu period`

By reading /sys/fs/cgroup/cpu/cpu.cfs_period_us & /sys/fs/cgroup/cpu/cpu.cfs_quota_us. Calculate the available CPU cores by quota divided by period and rounded up.

##### Step 3 - Get the value of the `cpu shares`

By reading /sys/fs/cgroup/cpu/cpu.shares. If you don't specify the cpu shares when running a container then its default value is 1024.

##### Step 4 - Calculate the number of available CPU cores.

These three ways can be specified at the same time. When they are specfied at the same time, take the minimum value as the number of available CPU cores.


## Usage
* make
* make test (Please make sure that docker has already installed.)

Note:
1. Set the environment variable `DETECTION_TARGETS` in the container to 
      specify which programs you want to hijack. Multiple name can be specified
      at the same time. (separated by a colon)
2. Set the environment variable `LD_PRELOAD` in the container to specify 
      the path of the .so file.
3. Running a container with -v parameter to mount .so file into the container.
4. Only for Linux.

For example:

    docker run -ti --rm \
    --cpuset-cpus 0,1 --cpu-quota 400000 \
    -v `pwd`/detection.so:/usr/lib/detection.so \
    -v `pwd`/sysconf_test:/tmp/sysconf_test \
    -e DETECTION_TARGETS=sysconf_test \
    -e LD_PRELOAD=/usr/lib/detection.so \
    ubuntu /tmp/sysconf_test
