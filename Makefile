versioned_so = detection.so

DOCKER_IMAGE = ubuntu
DOCKER_CMD = /tmp/sysconf_test
DOCKER_RUN_OPTS = $(shell echo "-ti --rm" \
					"--cpuset-cpus 0,1 --cpu-quota 200000" \
				    "-v `pwd`/detection.so:/usr/lib/detection.so" \
					"-v `pwd`/sysconf_test:/tmp/sysconf_test" \
					"-e DETECTION_TARGETS=sysconf_test" \
					"-e LD_PRELOAD=/usr/lib/detection.so")

$(versioned_so): detection.c
	gcc -std=c99 -Wall -shared -g -fPIC -ldl detection.c -o $(versioned_so)
	gcc sysconf_test.c -o sysconf_test

clean:
	rm -f *.o *.so detection.so.* sysconf_test

test:
	docker run $(DOCKER_RUN_OPTS) $(DOCKER_IMAGE) $(DOCKER_CMD)

.PHONY: clean test
