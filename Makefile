versioned_so = detection.so

$(versioned_so): detection.c
	gcc -std=c99 -Wall -shared $(CFLAGS) -g -fPIC -Wl,--no-as-needed -ldl detection.c -o $(versioned_so)

clean:
	rm -f *.o *.so detection.so.*

.PHONY: clean
