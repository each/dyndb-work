COMMON_HDR = db.h util.h instance.h instance_manager.h \
	     lock.h log.h syncptr.h zone.h

CFLAGS = $(shell isc-config.sh --cflags bind9) \
	 -I ../../lib/dns/include -fpic -Wall -Wextra -std=gnu99 -ggdb3

LDFLAGS = $(shell isc-config.sh --libs bind9) -shared

OBJECTS = db.o driver.o instance.o instance_manager.o \
	  lock.o log.o syncptr.o zone.o

%.o: %.c $(COMMON_HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

all: $(OBJECTS)
	$(CC) $(LDFLAGS) -o sample.so $(OBJECTS)

clean:
	rm -f $(OBJECTS) sample.so
