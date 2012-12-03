PLUGINDIR=${PREFIX}/lib/collectd
INCLUDEDIR=${PREFIX}/collectd/ ${EXTRA_INCLUDE}

CFLAGS=-I${INCLUDEDIR} -Wall -g -O2

all:
	${CC} -DHAVE_CONFIG_H ${CFLAGS} -c pftables.c -fPIC -DPIC -o pftables.o
	${CC} -shared pftables.o -Wl,-soname -Wl,pftables.so -o pftables.so

clean:
	rm -f pftables.o pftables.so

install:
	mkdir -p ${DESTDIR}/${PLUGINDIR}/
	cp pftables.so ${DESTDIR}/${PLUGINDIR}/

