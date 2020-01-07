#
#  src_vipa
#
#  Copyright IBM Corp. 2001, 2013
#  Author(s): Utz Bacher <utz.bacher@de.ibm.com>
#
#  Published under the terms and conditions of the CPL (common public license)
#
#  PLEASE NOTE:
#  src_vipa is provided under the terms of the enclosed common public license
#  ("agreement"). Any use, reproduction or distribution of the program
#  constitutes recipient's acceptance of this agreement.
#

CC=gcc
CC_FLAGS=-fPIC -Wall
LD=gcc
LD_FLAGS=-shared 
INSTALL=install
VERSION=2.1.0
LDCONFIG=$(shell [ `id -u` -eq 0 ] && echo "ldconfig" )

# the path to the .so
ifeq ($(shell uname -m),s390x)
LIBDIR = /usr/lib64
else
LIBDIR = /usr/lib
endif
SRC_VIPA_PATH=$(INSTROOT)$(LIBDIR)
# the path to the starter script
SBINDIR=/usr/sbin
SRC_VIPA_STARTER_PATH=$(INSTROOT)$(SBINDIR)
# path to man page
MANDIR=/usr/share/man
SRC_VIPA_MANPAGE_PATH=$(INSTROOT)$(MANDIR)

all: src_vipa.so src_vipa.sh

src_vipa.so: src_vipa.c
	$(CC) $(CC_FLAGS) -D VERSION=$(VERSION) -c src_vipa.c
	$(LD) $(LD_FLAGS) src_vipa.o -ldl -o src_vipa.so

src_vipa.sh:
	echo '#!/bin/bash' > src_vipa.sh
	echo 'export LD_LIBRARY_PATH=$(LIBDIR):$$LD_LIBRARY_PATH' >> src_vipa.sh
	echo 'export LD_PRELOAD=$(LIBDIR)/src_vipa.so' >> src_vipa.sh
	echo 'exec $$@' >> src_vipa.sh
	chmod 755 src_vipa.sh

install: src_vipa.so src_vipa.sh
	$(INSTALL) -d -m 755 $(SRC_VIPA_PATH) $(SRC_VIPA_STARTER_PATH) $(SRC_VIPA_MANPAGE_PATH)/man8
	$(INSTALL) -m 755 src_vipa.so $(SRC_VIPA_PATH)
	$(INSTALL) -m 755 src_vipa.sh $(SRC_VIPA_STARTER_PATH)
	$(INSTALL) -m 644 src_vipa.8 $(SRC_VIPA_MANPAGE_PATH)/man8
	$(LDCONFIG)

clean:
	rm -f src_vipa.i src_vipa.s src_vipa.o src_vipa.sh src_vipa.so core src_vipa-$(VERSION).tar.gz

tar:
	mkdir src_vipa-$(VERSION)
	cp LICENSE Makefile README src_vipa.8 src_vipa.c src_vipa-$(VERSION)
	tar -czvf src_vipa-$(VERSION).tar.gz src_vipa-$(VERSION)
	rm -rf src_vipa-$(VERSION)
