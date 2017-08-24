#
# Copyright (C) 2010-2017 Canonical, Ltd.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
#
BINDIR=/usr/bin

VERSION=0.2.12

ifeq ($(CC),clang)
CFLAGS += -O3 -Wall -Wextra -ftree-vectorize
else
CFLAGS += -O3 -Wall -Wextra -fipa-pta -ftree-vectorize -fweb -fwhole-program -fivopts 
endif

CFLAGS += -DVERSION='"$(VERSION)"'

#
# Pedantic flags
#
ifeq ($(PEDANTIC),1)
CFLAGS += -Wabi -Wcast-qual -Wfloat-equal -Wmissing-declarations \
	-Wmissing-format-attribute -Wno-long-long -Wpacked \
	-Wredundant-decls -Wshadow -Wno-missing-field-initializers \
	-Wno-missing-braces -Wno-sign-compare -Wno-multichar
endif

kernelscan: kernelscan.o Makefile
	$(CC) $< -o $@
	#strip $@

clean:
	rm -f kernelscan.o kernelscan kernelscan*snap

install: kernelscan
	mkdir -p ${DESTDIR}${BINDIR}
	cp kernelscan ${DESTDIR}${BINDIR}
