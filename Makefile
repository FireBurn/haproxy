# This makefile supports different OS and CPU setups.
# You should use it this way :
#   make TARGET=os CPU=cpu

# Select target OS. TARGET must match a system for which COPTS and LIBS are
# correctly defined below.
TARGET = linux24
#TARGET = linux22
#TARGET = solaris
#TARGET = openbsd

# pass CPU=<cpu_name> to make to optimize for a particular CPU
CPU = generic
#CPU = i586
#CPU = i686
#CPU = ultrasparc

# By default, we use libc's regex. WARNING! On Solaris 8/Sparc, group
# references seem broken using libc ! Use pcre instead.
REGEX=libc
#REGEX=pcre
#REGEX=static-pcre

# tools options
CC = gcc
LD = gcc

# This is the directory hosting include/pcre.h and lib/libpcre.* when REGEX=pcre
PCREDIR	:= $(shell pcre-config --prefix 2>/dev/null || :)
#PCREDIR=/usr/local

# This is for Linux 2.4 with netfilter
COPTS.linux24 = -DNETFILTER
LIBS.linux24 =

# This is for Linux 2.2
COPTS.linux22 = -DUSE_GETSOCKNAME
LIBS.linux22 =

# This is for Solaris 8
COPTS.solaris = -fomit-frame-pointer -DFD_SETSIZE=65536
LIBS.solaris = -lnsl -lsocket

# This is for OpenBSD 3.0
COPTS.openbsd =
LIBS.openbsd =

# CPU dependant optimizations
COPTS.generic = -O2
COPTS.i586 = -O2 -march=i586
COPTS.i686 = -O2 -march=i686
COPTS.ultrasparc = -O6 -mcpu=v9 -mtune=ultrasparc

# options for standard regex library
COPTS.libc=
LIBS.libc=

# options for libpcre
COPTS.pcre=-DUSE_PCRE -I$(PCREDIR)/include
LIBS.pcre=-L$(PCREDIR)/lib -lpcreposix -lpcre

# options for static libpcre
COPTS.static-pcre=-DUSE_PCRE -I$(PCREDIR)/include
LIBS.static-pcre=-L$(PCREDIR)/lib -Wl,-Bstatic -lpcreposix -lpcre -Wl,-Bdynamic

# you can enable debug arguments with "DEBUG=-g" or disable them with "DEBUG="
#DEBUG =
DEBUG = -g

# if small memory footprint is required, you can reduce the buffer size. There
# are 2 buffers per concurrent session, so 16 kB buffers will eat 32 MB memory
# with 1000 concurrent sessions. Putting it slightly lower than a page size
# will avoid the additionnal paramters to overflow a page.
#SMALL_OPTS = -DBUFSIZE=8100 -DMAXREWRITE=1000
SMALL_OPTS =

# redefine this if you want to add some special PATH to include/libs
ADDINC =
ADDLIB =

# set some defines when needed.
# Known ones are -DENABLE_POLL, -DENABLE_EPOLL, and -DUSE_MY_EPOLL
DEFINE =

# global options
TARGET_OPTS=$(COPTS.$(TARGET))
REGEX_OPTS=$(COPTS.$(REGEX))
CPU_OPTS=$(COPTS.$(CPU))

COPTS=$(ADDINC) $(CPU_OPTS) $(TARGET_OPTS) $(REGEX_OPTS) $(SMALL_OPTS) $(DEFINE)
LIBS=$(LIBS.$(TARGET)) $(LIBS.$(REGEX)) $(ADDLIB)

# - use -DSTATTIME=0 to disable statistics, else specify an interval in
#   milliseconds.
# - use -DTPROXY to compile with transparent proxy support.
CFLAGS = -Wall $(COPTS) $(DEBUG) -DSTATTIME=0 -DTPROXY
LDFLAGS = -g

all: haproxy

haproxy: haproxy.o
	$(LD) $(LDFLAGS) -o $@ $^ $(LIBS)

%.o:	%.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.[oas] *~ *.rej core haproxy test nohup.out gmon.out

