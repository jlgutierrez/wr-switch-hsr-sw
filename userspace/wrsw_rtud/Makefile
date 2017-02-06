
PROGRAM		= wrsw_rtud
SRCFILES	= mac.c rtu_drv.c rtu_ext_drv.c rtu_hash.c rtu_fd.c rtud.c \
			rtud_exports.c utils.c
OBJFILES	= $(patsubst %.c,%.o,$(SRCFILES))

CC		= $(CROSS_COMPILE)gcc

# We must include stuff from various headers, which are installed.
# If this is build under build scripts, it's $WRS_OUTPUT_DIR/images/wr
WR_INSTALL_ROOT ?= /usr/lib/white-rabbit
WR_INCLUDE = $(WR_INSTALL_ROOT)/include
WR_LIB = $(WR_INSTALL_ROOT)/lib

CFLAGS		= -O2 -Wall -ggdb  \
		-I../libptpnetif -I../wrsw_hal \
		-I../mini-rpc -I../include -I$(WR_INCLUDE) -I$(LINUX)/include
# -I$(CROSS_COMPILE_ARM_PATH)/../include

#ifdef WRS_RTUD_DEBUG
  CFLAGS += -DDEBUG
#endif


LDFLAGS 	:= -L../libptpnetif -L../libswitchhw -L../mini-rpc\
		-lswitchhw -lptpnetif -lpthread -lminipc

RM 	    := rm -f


.PHONY: all

all: $(PROGRAM)

$(PROGRAM): $(OBJFILES)
	$(CC) -o $@ $(OBJFILES) $(LDFLAGS) 

clean:
	$(RM) $(PROGRAM) $(OBJFILES)

install: all
	cp $(PROGRAM) $(WR_INSTALL_ROOT)/bin
