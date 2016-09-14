
CC = $(CROSS_COMPILE)gcc

OBJS = hsrd.o

BINARY = wrsw_hsrd

# We must include stuff from wr_ipc, which is installed.
# If this is build under build scripts, it's $WRS_OUTPUT_DIR/images/wr
WR_INSTALL_ROOT ?= /usr/lib/white-rabbit
WR_INCLUDE = $(WR_INSTALL_ROOT)/include
WR_LIB = $(WR_INSTALL_ROOT)/lib

CFLAGS = -g -Wall -DRT_CLIENT\
	-I../include -I../mini-rpc -I$(WR_INCLUDE)

ifdef WRS_HAL_DEBUG
  CFLAGS += -DDEBUG
endif

LDFLAGS = -L../libswitchhw -L../mini-rpc \
	 -lminipc -llua -lm -ldl -lswitchhw 

all: $(BINARY)

$(BINARY): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

install: all
	install -d        $(WR_INSTALL_ROOT)/bin $(WR_INSTALL_ROOT)/include
	install $(BINARY) $(WR_INSTALL_ROOT)/bin

clean:
	rm -f $(BINARY) *.o *~
