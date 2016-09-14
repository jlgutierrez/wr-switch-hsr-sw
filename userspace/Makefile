
# Most of the sub makefiles require some variables that used to be
# in the auto-generated ../Makedefs (when software was in svn).
# So let's add all of the needed variables here (environment can override)

ARCH ?= arm
CROSS_COMPILE ?= $(CROSS_COMPILE_ARM_PATH)$(CROSS_COMPILE_ARM_PREFIX)
CROSS_COMPILE_ARM ?= $(CROSS_COMPILE)

# Installation of all of this stuff goes to images/wr in the output dir
WR_INSTALL_ROOT ?= $(WRS_OUTPUT_DIR)/images/wr
WRDEV_DIR ?= $(WRS_BASE_DIR)/..

# subdirectories we want to compile
SUBDIRS = libptpnetif mini-rpc libswitchhw wrsw_hal wrsw_rtud tools snmpd wrsw_hsrd

# all variables are exported
export

# All targets must install as well, as later builds use headers/libs
all:
	ln -sf ../../kernel/wbgen-regs include/regs
	ln -sf ../../kernel/at91_softpwm/at91_softpwm.h include/at91_softpwm.h
	for d in $(SUBDIRS); do $(MAKE) -C $$d $@ || exit 1; done

clean:
	for d in $(SUBDIRS); do $(MAKE) -C $$d $@ || exit 1; done

install: all
	for d in $(SUBDIRS); do $(MAKE) -C $$d $@ || exit 1; done
