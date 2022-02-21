ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, can be overridden by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk

# binary name
APP=dpdkcap
DPDKDIR := $(RTE_SDK)/$(RTE_TARGET)

# all source are stored in SRCS-y
SRC_DIR= src
SOURCES += $(SRC_DIR/*.c) dpdkcap.c core_write.c core_capture.c statistics_ncurses.c pcap.c utils.c producer.c protocal.c lzo/minilzo/minilzo.c lzo/lzowrite.c 

SRCS-y += $(addprefix $(SRC_DIR)/, $(SOURCES))

KAFKALIB = -L/usr/local/lib -lrdkafka
KAFKAINC = -I/usr/local/include/librdkafka/
GLIB     = $(shell pkg-config --libs glib-2.0) -lgthread-2.0
GLIBINC  = $(shell pkg-config --cflags glib-2.0)
LDLIBS += $(KAFKALIB) $(GLIB) 

CFLAGS += -O3 -g $(WERROR_FLAGS) $(KAFKAINC) $(GLIBINC) -Wfatal-errors -std=c99 -U__STRICT_ANSI__
LDLIBS += -lncurses

include $(RTE_SDK)/mk/rte.extapp.mk
