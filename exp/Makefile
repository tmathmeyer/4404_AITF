include config.mk

all: netfilter

netfilter: ait_filter.o iputils.o

.c.o: config.mk
	@echo CC -c $<
	@${CC} -c $< ${CFLAGS}

netfilter tint3_path:
	@echo CC -o $@
	@${CC} -o $@ $+ ${LDFLAGS}

clean:
	@echo cleaning
	@rm -vf netfilter *.o
