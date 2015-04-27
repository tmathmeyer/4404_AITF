include config.mk

all: netfilter

netfilter: ait_filter.o iputils.o

netfilter2: netfilter.o iputils.o

.c.o: config.mk
	@echo CC -c $<
	@${CC} -c $< ${CFLAGS}

netfilter:
	@echo CC -o $@
	@${CC} -o $@ $+ ${LDFLAGS}

netfilter2:
	@echo CC -o $@
	@${CC} -o $@ $+ ${LDFLAGS}

clean:
	@echo cleaning
	@rm -vf netfilter *.o
