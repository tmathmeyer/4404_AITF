include config.mk

all: netfilter

netfilter: ait_filter.o iputils.o dlist.o

.c.o: config.mk
	@echo CC -c $<
	@${CC} -c $< ${CFLAGS} -D ${OPT}

netfilter:
	@echo CC -o $@
	@${CC} -o $@-${OPT} $+ ${LDFLAGS}

clean:
	@echo cleaning
	@rm -vf netfilter2 netfilter-* *.o


