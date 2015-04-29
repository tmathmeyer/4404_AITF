include config.mk

all: victim

victim: victim.o iputils.o

.c.o: config.mk
	@echo CC -c $<
	@${CC} -c $< ${CFLAGS}

victim:
	@echo CC -o $@
	@${CC} -o $@ $+ ${LDFLAGS}

clean:
	@echo cleaning
	@rm -vf netfilter *.o
