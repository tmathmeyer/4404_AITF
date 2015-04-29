include config.mk

all: aitf-control

aitf-control: control.o iputils.o

.c.o: config.mk
	@echo CC -c $<
	@${CC} -c $< ${CFLAGS}

aitf-control:
	@echo CC -o $@
	@${CC} -o $@ $+ ${LDFLAGS}


clean:
	@echo cleaning
	@rm -vf netfilter2 netfilter-* *.o


