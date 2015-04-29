include config.mk

.c.o: config.mk
	@echo CC -c $<
	@${CC} -c $< ${CFLAGS}

victim.o: victim.c

clean:
	@echo cleaning
	@rm -vf netfilter *.o
