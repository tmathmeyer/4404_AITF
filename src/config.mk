VERSION = 1.0.0

# includes and libs
LIBS = -lnetfilter_queue -lssl -lcrypto

# flags
CFLAGS   = -std=c11
LDFLAGS  = ${LIBS}

# compiler and linker
CC = gcc
