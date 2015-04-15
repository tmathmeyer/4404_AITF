VERSION = 1.0.0

# includes and libs
LIBS = -lnetfilter_queue

# flags
CFLAGS   = -std=c11 -pedantic -Wextra -Wall ${CPPFLAGS} -g
LDFLAGS  = ${LIBS}

# compiler and linker
CC = gcc
