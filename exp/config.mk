VERSION = 1.0.0

# includes and libs
LIBS = -lnetfilter_queue

# flags
CFLAGS   = -std=c11 -pedantic-errors -Wextra -Wall ${CPPFLAGS} -O1
LDFLAGS  = ${LIBS}

# compiler and linker
CC = gcc
