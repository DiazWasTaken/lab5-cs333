CC = gcc
DEBUG = -g
DEFINES =
WERROR = 
#WERROR = -Werror 
CFLAGS = $(DEBUG) -Wall -Wextra -Wshadow -Wunreachable-code -Wredundant-decls \
	-Wmissing-declarations -Wold-style-definition \
	-Wmissing-prototypes -Wdeclaration-after-statement \
	-Wno-return-local-addr -Wunsafe-loop-optimizations \
	-Wuninitialized $(WERROR) $(DEFINES)

PROG = thread_hash
PROGS = $(PROG)

all: $(PROGS)

$(PROG): $(PROG).o
	$(CC) $(CFLAGS) -o $@ $^ -lcrypt

$(PROG).o: $(PROG).c $(PROG).h
	$(CC) $(CFLAGS) -c $< 

clean cls:
	rm -f $(PROGS) *.o *~ \#*

tar:
	tar cvfa lab5_${LOGNAME}.tar.gz *.[ch] [mM]akefile

git:
	git add Makefile $(PROG).c $(PROG).h
	git commit -m "end of work submit"
	git push 
