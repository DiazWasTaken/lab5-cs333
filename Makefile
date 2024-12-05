CC = gcc
DEBUG = -g
DEFINES =
WERROR = 
CFLAGS = $(DEBUG) -Wall -Wextra -Wshadow -Wunreachable-code -Wredundant-decls \
	-Wmissing-declarations -Wold-style-definition \
	-Wmissing-prototypes -Wdeclaration-after-statement \
	-Wno-return-local-addr -Wunsafe-loop-optimizations \
	-Wuninitialized -Werror -Wno-unused-parameter $(DEFINES)


PROG = thread_hash
PROGS = $(PROG)

# Ensure 'all' target explicitly builds both executable and object files
all: $(PROG) $(PROG).o

$(PROG): $(PROG).o
	$(CC) $(CFLAGS) -o $@ $^ -lcrypt

$(PROG).o: $(PROG).c $(PROG).h
	$(CC) $(CFLAGS) -c $< 

# Clean target must remove both the executable and object file
clean cls:
	rm -f $(PROGS) *.o *~ \#*

# Include the tarball creation for submission
tar:
	tar cvfa lab5_${LOGNAME}.tar.gz *.[ch] [mM]akefile

# Ensure the Git target works as expected
git:
	git add Makefile $(PROG).c $(PROG).h
	git commit -m "end of work submit"
	git push
