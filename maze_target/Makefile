CC=clang
CFLAGS=-Wall -Wextra -Werror

.PHONY: all clean

all: maze

maze: maze.c
	# choose different mazes with the -DMAZE#
	$(CC) $(CFLAGS) -DMAZE1 -o $@ $<

clean:
	rm -f maze
