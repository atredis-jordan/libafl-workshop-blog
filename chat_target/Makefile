CC=clang
CFLAGS=-Wall -Wextra -Werror

.PHONY: all clean

all: chat

chat: chat.c
	$(CC) $(CFLAGS) -o $@ $<

chatdbg: chat.c
	$(CC) $(CFLAGS) -g -o $@ $<

clean:
	rm -f chat chatdbg
