CC := gcc -std=c17 -D_POSIX_C_SOURCE=200809L
FLAGS := -O2 -Wall -Wextra -Werror
DEBUG := -g -DDEBUG 

.PHONY: all

all: install

debug: FLAGS += $(DEBUG)
debug: all

install: 
	$(CC) $(FLAGS) cliente.c -o cliente
	$(CC) $(FLAGS) servidor.c -o servidor
