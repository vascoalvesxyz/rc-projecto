CC := gcc -std=c99 -D_POSIX_C_SOURCE=200809L
FLAGS := -O2 
DEBUG := -g -DDEBUG 

.PHONY: all

all: install

debug: FLAGS += $(DEBUG)
debug: all

install: 
	$(CC) $(FLAGS) -pthread cliente.c -o cliente
	$(CC) $(FLAGS) -pthread servidor.c -o servidor
