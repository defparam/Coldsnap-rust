CC = gcc
CFLAGS = -g

default: run

compile:
	@$(CC) $(CFLAGS) target_exec.c -o target_exec

run: compile
	@cargo run
	
clean:
	rm -rf target
	rm -f Cargo.lock
	rm -f target_exec
