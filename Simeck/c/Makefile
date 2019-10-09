CFLAGS := -Wall

test_simeck.run: main.c simeck32.h simeck48.h simeck64.h
	gcc $(CFLAGS) $< -o $@

.PHONY: clean
clean:
	rm -rf *.out *.run *.o

.PHONY: check test
check test: test_simeck.run
	./test_simeck.run
