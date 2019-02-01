all:
	$(CC) xdma-test.c -o xdma-test

.PHONY: clean
clean:
	rm -f xdma-test
