// Copyright 2019 IBM Corp

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define TESTING
#ifdef TESTING
struct __attribute__ ((__packed__)) aspeed_xdma_op {
	uint8_t upstream;
	uint64_t host_addr;
	uint32_t len;
};
#endif /* TESTING */

#define DEFAULT_PATTERN_LENGTH	16
#define DISPLAY_BYTES_PER_LINE	16

#define log_err(x, ...)		fprintf(stderr, (x), ##__VA_ARGS__)
#define log_info(x, ...)	fprintf(stdout, (x), ##__VA_ARGS__)

static const uint8_t _default_pattern[DEFAULT_PATTERN_LENGTH] = {
	0xfe,
	0xdc,
	0xba,
	0x98,
	0x76,
	0x54,
	0x32,
	0x10,
	0x01,
	0x23,
	0x45,
	0x67,
	0x89,
	0xab,
	0xcd,
	0xef
};

static const char *_help =
	"xdma-test performs DMA operations between the BMC and the host.\n"
	"Usage: xdma-test [options]\n"
	"Options:\n"
	"    -a --addr <host address>    specify the host memory address\n"
	"    -d --data <data>            specify the data pattern for upstream"
					 " ops\n"
	"    -p --pattern                pattern the memory before upstream "
					 "op\n"
	"    -r --read <length>          do a read (downstream) op of <length>"
					 " bytes\n"
	"    -w --write <length>         do a write (upstream) op of <length> "
					 "bytes\n";

uint32_t align_length(uint32_t len)
{
	const int page_size = getpagesize();
	uint32_t num_pages = len / page_size;
	uint32_t aligned_len = num_pages * page_size;

	if (len > aligned_len)
		aligned_len += page_size;

	return aligned_len;
}

void arg_to_data(char *arg, unsigned long size, uint8_t *buf)
{
	char c;
	uint8_t n;
	unsigned int i;
	unsigned int count = strlen(arg);

	for (i = 0; (i < count) && ((i / 2) < size); ++i) {
		c = arg[i];
		if (c >= '0' && c <= '9')
			n = c - '0';
		else if (c >= 'a' && c <= 'f')
			n = (c - 'a') + 10;
		else if (c >= 'A' && c <= 'F')
			n = (c - 'A') + 10;
		else
			n = 0;

		if (!(i % 2))
			buf[i / 2] = n << 4;
		else
			buf[i / 2] |= n;
	}
}

int arg_to_u32(char *arg, uint32_t *val)
{
	uint32_t tval;

	errno = 0;
	tval = strtoul(arg, NULL, 0);
	if (errno) {
		log_err("Couldn't parse u32 arg %s.\n", arg);
		return -EINVAL;
	}

	*val = tval;
	return 0;
}

int arg_to_u64(char *arg, uint64_t *val)
{
	uint64_t tval;

	errno = 0;
	tval = strtoull(arg, NULL, 0);
	if (errno) {
		log_err("Couldn't parse u64 arg %s.\n", arg);
		return -EINVAL;
	}

	*val = tval;
	return 0;
}

void do_pattern(uint8_t *vga_mem, uint32_t data_length,
		unsigned int pattern_length, const uint8_t *data)
{
	char free_tmp = 0;
	uint8_t *tmp;

	if (!data) {
		data = _default_pattern;
		pattern_length = DEFAULT_PATTERN_LENGTH;
	}

	/*
	 * Pattern a temporary buffer and then copy the whole buffer to VGA. In
	 * testing, copying small chunks at a time resulted in cache coherency
	 * issues.
	 */
	if (pattern_length < data_length) {
		int len;
		unsigned int i;

		free_tmp = 1;
		tmp = malloc(data_length);

		if (!tmp) {
			log_err("Failed to allocate memory for patterning.\n");
			return;
		}

		for (i = 0; i < data_length; i += pattern_length) {
			if (data_length < i + pattern_length)
				len = data_length - i;
			else
				len = pattern_length;

			memcpy(&tmp[i], data, len);
		}
	} else {
		tmp = (uint8_t *)data;
	}

	memcpy(vga_mem, tmp, data_length);

	if (free_tmp)
		free(tmp);
}

void read_and_display(uint8_t *vga_mem, uint32_t data_length)
{
	int len;
	unsigned int i;
	unsigned int j;
	uint8_t data[DISPLAY_BYTES_PER_LINE];
	uint8_t *tmp = malloc(data_length);

	if (!tmp) {
		log_err("Failed to allocate memory to display data.\n");
		return;
	}

	memcpy(tmp, vga_mem, data_length);

	for (i = 0; i < data_length; i += DISPLAY_BYTES_PER_LINE) {
		if (data_length < i + DISPLAY_BYTES_PER_LINE)
			len = data_length - i;
		else
			len = DISPLAY_BYTES_PER_LINE;

		memcpy(data, &tmp[i], len);

		for (j = 0; j < len; ++j)
			fprintf(stdout, "%02X ", data[j]);

		fprintf(stdout, "\n");
	}

	free(tmp);
}

int main(int argc, char **argv)
{
	char op = 0;
	char do_read = 1;
	char pattern = 0;
	int fd = -1;
	int option;
	int rc;
	unsigned int pattern_length = DEFAULT_PATTERN_LENGTH;
	uint8_t res;
	uint64_t host_addr;
	uint32_t aligned_len;
	uint32_t len;
	uint8_t *data_buf = NULL;
	uint8_t *vga_mem = NULL;
	char *data_arg = NULL;
	const char *xdma_dev = "/dev/xdma";
	const char *opts = "a:d:hpr:w:";
	struct aspeed_xdma_op xdma_op;
	struct pollfd fds;
	struct option lopts[] = {
		{ "addr", 1, 0, 'a' },
		{ "data", 1, 0, 'd' },
		{ "help", 0, 0, 'h' },
		{ "pattern", 0, 0, 'p' },
		{ "read", 1, 0, 'r' },
		{ "write", 1, 0, 'w' },
		{ 0, 0, 0, 0 }
	};

	while ((option = getopt_long(argc, argv, opts, lopts, NULL)) != -1) {
		switch (option) {
		case 'a':
			if ((rc = arg_to_u64(optarg, &host_addr)))
				goto done;
			break;
		case 'd':
			if (data_arg) {
				log_err("Can't accept multiple data arguments,"
					" aborting.\n");
				rc = -EINVAL;
				goto done;
			}

			pattern_length = strlen(optarg);
			data_arg = malloc(pattern_length + 1);
			if (!data_arg) {
				rc = -ENOMEM;
				goto done;
			}

			strcpy(data_arg, optarg);
			break;
		case 'h':
			printf("%s", _help);
			goto done;
			break;
		case 'p':
			pattern = 1;
			break;
		case 'r':
			if (op) {
				log_err("Can't accept multiple commands,"
					" aborting.\n");
				rc = -EINVAL;
				goto done;
			}

			if ((rc = arg_to_u32(optarg, &len)))
				goto done;

			if (!len) {
				log_err("Zero length read specified,"
					" aborting.\n");
				rc = -EINVAL;
				goto done;
			}

			op = 1;
			break;
		case 'w':
			if (op) {
				log_err("Can't accept multiple commands,"
					" aborting.\n");
				rc = -EINVAL;
				goto done;
			}

			if ((rc = arg_to_u32(optarg, &len)))
				goto done;

			if (!len) {
				log_err("Zero length write specified,"
					" aborting.\n");
				rc = -EINVAL;
				goto done;
			}

			op = 1;
			do_read = 0;
			break;
		}
	}

	if (!op) {
		log_err("No operation specified, aborting.\n");
		rc = -EINVAL;
		goto done;
	}

	aligned_len = align_length(len);

	if (data_arg) {
		data_buf = malloc(aligned_len);
		if (!data_buf) {
			rc = -ENOMEM;
			goto done;
		}

		arg_to_data(data_arg, len, data_buf);
	}

	fd = open(xdma_dev, O_RDWR);
	if (fd < 0) {
		log_err("Failed to open %s.\n", xdma_dev);
		rc = -ENODEV;
		goto done;
	}

	vga_mem = mmap(NULL, aligned_len, do_read ? PROT_READ : PROT_WRITE, MAP_SHARED,
		       fd, 0);
	if (!vga_mem) {
		log_err("Failed to mmap %s.\n", strerror(errno));
		rc = -ENOMEM;
		goto done;
	}

	if (pattern && !do_read) {
		do_pattern(vga_mem, aligned_len, pattern_length / 2, data_buf);
		munmap(vga_mem, aligned_len);
		vga_mem = NULL;
	}

	xdma_op.upstream = do_read ? 0 : 1;
	xdma_op.host_addr = host_addr;
	xdma_op.len = len;

	rc = write(fd, &xdma_op, sizeof(xdma_op));
	if (rc < 0) {
		log_err("Failed to start DMA operation: %s.\n",
			strerror(errno));
		goto done;
	}

	fds.fd = fd;
	fds.events = POLLIN;
	rc = poll(&fds, 1, -1);
	if (rc < 0) {
		log_err("Failed to complete DMA operation: %s.\n",
			strerror(errno));
		goto done;
	}

	if (do_read)
		read_and_display(vga_mem, len);

done:
	if (vga_mem)
		munmap(vga_mem, aligned_len);

	if (fd >= 0)
		close(fd);

	if (data_arg)
		free(data_arg);

	if (data_buf)
		free(data_buf);

	return rc;
}
