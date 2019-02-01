// Copyright 2019 IBM Corp

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define TESTING
#ifdef TESTING
struct __attribute__ ((__packed__)) aspeed_xdma_op {
	uint8_t upstream;
	uint64_t host_addr;
	uint32_t len;
	uint32_t bmc_addr;
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

void do_pattern(int fd, uint32_t data_length, unsigned int pattern_length, const uint8_t *data)
{
	int len;
	int rc;
	unsigned int i;

	if (!data) {
		data = _default_pattern;
		pattern_length = DEFAULT_PATTERN_LENGTH;
		log_info("Patterning with default pattern.\n");
	}

	for (i = 0; i < data_length; i += pattern_length) {
		if (data_length < i + pattern_length)
			len = data_length - i;
		else
			len = pattern_length;
		
		if ((rc = write(fd, data, len)) < 0) {
			log_err("Failed to write pattern: %s.\n", strerror(errno));
			break;
		}
	}
}

void read_and_display(int fd, uint32_t data_length)
{
	int len;
	int rc;
	unsigned int i;
	unsigned int j;
	uint8_t data[DISPLAY_BYTES_PER_LINE];

	for (i = 0; i < data_length; i += DISPLAY_BYTES_PER_LINE) {
		if (data_length < i + DISPLAY_BYTES_PER_LINE)
			len = data_length - i;
		else
			len = DISPLAY_BYTES_PER_LINE;

		if ((rc = read(fd, data, len)) < 0) {
			log_err("Failed to read buffer: %s\n", strerror(errno));
			break;
		}

		for (j = 0; j < len; ++j)
			fprintf(stdout, "%02X ", data[j]);

		fprintf(stdout, "\n");
	}
}

int main(int argc, char **argv)
{
	char op = 0;
	char do_read = 1;
	char pattern = 0;
	int fd = -1;
	int fd_buf = -1;
	int option;
	int rc;
	unsigned int pattern_length = DEFAULT_PATTERN_LENGTH;
	uint8_t res;
	uint64_t host_addr;
	uint32_t len;
	uint8_t *data_buf = NULL;
	char *data_arg = NULL;
	const char *xdma_dev = "/dev/xdma";
	const char *xdma_buf_dev = "/dev/xdma-buf";
	const char *opts = "a:d:hpr:w:";
	struct aspeed_xdma_op xdma_op;
	struct option lopts[] = {
		{ "addr", 1, 0, 'a' },
		{ "data", 1, 0, 'd' },
		{ "help", 0, 0, 'h' },
		{ "pattern", 1, 0, 'p' },
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
				log_err("Can't accept multiple data arguments, aborting.\n");
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

			break;
		case 'p':
			pattern = 1;
			break;
		case 'r':
			if (op) {
				log_err("Can't accept multiple commands, aborting.\n");
				rc = -EINVAL;
				goto done;
			}

			if ((rc = arg_to_u32(optarg, &len)))
				goto done;

			if (!len) {
				log_err("Zero length read specified, aborting.\n");
				rc = -EINVAL;
				goto done;
			}

			op = 1;
			break;
		case 'w':
			if (op) {
				log_err("Can't accept multiple commands, aborting.\n");
				rc = -EINVAL;
				goto done;
			}

			if ((rc = arg_to_u32(optarg, &len)))
				goto done;

			if (!len) {
				log_err("Zero length write specified, aborting.\n");
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

	if (data_arg) {
		data_buf = malloc(len);
		if (!data_buf) {
			rc = -ENOMEM;
			goto done;
		}

		arg_to_data(data_arg, len, data_buf);
	}

	fd_buf = open(xdma_buf_dev, do_read ? O_RDONLY : O_WRONLY);
	if (fd_buf < 0) {
		log_err("Failed to open %s.\n", xdma_buf_dev);
		rc = -ENODEV;
		goto done;
	}

	if (pattern && !do_read)
		do_pattern(fd_buf, len, pattern_length, data_buf);

	xdma_op.upstream = do_read ? 0 : 1;
	xdma_op.host_addr = host_addr;
	xdma_op.len = len;
	xdma_op.bmc_addr = 0;

	fd = open(xdma_dev, O_RDWR);
	if (fd < 0) {
		log_err("Failed to open %s.\n", xdma_dev);
		rc = -ENODEV;
		goto done;
	}

	errno = 0;
	rc = write(fd, &xdma_op, sizeof(xdma_op));
	if (rc < 0) {
		log_err("Failed to start DMA operation: %s.\n", strerror(errno));
		goto done;
	}

	rc = read(fd, &res, 1);
	if (rc < 0) {
		log_err("Failed to complete DMA operation: %s.\n", strerror(errno));
		goto done;
	}

	if (do_read)
		read_and_display(fd_buf, len);

done:
	if (fd >= 0)
		close(fd);

	if (fd_buf >= 0)
		close(fd_buf);

	if (data_arg)
		free(data_arg);

	if (data_buf)
		free(data_buf);

	return rc;
}
