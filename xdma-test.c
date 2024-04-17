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

#include <stdbool.h>

#include <sys/ioctl.h>
#include <linux/types.h>

#define TESTING
#ifdef TESTING
struct __attribute__ ((__packed__)) aspeed_xdma_op {
	uint64_t host_addr;
	uint32_t len;
	uint32_t upstream;
};

#define __ASPEED_XDMA_IOCTL_MAGIC       0xb7
#define ASPEED_XDMA_IOCTL_RESET         _IO(__ASPEED_XDMA_IOCTL_MAGIC, 0)

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
	"    -f --file                   File to read/write to\n"
	"    -r --read                   do a read (downstream) op of <length>"
					 " bytes. If the file parameter is "
                                         "specified, will place data in file arg\n"
	"    -w --write                  do a write (upstream) op of <length> "
					 "bytes. If the file arg is specified"
                                         " will write file contents to memory. "
                                         " Uses len of file and size\n"
	"    -s --size                   size in bytes of opeartion\n";

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
	char clear = 0;
	bool reset = false;
	int fd = -1;
        int bin_fd = -1;
	int option;
	int rc;
	unsigned int pattern_length = DEFAULT_PATTERN_LENGTH;
	size_t fname_length = 0;
	uint8_t res;
	uint64_t host_addr;
	uint32_t aligned_len;
	uint32_t len =0;
	uint8_t *data_buf = NULL;
	uint8_t *vga_mem = NULL;
	char *data_arg = NULL;
	const char *xdma_dev = "/dev/aspeed-xdma";
        char *fname = NULL;
	const char *opts = "a:cd:hf:prwRs:";
	struct aspeed_xdma_op xdma_op;
	struct pollfd fds;
	struct option lopts[] = {
		{ "addr", 1, 0, 'a' },
		{ "clear", no_argument, 0, 'c' },
		{ "data", 1, 0, 'd' },
		{ "help", 0, 0, 'h' },
		{ "file", 1, 0, 'f' },
		{ "pattern", 0, 0, 'p' },
		{ "size", 1, 0, 's' },
		{ "read", no_argument, 0, 'r' },
		{ "write", no_argument, 0, 'w' },
		{ "reset", no_argument, 0, 'R' },
		{ 0, 0, 0, 0 }
	};

	while ((option = getopt_long(argc, argv, opts, lopts, NULL)) != -1) {
		switch (option) {
		case 'a':
			if ((rc = arg_to_u64(optarg, &host_addr)))
				goto done;
			break;
		case 'c':
			clear = 1;
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
                 case 'f':
			fname_length = strlen(optarg);
			fname = malloc(fname_length + 1);
			if (!fname) {
				rc = -ENOMEM;
				goto done;
			}

			strcpy(fname, optarg);
			break;
		case 'h':
			printf("%s", _help);
			goto done;
			break;
		case 'p':
			pattern = 1;
			break;
		case 'R':
			reset = true;
			break;
		case 'r':
			if (op) {
				log_err("Can't accept multiple commands,"
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

			op = 1;
			do_read = 0;
			break;
		case 's':
			if ((rc = arg_to_u32(optarg, &len)))
				goto done;
			break;
		}
	}

	if (!op && !reset) {
		log_err("No operation specified, aborting.\n");
		rc = -EINVAL;
		goto done;
	}


	fd = open(xdma_dev, O_RDWR);
	if (fd < 0) {
		log_err("Failed to open %s.\n", xdma_dev);
		rc = -ENODEV;
		goto done;
	}

	if (reset) {
		printf("Performing reset...\n");
		rc = ioctl(fd, ASPEED_XDMA_IOCTL_RESET);
		if (rc)
			log_err("Failed to reset: %s\n", strerror(errno));
		goto done;
	}

        // See if we are reading/writing to a file
        if(fname)
        {
            bin_fd = open(fname, do_read ? O_RDWR | O_CREAT | O_TRUNC : O_RDONLY, (mode_t)0600 );
            if (bin_fd < 0) {
		log_err("Failed to open %s.\n", fname);
		rc = -ENODEV;
		goto done;
            }

            //If a read seek to create the file size for mem map to cpy
            //Else write, use the bin file size as the length
            if(do_read){
                if (0 > (rc = lseek(bin_fd, len-1 , SEEK_SET))){
                    log_err("Failed[%s] to seek %d on %s\n", strerror(errno), len, fname);
                    goto done;
                }
                if ((rc = write(bin_fd, "", 1)) !=1){
                    log_err("Failed[%s] to put char on %s\n",strerror(errno), fname);
                    goto done;
                }
            } else {
                struct stat fbin_stats;
                rc = fstat(bin_fd, &fbin_stats);
                if(rc) {
                    log_err("fstat failed on %s, %s\n", fname, strerror(errno));
                    goto done;
                }
                len = fbin_stats.st_size;            
            }
            log_info("Doing %s of %s to/from 0x%llx for size %d\n",
                     do_read ? "read" : "write", fname, host_addr, len);

	}

        if (!len) {
            log_err("Zero length op specified,"
                    " aborting.\n");
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
        } else if(fname) {  // See if we are reading/writing to a file
            data_buf = mmap(NULL, aligned_len, do_read ? PROT_READ | PROT_WRITE : PROT_READ, MAP_SHARED,
                           bin_fd, 0);
            if (!data_buf) {
                log_err("Failed to mmap %s.\n", strerror(errno));
                rc = -ENOMEM;
                goto done;
            }

        }


	vga_mem = mmap(NULL, aligned_len, PROT_READ | PROT_WRITE, MAP_SHARED,
		       fd, 0);
	if (!vga_mem) {
		log_err("Failed to mmap %s.\n", strerror(errno));
		rc = -ENOMEM;
		goto done;
	}

       	if (!do_read) {
            if(fname){
                memcpy(vga_mem, data_buf, len);
            }else if (pattern) {
		do_pattern(vga_mem, aligned_len, pattern_length / 2, data_buf);
            }
	} else if (clear) {
		char *tmp = malloc(aligned_len);

		memset(tmp, 0, aligned_len);
		memcpy(vga_mem, tmp, aligned_len);
		free(tmp);
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

        if (do_read) {
            if(fname){
                memcpy(data_buf, vga_mem, len);
                msync(data_buf, len, MS_SYNC);
            }else {
		read_and_display(vga_mem, len);
            }
        }
done:
	if (vga_mem)
		munmap(vga_mem, aligned_len);

	if (fd >= 0)
		close(fd);

	if (data_buf)
            if(fname)
                munmap(data_buf, aligned_len);
            else    
		free(data_buf);

	if (bin_fd >= 0)
		close(bin_fd);

	if (data_arg)
		free(data_arg);


	return rc;
}
