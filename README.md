# xdma-test

The xdma-test application performs DMA operations between the BMC and the host.
A PCI driver is needed on the host; this is provided in the host/ directory.

## Setup

### 1) Install kernel sources (depends on linux distro)

Then usally found in /usr/src/kernels/

### 2) Compile driver

```
cd host/
make -C <path to kernel source> M=$PWD
```

### 3) Make sure to enable VGA device on BMC

### 4) Probe driver

If the existing ast graphics driver is running on the host (check for 'ast'
with lsmod) it must first be removed.

To obtain the device name (probably "0002:02:00.0"):
```
ls /sys/bus/pci/drivers/ast/
echo <device name> > /sys/bus/pci/drivers/ast/unbind
rmmod ast
```

Then probe our driver:
```
insmod ast-bmc-pcie.ko
```

Finally, check dmesg for the host address to use with xdma-test, usually
0x60000000.

### 5) Use xdma-test

Compile the xdma-test under openbmc sdk and copy it to the BMC node.
Run the test on BMC node.
```
xdma-test -a <host address> -p -w -s 4096
```

### 6) Verify

The host driver provides a device file to check the target memory space to
verify that the transfer went through.

```
dd if=/dev/ast-bmc-mem of=/tmp/vga bs=1024 count=4; cat /tmp/vga | hexdump -C
```
