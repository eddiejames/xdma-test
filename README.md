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

### 3) Probe driver

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

### 4) use xdma-test

```
xdma-test -a <host address> -p -w 4096
```
