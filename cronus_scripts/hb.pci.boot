#!/bin/sh

# NOTE:
# This Cronus script must be run from an lcb that has python 3 (ie lcb329)
# User must have access/permissions to cronus and general P9 lab space
# System must have power before begining ("obmcutil chassison") and a 
# Cronus connection/config ("systemctl start croserver")
# This is all run against a lab system with the imprint secureboot key (won't work with
# production key security
#
# It has been tested against a P9 system + AST2600.  Following devmem commands
# are needed to open up the BMC PCIe space
#     devmem 0x1E6E2C20 32 0x003CFF57  #  VGA mmio, lpc, mctp, dma :: BMC MMIO, LPC, MSI, MCTP, INT, DMA  E2L
#     devmem 0x1E6E20c8 32 0x0 # Enable P2A
#     devmem 0x1E7E0F18 32 0xB8000000  #BMC remap address -- same as LPC window
#     devmem 0x1E7E0F10 32 0xFC000001  #Host size access of 0x0400_0000

# At the end of the script the xdma-test app can be used to read/write the first 4GB of host memory
# and "HIOMAP" memory can be accessed via PCIE (along with SIO, VUART, etc) 
# 
# PCIe address map:
#  VGA:
#     Region 0: Memory at 600c104000000 (32-bit, non-prefetchable) [size=8M]
#     Region 1: Memory at 600c104800000 (32-bit, non-prefetchable) [size=256K]  #PCIe 2 AHB (P2A) space
#     Region 3: Memory at 600c104880000 (32-bit, non-prefetchable) [size=4K]    #BMC LPC space
# PBMC:
#     Region 0: Memory at 600c100000000 (32-bit, non-prefetchable) [size=64M]   #BMC LPC memory map
#     Region 1: Memory at 600c104840000 (32-bit, non-prefetchable) [size=256K]


setconfig IPL_OPTIONS istep_fw
setconfig GLOBAL_DEBUG none
setconfig USE_SBE_FIFO on
sshpass -p 0penBmc ssh -k root@$1 '/usr/sbin/mboxctl --reset' && istep startipl && putcfam pu 283a 6 1 1 -ib && istep -s2..14 || exit 1
setconfig HW_PROCEDURE_PATH /afs/awd/projects/eclipz/lab/p9/u/pcibu/hw_ekb/output/lib/
setconfig HWP_ATTRIBUTE_FILE `pwd`"/base_hwp_attribute_file_phb_phase4"
putscom pu 04011092 0600C3C020000000 -quiet || exit 1 #PHB BAR 
putscom pu 0401108E 0600800000000000 -quiet || exit 1 #PHB 64BIT bar0
putscom pu 0401108F FFFFC00000000000 -quiet || exit 1 #PHB 64BIT mask
putscom pu 04011090 0600C10000000000 -quiet || exit 1 #PHB 32Bit bar1
putscom pu 04011091 FFFFFF8000000000 -quiet || exit 1 #PHB 32BIT mask
putscom pu 04011094 E000000000000000 -quiet || exit 1 #PHB BAR Enble (0 - bar0, 1 bar1, 2- phb , 3 - int)	
p9_phb4_init -p0 -c2 || exit 1 #BMC PHB x1 
check_link_status_mst -p0 -c2 || exit 1


#Setup necessary bus routing for cfg cycles to work:
#putmemproc 600c3c0201018 00010200 -ci  #root: pri = 0, sec = 1, sub = 2
cfg_cycle -p0 -c2 -b1 -d0 -f0 18 00020201 #ast2600 bridge pri = 1, sec = 2, sub = 2

#Read the various revision IDs
getmemproc 600c3c0201000 4 -ci -quiet #PHB root
cfg_cycle -p0 -c2 -b1 -d0 -f0 0 -quiet #AST2600 bridge
cfg_cycle -p0 -c2 -b2 -d0 -f0 0 -quiet #AST2600 VGA
cfg_cycle -p0 -c2 -b2 -d1 -f0 0 -quiet #AST2600 BMC

#Configure the PCIe bus
./cfg_pcie_ioa || exit 1


echo "##################################################"
echo "# Testing PCIe BMC memory map"
echo "# HIO MAP (PART layout)"
echo "# MCTP LPC binding config"
echo "########"
getmemproc 600c100000000 256  -ci -omema -quiet #PBMC mem vpnor
getmemproc 600c103F00000 4  -ci -omema -quiet   #PBMC MCTP buf

echo "##################################################"
echo "# Testing P2A interface to BMC LPC memory mapping"
echo "########"
putmemproc 600c10480f000 01000000 -ci  -quiet  #enable P2A bus
getmemproc 600c10480f000 4 -ci  -quiet         #check state
putmemproc 600c10480f004 000000b8 -ci  -quiet  #LE 0xB800_0000 to map to PNOR
getmemproc 600c10480f004 4 -ci  -quiet         #check addr
getmemproc 600c104810000 256 -ci -omema -quiet 

echo "##################################################"
echo "# Testing SIO access -- expect version of 0x26"
echo "########"
putmemproc 600c1048800b8  0xAA000000 -ci  -quiet #SIO LOCK
putmemproc 600c1048800b8  0xA5000000 -ci  -quiet #SIO unlock
putmemproc 600c1048800b8  0xA5000000 -ci  -quiet #SIO unlock
putmemproc 600c1048800b8  0x20000000 -ci  -quiet #Write SIO ID reg to indirect addr reg
getmemproc 600c1048800bc  1    -ci  -quiet       #Read SIO ID reg indirect data reg

exit 0


