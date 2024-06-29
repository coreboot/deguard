#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only

set -e

if [ ! -f "me.bin" ]; then
	wget "https://download.asrock.com/BIOS/1151/H110M-DGS(7.30)ROM.zip"
	unzip "H110M-DGS(7.30)ROM.zip" H11MDGS7.30
	rm "H110M-DGS(7.30)ROM.zip"
	dd if=H11MDGS7.30 of=me.bin skip=1 count=511 bs=4096
	rm H11MDGS7.30
fi

dd if=me.bin of=MFS.part skip=168 count=100 bs=4096

# Extract file number 7 (fitc.cfg)
python3 MFSUtil.py -m MFS.part -x -i 7 -o fitc.cfg

# Remove /home/mca/eom
python3 MFSUtil.py -c fitc.cfg -r -f /home/mca/eom -o fitc.cfg
# Remove /home/bup/ct
python3 MFSUtil.py -c fitc.cfg -r -f /home/bup/ct -o fitc.cfg

# list off files differing in optiplex 3050 fw vs donor
files="
bup/bup_sku/emu_fuse_map
bup/bup_sku/plat_n_sku
fwupdate/fwuoemid
icc/prof0
mctp/device_ports
pavp/hdcp_ports
policy/cfgmgr/cfg_rules
secureboot/bootpolres
secureboot/bootpoltype
secureboot/enfpolicy
secureboot/kmid
secureboot/pubkeyhash
"

for i in $files
do
	python3 MFSUtil.py -c fitc.cfg -r -f /home/$i -o fitc.cfg
done

# Add /home/mca/eom
dd if=/dev/zero of=eom count=1 bs=1
python3 MFSUtil.py -c fitc.cfg --add eom --alignment 2 --mode ' --Irw-r-----' \
	--opt '?!-F' --uid 0 --gid 238 -f /home/mca/eom -o fitc.cfg

# Add /home/bup/ct
python3 gen_shellcode.py -p H -v 11.6.0.1126
python3 MFSUtil.py -c fitc.cfg --add ct  --alignment 2 --mode ' ---rwxr-----' \
	--opt '?--F' --uid 3 --gid 351 -f /home/bup/ct -o fitc.cfg

# Add dell files
python3 MFSUtil.py -c fitc.cfg --add data/emu_fuse_map --alignment 2 --mode=' ---rw-r-----' --opt='?--F' --uid=3  --gid=238 -f /home/bup/bup_sku/emu_fuse_map -o fitc.cfg
python3 MFSUtil.py -c fitc.cfg --add data/plat_n_sku   --alignment 2 --mode=' ---rw-r-----' --opt='?--F' --uid=3  --gid=238 -f /home/bup/bup_sku/plat_n_sku -o fitc.cfg
python3 MFSUtil.py -c fitc.cfg --add data/fwuoemid     --alignment 2 --mode=' ---rw-rw----' --opt='?--F' --uid=32 --gid=238 -f /home/fwupdate/fwuoemid -o fitc.cfg
python3 MFSUtil.py -c fitc.cfg --add data/prof0        --alignment 2 --mode=' ---rw-r-----' --opt='?--F' --uid=55 --gid=238 -f /home/icc/prof0 -o fitc.cfg
python3 MFSUtil.py -c fitc.cfg --add data/device_ports --alignment 2 --mode=' ---rw-r-----' --opt='?--F' --uid=73 --gid=238 -f /home/mctp/device_ports -o fitc.cfg
python3 MFSUtil.py -c fitc.cfg --add data/hdcp_ports   --alignment 2 --mode=' -EIrw-r-----' --opt='?!-F' --uid=80 --gid=238 -f /home/pavp/hdcp_ports -o fitc.cfg
python3 MFSUtil.py -c fitc.cfg --add data/cfg_rules    --alignment 2 --mode=' ---rw-rw----' --opt='-!MF' --uid=85 --gid=238 -f /home/policy/cfgmgr/cfg_rules -o fitc.cfg
python3 MFSUtil.py -c fitc.cfg --add data/bootpolres   --alignment 2 --mode=' ---rw-rw----' --opt='?-MF' --uid=3  --gid=238 -f /home/secureboot/bootpolres -o fitc.cfg
python3 MFSUtil.py -c fitc.cfg --add data/bootpoltype  --alignment 2 --mode=' ---rw-rw----' --opt='?-MF' --uid=3  --gid=238 -f /home/secureboot/bootpoltype -o fitc.cfg
python3 MFSUtil.py -c fitc.cfg --add data/enfpolicy    --alignment 2 --mode=' ---rw-rw----' --opt='?-MF' --uid=3  --gid=238 -f /home/secureboot/enfpolicy -o fitc.cfg
python3 MFSUtil.py -c fitc.cfg --add data/kmid         --alignment 2 --mode=' ---rw-r-----' --opt='?-MF' --uid=3  --gid=238 -f /home/secureboot/kmid -o fitc.cfg
python3 MFSUtil.py -c fitc.cfg --add data/pubkeyhash   --alignment 2 --mode=' ---rw-rw-r--' --opt='?-MF' --uid=3  --gid=238 -f /home/secureboot/pubkeyhash -o fitc.cfg

# Delete file id 7 (fitc.cfg) from the MFS partition
python3 MFSUtil.py -m MFS.part -r -i 7 -o MFS.part
# Delete file id 8 (home) from the MFS partition
python3 MFSUtil.py -m MFS.part -r -i 8 -o MFS.part

# Add the modified fitc.cfg into the MFS partition
python3 MFSUtil.py -m MFS.part -a fitc.cfg --deoptimize -i 7 -o MFS.part

# Write
dd conv=notrunc if=MFS.part of=me.bin seek=168 count=100 bs=4096

# Resize for optiplex
truncate -s 7335936 me.bin

# Cleanup
rm ct eom fitc.cfg MFS.part
