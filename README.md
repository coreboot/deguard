# Bypass Intel BootGuard on ME v11.x.x.x hardware

This utility allows generating BootGuard bypass images for hardware running ME v11.x.x.x firmware.

This includes Skylake, Kaby Lake, and some Coffee Lake PCHs. Both the H (desktop) and LP (mobile) firmware
varaints are supported.

## Background

This uses [CVE-2017-5705](https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00086.html).

It has been fixed by Intel in newer ME v11.x.x.x firmware releases, however ME11 hardware has no protection
against downgrading the ME version by overwriting the SPI flash physically, thus we can downgrade to a vulnerable
version.

After downgrade, we exploit the bup module of the vulnerable firmware, overwriting the copy of field programmable fuses
stored in SRAM, resulting in the fused BootGuard configuration being replaced with our desired one.

## Adding new target

You will need to provide the delta between the default and vendor provided ME configuration.

This goes in the `data/delta/<target>` directory for each target.

To obtain this, dump the vendor firmware from your board, and execute:

`./generatedelta.py --input <dump> --output data/delta/<target>`

Note the delta generation only takes your factory dump as an input. This is because an ME image contains both the
default and system specific configuration, and these can be compared by deguard.

You *must discard* the `/home/secureboot` directory from the delta for the zero FPF config to work.

You can optionally also discard `home/{amt,fwupdate,pavp,ptt}` from the delta.

## Generating images for an existing target

First, the **the HAP bit must be enabled** in your flash descriptor for deguard generated ME images to work.

This can be set using `ifdtool` (the modified flash descriptor will have a `.new` extension):

`ifdtool -p sklkbl -M 1 ifd.bin`

You will then need to obtain a donor image for your platform variant with a supported ME version (see URLs below).

This can either be a full image with a flash descriptor or just a bare ME region.

To generate a deguard patched ME image, execute the following command:

`./finalimage.py --delta data/delta/<target> --version <donor version> --pch <H or LP PCH type> --sku <2M or 5M SKU> --fake-fpfs data/fpfs/zero --input <donor> --output <output>`

The output will be a bare deguard patched ME region.

## DCI Debugging over USB

Both the and main CPU cores, and ME core can be debugged using DCI (JTAG over USB essentially).

You will need:

-  USB 3.0 A-to-A cable with the VBUS pin removed to connect the target and your system running the debugger. This can be purchased pre-made, or the pin can be removed from a commodity cable.

- Enable the DCI bit in the flash descriptor (See CB: 82272).

- To debug the main CPU: firmware, or kernel mode software has to set the consent bit (See CB: 83268).

- To debug the ME core itself: Red Unlock needs to be enabled in the deguard patched ME image (see `--red-unlock`). Please note that red unlock has disastrous ramifications for the security of the running system and should only be used for debugging.

## Donor images

This section lists some URLs to recommended and tested donor images. Any image with a supported firmware
version and variant ought to work, but the path of least resistance is for everyone to use the same images.

|Version|Variant|SKU|URL|Notes|
|-|-|-|-|-|
|11.6.0.1126|H (Desktop)|2M|[link](https://web.archive.org/web/20230822134231/https://download.asrock.com/BIOS/1151/H110M-DGS(7.30)ROM.zip)|Zipped flash image|
|11.6.0.1126|LP (Laptop)|2M|[link](https://web.archive.org/web/20241110222323/https://dl.dell.com/FOLDER04573471M/1/Inspiron_5468_1.3.0.exe)|Dell BIOS update (use [Dell_PFS_Extract.py](https://github.com/vuquangtrong/Dell-PFS-BIOS-Assembler/blob/master/Dell_PFS_Extract.py))|

## Thanks

Thanks goes to PT Research and Youness El Alaoui for previous work on exploiting Intel SA 00086, which this PoC is heavily reliant on.

- [IntelTXE-PoC](https://github.com/kakaroto/IntelTXE-PoC)
- [MFSUtil](https://github.com/kakaroto/MFSUtil)
