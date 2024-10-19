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

As a board porter, you need to:

1. Provide the delta between the default and vendor provided ME configuration.

   This goes in the `data/delta/<target>` directory for each target.

   To obtain this, dump the vendor firmware from your board, and execute:

    `./generatedelta.py --input <dump> --output data/delta/<target>`

   FIXME the dump needs to be ran through FIT first to work for now but this can be fixed.

2. Generate fake FPF data for the board that overrides the default configuration.

   This goes in the `data/fpfs/<target>` directory for each target.

   FIXME explain how to do this.

## Generating images for an existing target

As a user wishing to generate an image for a supported target:

1. You will need to obtain a donor image for your platform variant with a supported ME version (see URLs below).

   This can either be a full image with a flash descriptor or just a bare ME region.

2. Execute the following command and enjoy:

    `./finalimage.py --delta data/mfs/<target> --version <donor version> --pch <H or LP PCH type> --fake-fpfs data/fpfs/<target> --input <donor> --output <output>`

   Plaese note that the output will be a bare deguard patched ME region and **the HAP bit must be
   enabled** in your flash descriptor for a deguard generated ME image to work.

## Donor images

This section lists some URLs to recommended and tested donor images. Any image with a supported firmware
version and variant ought to work, but the path of least resistance is for everyone to use the same images.

|Version|Variant|URL|
|-|-|-|
|11.6.0.1126|H (Desktop)|[link](https://web.archive.org/web/20230822134231/https://download.asrock.com/BIOS/1151/H110M-DGS(7.30)ROM.zip)|
|11.6.0.1126|LP (Laptop)|FIXME find a donor|

## Thanks

Thanks goes to PT Research and Youness El Alaoui for previous work on exploiting Intel SA 00086, which this PoC is heavily reliant on.

- [IntelTXE-PoC](https://github.com/kakaroto/IntelTXE-PoC)
- [MFSUtil](https://github.com/kakaroto/MFSUtil)
