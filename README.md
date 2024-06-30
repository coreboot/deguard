# Intel BootGuard disable PoC for the Dell OptiPlex 3050

Run './RUNME.sh' to generate an ME image that bypasses BootGuard on the OptiPlex 3050.

## What hardware is vulnerable?

Any machine running Intel ME v11.x.x.x. This includes Skylake, Kaby Lake, and some Coffee Lake PCHs.

## How it works?

This uses [CVE-2017-5705](https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00086.html).

It has been fixed by Intel in newer ME v11.x.x.x firmware releases, however ME11 hardware has no protection
against downgrading the ME version by overwriting the SPI flash physically, thus we can downgrade to a vulnerable
version.

After downgrade, we exploit the bup module of the vulnerable firmware, overwriting the copy of boot guard FPFs
stored in SRAM, resulting in the fused boot guard configuration being replaced with our desired one.

In the case of the OptiPlex 3050, we disable verified boot enforcement, letting the user boot any firmware and
control their hardware.

## Note on code quality

The code in this repository is copy pasted from various places and was haphazardly modified until it
generated the desired image. It is no example on how to write good software :)

I am planning on releasing a better utility that accomplishes the same task in the future that
is generic to all Skylake and Kaby Lake machines, stay tuned!

## Thanks

Thanks goes to PT Research and Youness El Alaoui for previous work on exploiting Intel SA 00086, which this PoC is heavily reliant on.

- [IntelTXE-PoC](https://github.com/kakaroto/IntelTXE-PoC)
- [MFSUtil](https://github.com/kakaroto/MFSUtil)
