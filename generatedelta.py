#!/usr/bin/python3
# SPDX-License-Identifier: GPL-2.0-only

import argparse
import os
from lib.image import parse_ifd_or_me
from lib.mfs import INTEL_IDX, FITC_IDX, HOME_IDX, MFS
from lib.cfg import CFG

def delta_from_fitc_cfg(overridable, fitc_files, output):
    if set(fitc_files.keys()).difference(overridable.keys()) != set():
        raise ValueError("fitc.cfg contains unexpected data, please report this for investigation")

    # This will only iterate fitc overridable paths
    for path, intel_file in overridable.items():
        # Skip dirs
        if intel_file.isDirectory():
            continue
        # Skip files not in fitc
        if path not in fitc_files:
            continue
        fitc_file = fitc_files[path]
        if intel_file.data != fitc_file.data:
            # Write out differing file to delta
            filepath = os.path.join(output, path.lstrip("/"))
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            with open(filepath, "wb") as f:
                f.write(fitc_file.data)

parser = argparse.ArgumentParser()
parser.add_argument("--input", required=True, help="Input vendor image (either full with IFD or just ME)")
parser.add_argument("--output", required=True, help="Output MFS delta directory")
args = parser.parse_args()

# Get ME from input image
with open(args.input, "rb") as f:
    me = parse_ifd_or_me(f.read())

# Parse MFS and get its system volume
mfs = MFS(me.entry_data("MFS"))
sysvol = mfs.getSystemVolume()

# Lookup table of directories and overridable paths in intel.cfg
intel_cfg = CFG(sysvol.getFile(INTEL_IDX).data)
overridable = { file.path: file for file in intel_cfg.files \
                if file.isDirectory() or (file.record.opt & 1) != 0 }

fitc_cfg = CFG(sysvol.getFile(FITC_IDX).data)

if fitc_cfg:
    # We have a fitc.cfg, so compute delta from that
    fitc_files = { file.path: file for file in fitc_cfg.files }
    delta_from_fitc_cfg(overridable, fitc_files, args.output)
else:
    # Otherwise we need to go digging through the home partition
    raise Error("FIXME: No fitc.cfg in image, we need to implement /home decomposition")
