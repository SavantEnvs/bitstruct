#!/usr/bin/env python3
"""Atheris harness for bitstruct's pure-Python format-string interpreter.

Port of the original mayhemheroes `pack-fuzz` driver (mayhemheroes/bitstruct
commit 855900a): fixed positional numeric/bytes/string args pulled directly
off the FuzzedDataProvider, fed straight into bitstruct.pack/unpack/calcsize
and pack_dict/unpack_dict. Kept byte-for-byte compatible with that driver so
the mhh-run-8 corpus still reaches the same code paths.
"""

import sys

import atheris
from fuzz_helpers import build_fuzz_dict, build_fuzz_list

with atheris.instrument_imports():
    import bitstruct


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    try:
        format_string = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 100))
        packed_data = bitstruct.pack(format_string, fdp.ConsumeInt(4), -fdp.ConsumeInt(4),
                       fdp.ConsumeRegularFloat(), fdp.ConsumeBool(), fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 100)),
                       fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 100)))
        bitstruct.unpack(format_string, packed_data)
        bitstruct.calcsize(format_string)

        # Dicts
        names = build_fuzz_list(fdp, [str])
        dict_format_string = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 100))
        packed_dict = bitstruct.pack_dict(dict_format_string, names, build_fuzz_dict(fdp, [str, int]))
        bitstruct.unpack_dict(dict_format_string, names, packed_dict)
    except (bitstruct.Error, MemoryError):
        return -1


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
