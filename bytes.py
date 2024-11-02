# Simple python scripts to read binary file

import sys

if __name__ == "__main__":
    args = sys.argv[1:]

    if len(args) < 2:
        print("Usage: python bytes.py <src> <output>")
        sys.exit(1)

    SRC = args[0]
    OUT = args[1]

    driver_bytes = []
    with open(SRC, "rb") as f:
        driver_bytes = f.read()

    driver_c = f"#include \"driver_res.hpp\"\n\nunsigned char driver_bytes_res[] = {{ {', '.join(f'0x{byte:02X}' for byte in driver_bytes)} }};"
    with open(OUT, "w") as f:
        f.write(driver_c)