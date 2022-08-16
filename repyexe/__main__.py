import sys
from .decompile import decompile_exe

def main():
    if len(sys.argv) == 1:
        print("Usage: repyexe <files>")
        sys.exit(1)

    files = sys.argv[1:]
    for file in files:
        decompile_exe(file)

if __name__ == "__main__":
    main()