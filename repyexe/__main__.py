import argparse
import os
import sys
from .decompile import decompile_exe
from .utilities import options

parser = argparse.ArgumentParser(
    prog="repyexe",
    description="Reverse Engineer Windows executable file compiled using Python"
)
parser.add_argument(
    "files", 
    nargs="+", 
    help="one of more folders or files to decompile"
)
parser.add_argument(
    "-o", "--output",
    metavar="NAME",
    default="output",
    help="specify output directory name (default:output)"
)
parser.add_argument(
    "-d", "--debug",
    action="store_true",
    help="prints (deobfuscated) bytecode to stdout"
)

def main():
    args = parser.parse_args()
    inputs = args.files
    options["debug"] = args.debug
    if not args.output.isalnum():
        print("Invalid output directory name (no nested folders allowed)")
        sys.exit(1)
    options["output"] = args.output

    files = []
    bad = []
    while inputs:
        current = inputs.pop()
        if os.path.isdir(current):
            inputs += ["{}/{}".format(current, f) for f in os.listdir(current)]
        elif os.path.isfile(current):
            files.append(current)
        else:
            print("[!] File or folder {} not found".format(current))
            bad.append("{} ---> Not found".format(current))

    good = []
    count = 1
    for file in files:
        print('#' * 70)
        print("Decompiling {} out of {}".format(count, len(files)))
        success, remark = decompile_exe(file)
        count += 1
        if success:
            good.append("{0} --> {1}".format(file, remark))
        else:
            bad.append("{0} --> {1}".format(file, remark))
    if good:
        print("#"*70)
        print("The following {} files were successfully decompiled:".format(len(good)))
        print("\n".join(good))
    if bad:
        print("#"*70)
        print("The following {} files were not successfully decompiled:".format(len(bad)))
        print("\n".join(bad))


if __name__ == "__main__":
    main()