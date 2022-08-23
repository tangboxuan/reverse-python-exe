import sys
import os
from .decompile import decompile_exe

def main():
    if len(sys.argv) == 1:
        print("Usage: repyexe <files and dirs>")
        sys.exit(1)

    inputs = sys.argv[1:]
    files = []
    while inputs:
        current = inputs.pop()
        if os.path.isdir(current):
            inputs += ["{}/{}".format(current, f) for f in os.listdir(current)]
        elif os.path.isfile(current):
            files.append(current)
        else:
            print("[!] File {} not found".format(current))

    good = []
    bad = []
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