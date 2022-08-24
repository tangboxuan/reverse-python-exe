import unittest
from io import StringIO
import os
import sys
from repyexe.decompile import decompile_exe

sys.stdout = open(os.devnull, 'w')

class Test(unittest.TestCase):
    pass

def checkdecompile(filename):
    outfile = StringIO()
    decompile_exe(samplepath + filename, outstream=outfile)
    outfile.seek(0)
    content = outfile.read()
    with open(answerpath + filename.split('.')[0], "r") as f:
        answer = f.read()
    return content.endswith(answer)

def test_generator(filename):
    def test(self):
        self.assertTrue(checkdecompile(filename))
    return test

if __name__ == '__main__':
    version = "python{}{}/".format(sys.version_info.major, sys.version_info.minor)
    samplepath = "samples/" + version
    answerpath = "testcases/" + version
    for filename in os.listdir(samplepath):
        test_name = "test_{}".format(filename)
        test = test_generator(filename)
        setattr(Test, test_name, test)
    unittest.main()