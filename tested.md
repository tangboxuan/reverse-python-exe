## Tested on

1. Evilnum Pyvil RAT compiled using Py2exe in 3.7

    | MD5 | SHA256 |
    | :---: | :---: |
    | 0fff692652ec73d4f17438284a720224 | 5b159b58ee73c3330b1599913c6a7f66e4aaecad536223474fc8b6bb7700cd2f
    | 14d9d03cbb892bbbf9939ee8fffdd2b5 | 824626e09bffec0ee539d0165df0d9a1ef668d32d8fcccf13708d24e108d7cf9
    | b4183e52fb807689140ed5aa20808700 | 3fb323ad790d26fa319577e179190c1b25840a2aeffbe11072cce48f1bafde89 |
    | bb2113989478db0ae1dfbf6450079252 | d0c313a1983498abadb5ff36cb66aca5d2fc8893cbd6d40f9a85c6274fe5c8a3
    | d3947c239a07090deb7d4a9d21d68813 | 5988265627e2935865a2255f90d10c83b54046137834cb4c81748f2221971a4b | 
    | 15baf177fc6230ce2fcb483b052eb539[^1] | f67ae8c384ce028fdb09dac32341f1d8f9c59949ad594efad04b27527112e56c|
    | 6d0b710057c82e7ccd59a125599c8753[^1] |  f75ba590e17468b743b20ca40c6846be0128511794a2d1eb2c039aa1170477c5 |
    | bab0b5bb50c349cefd9dedf869eb0013[^1] | 12efa6d0f23346f2a6081969528839cc8712676f8f1e3658b1d15cd4bd7d3b5b |

1. Triton ICS Malware compiled using Py2exe in 2.7

    | MD5 | SHA256 |
    | :---: | :---: |
    | 6c39c3f4a08d3d78f2eb973a94bd7718 | e8542c07b2af63ee7e72ce5d97d91036c5da56e2b091aa2afe737b224305d230 |

1. Example exe and pyc files found in [/samples](https://github.com/tangboxuan/reverse-python-exe/tree/main/samples)

[^1]: Some ```JUMP``` instructions to ```EXTENDED_ARG``` instructions result in an error in uncompyle6's ifelsestmt.py file. Make the following [changes](https://github.com/tangboxuan/python-uncompyle6/commit/81633b3c1c3ae49120c755bd3ddfbc80ed452633) to the file.