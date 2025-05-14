#!/usr/bin/env python3

import sys

try:
    from alienpy import alien
except Exception:
    try:
        from xjalienfs import alien
    except Exception:
        print("Can't load alienpy, exiting...")
        sys.exit(1)


# in the case of AliEnMsg class just low-level json messages are exchanged with the server
# there are no client side implementations available, only message exchange with the AliEn central services
# default initialization have the 'dict' option enabled, with the effect that run command returns a dictionary

alien.setup_logging()

j = alien.AliEn()

out = j.run('pwd')
print(f"Output of type {type(out)}")
alien.retf_print(out)
print()

out = j.run('pwd', 'rawstr')  # let's request to have the actual string
print(f"Output of type {type(out)}")
print('formatted:')
alien.PrintDict(out)
print('raw and unformatted:')
print(out)
print()

out = j.run('pwd')
print(f"Output of type {type(out)}")
print('No metadata')
del out.ansdict['metadata']
alien.PrintDict(out.ansdict)  # let's not print metadata
print('Just the content of \'results\'')
alien.PrintDict(out.ansdict['results'])  # let's print just the results
print()

print('Let\'s just log the dictionary to the logfile with warning tag')
print(f'Check the log file {alien.DEBUG_FILE}')
alien.retf_print(out, 'warn')  # let's not print metadata
print()

out = j.run('pwd', 'nokeys')
print(f"Output of type {type(out)}")
print('Let\'s not receive the keys values in the server response')
alien.retf_print(out, 'json')
print()

out = j.run('pwd', 'nomsg')
print(f"Output of type {type(out)}")
print('Let\'s not receive the \'message\' values in the server response')
alien.retf_print(out, 'json')
print()

