#!/usr/bin/env python3

import xjalienfs.alien as alien

# in the case of AliEnMsg class just low-level json messages are exchanged with the server
# there are no client side implementations available, only message exchange with the AliEn central services
# default initialization have the 'dict' option enabled, with the efect that run command returns a dictionary

alien.setup_logging()

j = alien.AliEn()

out = j.run('pwd')
print(f"Output of type {type(out)}")
alien.PrintDict(out)
print()

out = j.run('pwd', 'rawstr')  # let's request to have the actual string
print(f"Output of type {type(out)}")
print('formated:')
alien.PrintDict(out)
print('raw and unformated:')
alien.PrintDict(out, opts = 'rawstr')
print()

out = j.run('pwd')
print(f"Output of type {type(out)}")
print('No metadata')
no_meta = alien.GetDict(out, 'nometa')
alien.PrintDict(no_meta)  # let's not print metadata
print('Just the content of \'results\'')
results_list = alien.GetDict(out, 'results')
alien.PrintDict(results_list)  # let's print just the results
print()

print('Let\'s just log the dictionary to the logfile with warning tag')
print(f'Check the log file {alien.DEBUG_FILE}')
alien.PrintDict(out, 'warn')  # let's not print metadata
print()

out = j.run('pwd', 'nokeys')
print(f"Output of type {type(out)}")
print('Let\'s not receive the keys values in the server response')
alien.PrintDict(out)
print()

out = j.run('pwd', 'nomsg')
print(f"Output of type {type(out)}")
print('Let\'s not receive the \'message\' values in the server response')
alien.PrintDict(out)
print()

