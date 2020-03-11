#!/usr/bin/env python3

import xjalienfs.alien as alien

# in the case of AliEnMsg class just low-level json messages are exchanged with the server
# there are no client side implementations available, only message exchange with the AliEn central services
# default initialization have the 'dict' option enabled, with the efect that run command returns a dictionary

alien.setup_logging()

j = alien.AliEnMsg()

out = j.run('pwd')
print(f"Output of type {type(out)}")
alien.PrintDict(out)
print()

out = j.run('pwd', ' ')  # let's disable the defaults, it will return a string
print(f"Output of type {type(out)}")
alien.PrintDict(out)  # PrintDict take either a string (which will be loaded as json dict) or a dictionary
print()

out = j.run('pwd', 'dict')
print(f"Output of type {type(out)}")
print('No metadata')
alien.PrintDict(out, 'nometa')  # let's not print metadata
print('Just the content of \'results\'')
alien.PrintDict(out, 'results')  # let's not print metadata
print()

# in fact lets just keep the results in a variable
another_out = alien.PrintDict(out, 'results return')  # let's not print metadata
print(f"Output of type {type(another_out)}")
print('Just the content of \'results\' saved in a variable')
alien.PrintDict(another_out)
print()

print('Let\'s just log the dictionary to the logfile with warning tag')
print(f'Check the log file {alien.DEBUG_FILE}')
alien.PrintDict(out, 'warn')  # let's not print metadata
print()

out = j.run('pwd', 'dict nokeys')
print(f"Output of type {type(out)}")
print('Let\'s not receive the keys values in the server response')
alien.PrintDict(out)
print()

out = j.run('pwd', 'dict nomsg')
print(f"Output of type {type(out)}")
print('Let\'s not receive the \'message\' values in the server response')
alien.PrintDict(out)
print()
print('Maybe we need a clean results list without un-needed \'message\' key')
my_clean_list = alien.PrintDict(out, 'return results')
print(f"Output of type {type(my_clean_list)}")
alien.PrintDict(my_clean_list)
print()
