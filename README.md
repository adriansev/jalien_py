![PyPI](https://img.shields.io/pypi/v/alienpy?style=plastic)  

## alien.py - Python interface to websocket endpoint of ALICE Grid Services  

### Basic usage
Can be used as command mode and interactive mode :  
1. Command mode :  
`alien.py <command>  `
e.g :  
`alien.py pwd  `  
**N.B.** command/arguments must be quoted to avoid being interpreted by the shell:  
`alien.py 'rm my_alien_dir/*'`

2. Interactive/shell mode e.g :  
```
alien.py
Welcome to the ALICE GRID
support mail: adrian.sevcenco@cern.ch

AliEn[asevcenc]:/alice/cern.ch/user/a/asevcenc/ >pwd
/alice/cern.ch/user/a/asevcenc/
AliEn[asevcenc]:/alice/cern.ch/user/a/asevcenc/ >whoami
asevcenc
AliEn[asevcenc]:/alice/cern.ch/user/a/asevcenc/ >
```
* For both command and shell mode multiple commands can be issued separated by `;`  
* The interactive mode save the command history in `${HOME}/.alienpy_history` and it can be navigated with Up/Down keys  
* `!` is understood as running into shell whatever command follows  
* `|` pipe whatever output of AliEn command to a shell command (that follows after the first(only the first) `|`)

### Environment steering

There are a few environment variables that influence the mechanics of the script :  
* JALIEN_TOKEN_CERT, JALIEN_TOKEN_KEY - will overwrite the defaults, full path certificate,key token files  
* If set these X509 locations will be used:   
   X509_USER_CERT, X509_USER_KEY, X509_CERT_DIR or X509_CERT_FILE  
* ALIENPY_TIMEOUT will change the interval for keep-alive mechanics.

For debugging purposes there are a few environment toggles :  
* ALIENPY_DEBUG - if set, the raw json content will be printed and all debug meesages will be found in $HOME/alien_py.log   
* ALIENPY_DEBUG_FILE - set the location of log file   
**N.B.** the logfile is per session! It will be overwritten by a new session and mangled by parallel sessions (to be addressed) 
* ALIENPY_TIMECONNECT - if set will report time for websocket creation - e.g. `ALIENPY_TIMECONNECT=1 alien.py pwd`     
* ALIENPY_JCENTRAL - it will connect to this server, ignoring any other options   
* ALIENPY_NO_STAGGER - disable staggered parallel host resolution and socket creation (see [RFC8305](https://tools.ietf.org/html/rfc8305))
* ALIENPY_JSON - print the unprocessed json message from the server   
* ALIENPY_JSONRAW - print the unprocessed byte stream message from the server   
   
For XRootD operations the native XRootD environment toggles are used, see [docs](https://xrootd.slac.stanford.edu/doc/man/xrdcp.1.html#ENVIRONMENT "XRootD xrdcopy documentation")   

## Authentication
The authentication process needs the presence of a X509 certificate (enrolled into ALICE VO, see [here](https://alien.web.cern.ch/content/vo/alice/userregistration))
and of a CA certificates directory for verification.
The default CA location that will be searched is within alice.cern.ch cvmfs repository
If not found, the CApath will default to /etc/grid-security/certificates
If these locations are not available, one _must_ set X509_CERT_DIR to a valid location


## Command usage and examples  

The list of available commands can seen with: `?` or `help`   
Command help can be listed with: `? command`, `help command`, `command -h`  

### Storage related operations
This section refer to any copy to/from grid or file interactions.   

`cat/more/less` will download the target lfn to a temporary file and will act upon it while  
`vi/nano/mcedit/edit` will, after the modification of downloaded temporary, backup the existing lfn, and upload the modified file  
The target file upload can support grid specifiers like those described in `cp` command e.g. `edit my_file@disk:2,SE1`  

#### ```cp``` option  

cp can take as arguments both files and directories and have the following options:  
```
alien.py cp -h
at least 2 arguments are needed : src dst
the command is of the form of (with the strict order of arguments):
cp args src dst
where src|dst are local files if prefixed with file:// or just file: and grid files otherwise; alien:// are allowed but ignored.
after each src,dst can be added comma separated specifiers in the form of: @disk:N,SE1,SE2,!SE3
where disk selects the number of replicas and the following specifiers add (or remove) storage endpoints from the received list
args are the following :
-h : print help
-f : replace any existing output file
-P : enable persist on successful close semantic
-y <nr_sources> : use up to the number of sources specified in parallel
-S <aditional TPC streams> : uses num additional parallel streams to do the transfer. The maximum value is 15. The default is 0 (i.e., use only the main stream).
-chunks <nr chunks> : number of chunks that should be requested in parallel
-chunksz <bytes> : chunk size (bytes)
-T <nr_copy_jobs> : number of parralel copy jobs from a set (for recursive copy)

for the recursive copy of directories the following options (of the find command) can be used:
-select <pattern> : select only these files to be copied; N.B. this is a REGEX applied to full path!!! defaults to all ".*"
-name <pattern> : select only these files to be copied; N.B. this is a REGEX applied to a directory or file name!!! defaults to all ".*"
-name <verb>_string : where verb = begin|contain|ends|ext and string is the text selection criteria. verbs are aditive : -name begin_myf_contain_run1_ends_bla_ext_root
N.B. the text to be filtered cannont have underline <_> within!!!
-parent <parent depth> : in destination use this <parent depth> to add to destination ; defaults to 0
-a : copy also the hidden files .* (for recursive copy)
-j <queue_id> : select only the files created by the job with <queue_id>  (for recursive copy)
-l <count> : copy only <count> nr of files (for recursive copy)
-o <offset> : skip first <offset> files found in the src directory (for recursive copy)
```

`.`, `..` are interpreted for all grid names (lfns)  
`%ALIEN` is converted to user AliEn home directory  
lfns that don't start with a `/` will have the current directory appended before being processed

### Miscellaneous

#### The shell prompt
It can show date and/or local directory:   
* `prompt date` will toggle on/off the date  
* `prompt pwd` will toggle on/off the local current directory  
For permanent setting the following are env variables are available : ALIENPY_PROMPT_DATE, ALIENPY_PROMPT_CWD   
```
AliEn[asevcenc]:/alice/cern.ch/user/a/asevcenc/ >prompt date
2020-02-07T16:49:05 AliEn[asevcenc]:/alice/cern.ch/user/a/asevcenc/ >

AliEn[asevcenc]:/alice/cern.ch/user/a/asevcenc/ >prompt pwd
AliEn[asevcenc]:/alice/cern.ch/user/a/asevcenc/ local:/home.hdd/adrian/work-GRID/jalien_py >
```

#### `ls` aliases
`ll`, `la`, `lla` are aliases to `ls -l`, `ls -a`, `ls -la`

#### CWD persistence
By default, the shell mode will remember the location of the last directory and a new session will use the previous cwd   
This bevahiour can be disabled with the env var ALIENPY_NO_CWD_RESTORE   

#### Custom aliases   
A fixed file `${HOME}/.alienpy_aliases` can be used to define alias=string pairs that will be used(translated) in the usage of alien.py. One can do `myalias=cmd1;cmd2;cmd3` and the `myalias` string will be replaced by it's value when used.   

