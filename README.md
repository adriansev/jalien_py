# alien.py  
Python interface to web-socket endpoint of ALICE Grid Services  
   
Can be used as command mode and interactive mode :  
1. Command mode :  
`alien.py <command>  `
e.g :  
`alien.py pwd  `
   
2. Interactive mode e.g :  
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
For both command and interctive mode multiple commands can be issued separated by `;`  
For command mode the full string must be enclosed by either double or single quotes  
The interactive mode save the command history in `${HOME}/.alienpy_history` and it can be navigated with Up/Down keys  
`!` is understood as running into shell whatever command follows  
and `|` pipe whatever output of AliEn command to a shell command (that follows after the `|`)

There are a few environment variables that influence the mechanics of the script :  
JALIEN_TOKEN_CERT, JALIEN_TOKEN_KEY - will overwrite the defaults, full path certificate,key token files  
If set these X509 locations will be used:  
X509_USER_CERT, X509_USER_KEY, X509_CERT_DIR or X509_CERT_FILE  

For debugging purposes there are a few environment toggles :  
ALIENPY_DEBUG - if set, the raw json content will be printed and all debug meesages will be found in $HOME/alien_py.log   
ALIENPY_XRDDEBUG - if set will activate printouts of XRootD related functions in the same $HOME/alien_py.log   
ALIENPY_TIMECONNECT - if set will report time for websocket creation - e.g. `ALIENPY_TIMECONNECT=1 alien.py pwd`     
a `time` command was added that, when prefixed to any other command, will report the time taken for command execution     
ALIENPY_TIMEOUT - set the value of websocket timeout waiting for server answer; default is 20, increase for large find or ps commands   
ALIENPY_JCENTRAL - it will connect to this server, ignoring any other options   
   
For XRootD operations the native XRootD env toggles are used, see [docs](https://xrootd.slac.stanford.edu/doc/man/xrdcp.1.html#ENVIRONMENT "XRootD xrdcopy documentation")   

`cat/more/less` will download the target lfn to a temporary file and will act upon it while  
`vi/nano/mcedit` will, after the modification of downloaded temporary, backup the existing lfn, and upload the modified file  

#######################  
```cp``` option  

cp can take as arguments both files and directories and have the following options:  
```
alien.py cp -h
at least 2 arguments are needed : src dst
the command is of the form of (with the strict order of arguments):
cp args src dst
where src|dst are local files if prefixed with file:// or grid files otherwise
after each src,dst can be added comma separated arguments like: disk:N,SE1,SE2,!SE3
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
-select <pattern> : select only these files (AliEn find semantics) to be copied; defaults to all "."
-parent <parent depth> : in destination use this <parent depth> to add to destination ; defaults to 0
-a : copy also the hidden files .* (for recursive copy)
-j <queue_id> : select only the files created by the job with <queue_id>  (for recursive copy)
-l <count> : copy only <count> nr of files (for recursive copy)
-o <offset> : skip first <offset> files found in the src directory (for recursive copy)
```

the ```-select``` takes as argument an AliEn ```find``` pattern for downloads from GRID   
and a full PCRE expression when uploading from local to GRID  
   
```-parent``` will keep in the name of the found files a number of <depth> directories from the src directory  
`-a` `-j` `-l` and `-o` are arguments of AliEn ```find``` command and are used for downloading from GRID operations  
   
