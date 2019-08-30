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
jsh:CERN: /alice/cern.ch/user/a/asevcenc/ > pwd  
/alice/cern.ch/user/a/asevcenc/  
jsh:CERN: /alice/cern.ch/user/a/asevcenc/ > ls /  
alice  
bin  
jdl  
remote  
root  
scripts  
test  
tmp  
var  
jsh:CERN: /alice/cern.ch/user/a/asevcenc/ >  
```
For both command and interctive mode multiple commands can be issued separated by `;`  
For command mode the full string must be enclosed by either double or single quotes  
The interactive mode save the command history in `${HOME}/.alienpy_history` and it can be navigated with Up/Down keys  
`!` is understood as running into shell whatever command follows  
and `|` pipe whatever output of AliEn command to a shell command (that follows after the `|`)

There are a few environment variables that influence the mechanics of the script :  
JALIEN_TOKEN_CERT, JALIEN_TOKEN_KEY - will overwrite the defaults, full path certificate,key token files  
If set these X509 locations will be used:  
X509_USER_CERT, X509_USER_KEY, X509_CERT_DIR   

For debugging purposes there are a few environment toggles :  
ALIENPY_DEBUG - if set, will activate some printouts, and all output will be the raw json content  
ALIENPY_DEBUG_WS - if set, will activate DEBUG level logging of websocket module  
ALIENPY_XRDDEBUG - if set will activate printout in XRootD commands and functions  
ALIENPY_TIMECONNECT - if set will report time for websocket creation - e.g. `ALIENPY_TIMECONNECT=1 alien.py pwd`  
a `time` command was added that, when prefixed to any other command, will report the time taken for command execution  

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
-S <parallel nr chunks> : copy using the specified number of TCP connections
-chksz <bytes> : chunk size (bytes)
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
   
#######################  
To use a compiled mode, one can declare the following bash functions:  
```
j_py_compile () {
    DIR=$(dirname $(which alien.py))
    cd ${DIR}
    python3 -OO -m py_compile alien.py
}

j ()          { python3 ${HOME}/bin/alien.py "${@}" ;}
j_json ()     { python3 ${HOME}/bin/alien_json "${@}" ;}
j_json_all () { python3 ${HOME}/bin/alien_json_all "${@}" ;}
```

