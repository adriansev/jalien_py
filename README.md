# alien.py  
Python interface to web-socket based interface to ALICE Grid Services  
   
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

For debugging purposes there are 2 symlinks that modify the output format:  
`
alien_json -> alien.py  
alien_json_all -> alien.py  
`
  
alien_json will output the exact json of ['results']  
alien_json_all will output the full json answer (including ['metadata'])  
  
There are a few environment variables that influence the mechanics of the script :  
JALIENPY_DEBUG - if true, will activate some printouts  
JALIENPY_XRDDEBUG - if set will activate printout in XRootD commands and functions  
JALIEN_TOKEN_CERT, JALIEN_TOKEN_KEY - full path file descriptions of certificate,key token files  
JALIENPY_TIMECONNECT - enable for measurement of time for websocket creation - e.g. `JALIENPY_TIMECONNECT=1 alien.py pwd`  
   
   
X509 locations:  
X509_USER_CERT, X509_USER_KEY, X509_CERT_DIR   

To use a compile mode, one can declare the following bash functions:  
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

