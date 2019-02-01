# jalien_py
Python interface to web-socket based interface to ALICE Grid Services

Can be used as command mode and interactive mode :  
1. Command mode :  
./j <command>  
e.g :  
./j pwd  
   
2. Interactive mode e.g :  
./j  
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
   
For debugging purposes there are 2 symlinks that modify the output format:  
lrwxrwxrwx 1 1 Jan 31 15:13 j_json -> j  
lrwxrwxrwx 1 1 Jan 31 15:13 j_json_all -> j  
  
j_json will output the exact json of ['results']  
j_json_all will output the full json answer (including ['metadata'])  
  
There are a few environment variables that influence the mechanics of the script :  
JALIENPY_DEBUG - if true, will activate some printouts  
JALIEN_TOKEN_CERT, JALIEN_TOKEN_KEY - full path file descriptions of certificate,key token files  
   
X509 locations:  
X509_USER_CERT, X509_USER_KEY, X509_CERT_DIR   

