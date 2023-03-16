'''alienpy:: SSL and certificate tooling'''

import logging
from pathlib import Path

try:
    import ssl
except Exception:
    print("Python ssl module could not be imported! Make sure you can do:\npython3 -c 'import ssl'", file = sys.stderr, flush = True)
    sys.exit(1)

try:
    import cryptography
except Exception:
    print("cryptography module could not be imported! Make sure you can do:\npython3 -c 'import cryptography'", file = sys.stderr, flush = True)
    sys.exit(1)

try:
    import OpenSSL
except Exception:
    print("OpenSSL module could not be loaded", file = sys.stderr, flush = True)
    sys.exit(1)

##   GLOBALS
from .global_vars import *
from .data_structs import *
from .tools_misc import *
from .tools_files import *


TOKENCERT_NAME = f'{TMPDIR}/tokencert_{str(os.getuid())}.pem'
TOKENKEY_NAME = f'{TMPDIR}/tokenkey_{str(os.getuid())}.pem'


def get_files_cert() -> tuple:
    return os.getenv('X509_USER_CERT', f'{Path.home().as_posix()}/.globus/usercert.pem'), os.getenv('X509_USER_KEY', f'{Path.home().as_posix()}/.globus/userkey.pem')


def get_token_names(files: bool = False) -> tuple:
    if files:
        return TOKENCERT_NAME, TOKENKEY_NAME
    return os.getenv('JALIEN_TOKEN_CERT', TOKENCERT_NAME), os.getenv('JALIEN_TOKEN_KEY', TOKENKEY_NAME)


def get_ca_path() -> str:
    """Return either the CA path or file; bailout application if not found"""
    DEBUG = os.getenv('ALIENPY_DEBUG', '')

    system_ca_path = '/etc/grid-security/certificates'
    alice_cvmfs_ca_path_lx = '/cvmfs/alice.cern.ch/etc/grid-security/certificates'
    alice_cvmfs_ca_path_macos = f'/Users/Shared{alice_cvmfs_ca_path_lx}'

    x509file = os.getenv('X509_CERT_FILE') if os.path.isfile(str(os.getenv('X509_CERT_FILE'))) else ''
    if x509file:
        if DEBUG: logging.debug('X509_CERT_FILE = %s', x509file)
        return x509file

    x509dir = os.getenv('X509_CERT_DIR') if os.path.isdir(str(os.getenv('X509_CERT_DIR'))) else ''
    if x509dir:
        if DEBUG: logging.debug('X509_CERT_DIR = %s', x509dir)
        return x509dir

    capath_default = None
    if os.path.exists(alice_cvmfs_ca_path_lx):
        capath_default = alice_cvmfs_ca_path_lx
    elif os.path.exists(alice_cvmfs_ca_path_macos):
        capath_default = alice_cvmfs_ca_path_macos
    else:
        if os.path.exists(system_ca_path): capath_default = system_ca_path

    if not capath_default:
        msg = "No CA location or files specified or found!!! Connection will not be possible!!"
        print_err(msg)
        logging.error(msg)
        sys.exit(2)
    if DEBUG: logging.debug('CApath = %s', capath_default)
    return capath_default


def IsValidCert(fname: str) -> bool:
    """Check if the certificate file (argument) is present and valid. It will return false also for less than 5min of validity"""
    try:
        with open(fname, encoding="ascii", errors="replace") as f:
            cert_bytes = f.read()
    except Exception:
        logging.error('IsValidCert:: Unable to open certificate file %s', fname)
        return False

    try:
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_bytes)  # type: ignore[attr-defined]
    except Exception:
        logging.error('IsValidCert:: Unable to load certificate %s', fname)
        return False

    x509_notafter = x509.get_notAfter()
    utc_time = datetime.datetime.strptime(x509_notafter.decode("utf-8"), "%Y%m%d%H%M%SZ")
    time_notafter = int((utc_time - datetime.datetime(1970, 1, 1)).total_seconds())
    time_current = int(datetime.datetime.now().timestamp())
    time_remaining = time_notafter - time_current
    if time_remaining < 1:
        logging.error('IsValidCert:: Expired certificate %s', fname)
    return time_remaining > 300


def get_valid_tokens() -> tuple:
    """Get the token filenames, including the temporary ones used as env variables"""
    global AlienSessionInfo
    tokencert, tokenkey = get_token_names()
    random_str = None
    cert_suffix = None
    if not path_readable(tokencert) and tokencert.startswith('-----BEGIN CERTIFICATE-----'):  # and is not a file
        random_str = str(uuid.uuid4())
        cert_suffix = f'_{str(os.getuid())}_{random_str}.pem'
        temp_cert = tempfile.NamedTemporaryFile(prefix = 'tokencert_', suffix = cert_suffix, delete = False)
        temp_cert.write(tokencert.encode(encoding = "ascii", errors = "replace"))
        temp_cert.seek(0)
        tokencert = temp_cert.name  # temp file was created, let's give the filename to tokencert
        AlienSessionInfo['templist'].append(tokencert)  # type: ignore[attr-defined]
    if not path_readable(tokenkey) and tokenkey.startswith('-----BEGIN RSA PRIVATE KEY-----'):  # and is not a file
        if random_str is None: random_str = str(uuid.uuid4())
        temp_key = tempfile.NamedTemporaryFile(prefix = 'tokenkey_', suffix = cert_suffix, delete = False)
        temp_key.write(tokenkey.encode(encoding = "ascii", errors = "replace"))
        temp_key.seek(0)
        tokenkey = temp_key.name  # temp file was created, let's give the filename to tokenkey
        AlienSessionInfo['templist'].append(tokenkey)  # type: ignore[attr-defined]

    if (IsValidCert(tokencert) and path_readable(tokenkey)):
        AlienSessionInfo['verified_token'] = True
        return (tokencert, tokenkey)
    return (None, None)


def get_valid_certs() -> tuple:
    """Return valid names for user certificate or None"""
    global AlienSessionInfo
    usercert, userkey = get_files_cert()
    if AlienSessionInfo['verified_cert']: return usercert, userkey

    INVALID = False
    if not (path_readable(usercert) and path_readable(userkey)):
        msg = f'User certificate files NOT FOUND or NOT accessible!!! Connection will not be possible!!\nCheck content of {os.path.expanduser("~")}/.globus'
        logging.info(msg)
        INVALID = True
    if not IsValidCert(usercert):
        msg = f'Invalid/expired user certificate!! Check the content of {usercert}'
        logging.info(msg)
        INVALID = True
    AlienSessionInfo['verified_cert'] = True  # This means that we already checked
    if INVALID: return None, None
    return usercert, userkey


def get_valid_auth_cred(use_usercert: bool = False) -> tuple:
    """Return tuple of valid cert files to be used for ssl context"""
    global AlienSessionInfo, tokencert, tokenkey, usercert, userkey
    usercert, userkey = get_valid_certs()
    tokencert, tokenkey = get_valid_tokens()

    # token auth
    if not use_usercert and tokencert: return (tokencert, tokenkey)

    # usercert auth
    AlienSessionInfo['use_usercert'] = True
    return (usercert, userkey)


def create_ssl_context(use_usercert: bool = False) -> ssl.SSLContext:
    """Create SSL context using either the default names for user certificate and token certificate or X509_USER_{CERT,KEY} JALIEN_TOKEN_{CERT,KEY} environment variables"""
    cert, key = get_valid_auth_cred(use_usercert)
    if not cert:
        print_err('create_ssl_context:: no certificate to be used for SSL context. This message should not be printed, contact the developer if you see this!!!')
        os._exit(126)

    DEBUG = os.getenv('ALIENPY_DEBUG', '')
    if DEBUG: logging.debug('\nCert = %s\nKey = %s\nCreating SSL context .. ', cert, key)
    ssl_protocol = ssl.PROTOCOL_TLS if sys.version_info[1] < 10 else ssl.PROTOCOL_TLS_CLIENT
    ctx = ssl.SSLContext(ssl_protocol)
    ctx.options |= ssl.OP_NO_SSLv3
    ctx.verify_mode = ssl.CERT_REQUIRED  # CERT_NONE, CERT_OPTIONAL, CERT_REQUIRED
    ctx.check_hostname = False
    if DEBUG: logging.debug("SSL context:: Load verify locations")

    ca_verify_location = get_ca_path()
    cafile = capath = None
    if os.path.isfile(ca_verify_location):
        cafile = ca_verify_location
    else:
        capath = ca_verify_location

    try:
        ctx.load_verify_locations(cafile = cafile, capath = capath)
    except Exception:
        logging.exception('Could not load verify location >>> %s <<<\n', ca_verify_location)  # EIO /* I/O error */
        print_err(f'Verify location could not be loaded!!! check content of >>> {ca_verify_location} <<< and the log')
        os._exit(126)

    if DEBUG: logging.debug('SSL context:: Loading cert,key pair\n%s\n%s', cert, key)
    try:
        ctx.load_cert_chain(certfile = cert, keyfile = key)
    except Exception:
        logging.exception('Could not load certificates!!!\n')  # EIO /* I/O error */
        print_err('Error loading certificate pair!! Check the content of {DEBUG_FILE}')
        os._exit(126)

    if DEBUG: logging.debug('... SSL context done.')
    return ctx


def CertInfo(fname: str) -> RET:
    """Print certificate information (subject, issuer, notbefore, notafter)"""
    try:
        with open(fname, encoding = "ascii", errors = "replace") as f:
            cert_bytes = f.read()
    except Exception:
        return RET(2, '', f'File >>>{fname}<<< not found')  # ENOENT /* No such file or directory */

    try:
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_bytes)
    except Exception:
        return RET(5, '', f'Could not load certificate >>>{fname}<<<')  # EIO /* I/O error */

    utc_time_notafter = datetime.datetime.strptime(x509.get_notAfter().decode("utf-8"), "%Y%m%d%H%M%SZ")
    utc_time_notbefore = datetime.datetime.strptime(x509.get_notBefore().decode("utf-8"), "%Y%m%d%H%M%SZ")
    issuer = '/'.join([f'{k.decode("utf-8")}={v.decode("utf-8")}' for k, v in x509.get_issuer().get_components()])
    subject = '/'.join([f'{k.decode("utf-8")}={v.decode("utf-8")}' for k, v in x509.get_subject().get_components()])
    info = f'DN >>> {subject}\nISSUER >>> {issuer}\nBEGIN >>> {utc_time_notbefore}\nEXPIRE >>> {utc_time_notafter}'
    return RET(0, info)


def CertVerify(fname: str) -> RET:
    """Print certificate information (subject, issuer, notbefore, notafter)"""
    try:
        with open(fname, encoding="ascii", errors="replace") as f:
            cert_bytes = f.read()
    except Exception:
        return RET(2, "", f"File >>>{fname}<<< not found")  # ENOENT /* No such file or directory */

    try:
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_bytes)
    except Exception:
        logging.debug(traceback.format_exc())
        return RET(5, "", f"Could not load certificate >>>{fname}<<<")  # EIO /* I/O error */

    x509store = OpenSSL.crypto.X509Store()
    x509store.set_flags(OpenSSL.crypto.X509StoreFlags.ALLOW_PROXY_CERTS)

    ca_verify_location = get_ca_path()
    cafile = capath = None
    if os.path.isfile(ca_verify_location):
        cafile = ca_verify_location
    else:
        capath = ca_verify_location

    try:
        x509store.load_locations(cafile = cafile, capath = capath)
    except Exception:
        logging.debug(traceback.format_exc())
        return RET(5, "", f"Could not load verify location >>>{ca_verify_location}<<<")  # EIO /* I/O error */

    store_ctx = OpenSSL.crypto.X509StoreContext(x509store, x509)
    try:
        store_ctx.verify_certificate()
        return RET(0, f'SSL Verification {PrintColor(COLORS.BIGreen)}succesful{PrintColor(COLORS.ColorReset)} for {fname}')
    except Exception:
        logging.debug(traceback.format_exc())
        return RET(1, '', f'SSL Verification {PrintColor(COLORS.BIRed)}failed{PrintColor(COLORS.ColorReset)} for {fname}')


def CertKeyMatch(cert_fname: str, key_fname: str) -> RET:
    """Check if Certificate and key match"""
    try:
        with open(cert_fname, encoding="ascii", errors="replace") as f: cert_bytes = f.read()
        x509cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_bytes)
    except Exception:
        logging.debug(traceback.format_exc())
        return RET(5, "", f'Could not load certificate >>>{cert_fname}<<<')  # EIO /* I/O error */

    try:
        with open(key_fname, encoding="ascii", errors="replace") as g: key_bytes = g.read()
        x509key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, key_bytes)
    except Exception:
        logging.debug(traceback.format_exc())
        return RET(5, "", f'Could not load key >>>{key_fname}<<<')  # EIO /* I/O error */

    ctx = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD)  # skipcq: PTC-W6001
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.use_privatekey(x509key)
    ctx.use_certificate(x509cert)

    ca_verify_location = get_ca_path()
    cafile = capath = None
    if os.path.isfile(ca_verify_location):
        cafile = ca_verify_location
    else:
        capath = ca_verify_location

    try:
        ctx.load_verify_locations(cafile = cafile, capath = capath)
    except Exception:
        logging.debug(traceback.format_exc())
        return RET(5, "", f"Could not load verify location >>>{ca_verify_location}<<<")  # EIO /* I/O error */    
    
    try:
        ctx.check_privatekey()
        return RET(0, f'Cert/key {PrintColor(COLORS.BIGreen)}match{PrintColor(COLORS.ColorReset)}')
    except OpenSSL.SSL.Error:
        return RET(0, '', f'Cert/key {PrintColor(COLORS.BIRed)}DO NOT match{PrintColor(COLORS.ColorReset)}')


if __name__ == '__main__':
    print('This file should not be executed!', file = sys.stderr, flush = True)
    sys.exit(95)
    
    
