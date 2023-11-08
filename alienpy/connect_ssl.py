"""alienpy:: SSL and certificate tooling"""

import sys
import os
import logging
import uuid
import traceback
import datetime
import tempfile
import warnings
with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    try:
        import cryptography
    except Exception:
        print("cryptography module could not be imported! Make sure you can do:\npython3 -c 'import cryptography'", file = sys.stderr, flush = True)
        sys.exit(1)
try:
    import ssl
except Exception:
    print("Python ssl module could not be imported! Make sure you can do:\npython3 -c 'import ssl'", file = sys.stderr, flush = True)
    sys.exit(1)
try:
    import OpenSSL
except Exception:
    print("OpenSSL module could not be loaded", file = sys.stderr, flush = True)
    sys.exit(1)

##   GLOBALS
from .data_structs import CertsInfo, RET
from .global_vars import AlienSessionInfo, COLORS, DEBUG, DEBUG_FILE, TOKENCERT_NAME, TOKENKEY_NAME, USERCERT_NAME, USERKEY_NAME, USER_HOME
from .tools_nowb import PrintColor, path_readable
from .setup_logging import print_err


def get_ca_path() -> str:
    """Return either the CA path or file, priority given to X509_CERT_FILE and X509_CERT_DIR"""
    system_ca_path = '/etc/grid-security/certificates'
    alice_cvmfs_ca_path_lx = '/cvmfs/alice.cern.ch/etc/grid-security/certificates'
    alice_cvmfs_ca_path_macos = f'/Users/Shared{alice_cvmfs_ca_path_lx}'
    local_ca_certs_dir = f'{USER_HOME}/.globus/certificates'

    x509file = os.getenv('X509_CERT_FILE', default = '')
    x509dir = os.getenv('X509_CERT_DIR', default = '')

    use_local_cas_dir = os.getenv('ALIENPY_USE_LOCAL_CAS', default = '')
    capath_default = None
    if use_local_cas_dir:
        if os.path.isfile(f'{local_ca_certs_dir}/CERN-GridCA.pem'):
            capath_default = local_ca_certs_dir
        else:
            msg = 'usage of local CAs was requested by presence of ALIENPY_USE_LOCAL_CAS, but no certificates found there!!!\nrun: "alien.py getCAcerts" first'
            print_err(msg)
            logging.error(msg)
            sys.exit(2)
    elif x509dir and os.path.isfile(f'{x509dir}/CERN-GridCA.pem'):
        capath_default = x509dir
    elif x509file and os.path.isfile(x509file):
        capath_default = x509file
    elif os.path.isfile(f'{alice_cvmfs_ca_path_lx}/CERN-GridCA.pem'):
        capath_default = alice_cvmfs_ca_path_lx
    elif os.path.isfile(f'{alice_cvmfs_ca_path_macos}/CERN-GridCA.pem'):
        capath_default = alice_cvmfs_ca_path_macos
    elif os.path.isfile(f'{local_ca_certs_dir}/CERN-GridCA.pem'):
        capath_default = local_ca_certs_dir
    elif os.path.isfile(f'{system_ca_path}/CERN-GridCA.pem'):
        capath_default = system_ca_path
    else:
        msg = "No CA location or files specified or found!!! Connection will not be possible!! Run:\nalien.py getCAcerts\nto download CAs to local ~/.globus/certificates"
        print_err(msg)
        logging.error(msg)
        sys.exit(2)

    # if x509file is not used (or is missing) then just set X509_CERT_DIR to whatever capath_default was found to be valid
    if capath_default != x509file: os.environ['X509_CERT_DIR'] = capath_default

    dbg_msg = f'\nX509_CERT_FILE = {x509file}\nCAfile = {x509file}' if x509file else f'\nX509_CERT_DIR = {x509dir}\nCApath = {capath_default}'
    if DEBUG: logging.debug('%s', dbg_msg)
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


def get_valid_certs() -> tuple:
    """Return valid names for user certificate or None"""
    if 'AlienSessionInfo' in globals() and AlienSessionInfo['verified_cert']: return AlienSessionInfo['user_cert'], AlienSessionInfo['user_key']

    FOUND = path_readable(USERCERT_NAME) and path_readable(USERKEY_NAME)
    if not FOUND:
        msg = f'User certificate files NOT FOUND or NOT accessible!!! Connection might be not be possible!!\nCheck content of {os.path.expanduser("~")}/.globus'
        logging.error(msg)
        return None, None

    INVALID = not IsValidCert(USERCERT_NAME)
    if INVALID:
        msg = f'Invalid/expired user certificate!! Check the content of {USERCERT_NAME}'
        logging.error(msg)
        return None, None

    if 'AlienSessionInfo' in globals():
        AlienSessionInfo['verified_cert'] = True  # This means that we already checked
        AlienSessionInfo['user_cert'] = USERCERT_NAME
        AlienSessionInfo['user_key'] = USERKEY_NAME
    return USERCERT_NAME, USERKEY_NAME


def get_valid_tokens() -> tuple:
    """Get the token filenames, including the temporary ones used as env variables"""
    global TOKENCERT_NAME, TOKENKEY_NAME
    random_str = None
    cert_suffix = None
    ENV_TOKENCERT = ENV_TOKENKEY = None
    if not path_readable(TOKENCERT_NAME) and TOKENCERT_NAME.startswith('-----BEGIN CERTIFICATE-----'):  # and is not a file
        random_str = str(uuid.uuid4())
        cert_suffix = f'_{str(os.getuid())}_{random_str}.pem'
        temp_cert = tempfile.NamedTemporaryFile(prefix = 'tokencert_', suffix = cert_suffix, delete = False)
        temp_cert.write(TOKENCERT_NAME.encode(encoding = "ascii", errors = "replace"))
        temp_cert.close()
        TOKENCERT_NAME = temp_cert.name  # temp file was created, let's give the filename to tokencert
        ENV_TOKENCERT = True
    if not path_readable(TOKENKEY_NAME) and TOKENKEY_NAME.startswith('-----BEGIN RSA PRIVATE KEY-----'):  # and is not a file
        if random_str is None: random_str = str(uuid.uuid4())
        temp_key = tempfile.NamedTemporaryFile(prefix = 'tokenkey_', suffix = cert_suffix, delete = False)
        temp_key.write(TOKENKEY_NAME.encode(encoding = "ascii", errors = "replace"))
        temp_key.close()
        TOKENKEY_NAME = temp_key.name  # temp file was created, let's give the filename to tokenkey
        ENV_TOKENKEY = True

    if (IsValidCert(TOKENCERT_NAME) and path_readable(TOKENKEY_NAME)):
        if 'AlienSessionInfo' in globals():
            AlienSessionInfo['verified_token'] = True
            AlienSessionInfo['token_cert'] = TOKENCERT_NAME
            AlienSessionInfo['token_key'] = TOKENKEY_NAME
            if ENV_TOKENCERT: AlienSessionInfo['templist'].append(TOKENKEY_NAME)  # type: ignore[attr-defined]
            if ENV_TOKENKEY: AlienSessionInfo['templist'].append(TOKENCERT_NAME)  # type: ignore[attr-defined]
        return (TOKENCERT_NAME, TOKENKEY_NAME)
    return (None, None)


def renewCredFilesInfo() -> CertsInfo:
    """Recheck and refresh the values of valid credential definitions"""
    token_cert, token_key = get_valid_tokens()
    user_cert, user_key = get_valid_certs()
    return CertsInfo(user_cert, user_key, token_cert, token_key)


# Populate information in AlienSessionInfo
_ = renewCredFilesInfo()


def create_ssl_context(use_usercert: bool = False, user_cert: str = '', user_key: str = '', token_cert: str = '', token_key: str = '') -> ssl.SSLContext:
    """Create SSL context using either the default names for user certificate and token certificate or X509_USER_{CERT,KEY} JALIEN_TOKEN_{CERT,KEY} environment variables"""
    if use_usercert or not token_cert:
        if AlienSessionInfo: AlienSessionInfo['use_usercert'] = True
        cert, key = user_cert, user_key
    else:
        cert, key = token_cert, token_key

    if not cert or not key:
        print_err('create_ssl_context:: no certificate to be used for SSL context. This message should not be printed, contact the developer if you see this!!!')
        return None

    if DEBUG: logging.debug('\nCert = %s\nKey = %s\nCreating SSL context .. ', cert, key)
    ssl_protocol = ssl.PROTOCOL_TLS if sys.version_info[1] < 10 else ssl.PROTOCOL_TLS_CLIENT
    ctx = ssl.SSLContext(ssl_protocol)
    ctx.options |= ssl.OP_NO_SSLv3
    ctx.verify_mode = ssl.CERT_REQUIRED  # CERT_NONE, CERT_OPTIONAL, CERT_REQUIRED
    ctx.check_hostname = False

    ca_verify_location = get_ca_path()
    cafile = capath = None
    if os.path.isfile(ca_verify_location):
        cafile = ca_verify_location
    else:
        capath = ca_verify_location

    if DEBUG: logging.debug('SSL context:: Loading verify location:\n%s', ca_verify_location)
    try:
        ctx.load_verify_locations(cafile = cafile, capath = capath)
    except Exception:
        logging.exception('Could not load verify location!!!\n')
        print_err(f'Verify location could not be loaded!!! check content of >>> {ca_verify_location} <<< and the log')
        return None  # EIO /* I/O error */

    if DEBUG: logging.debug('SSL context:: Loading cert,key pair:\n%s\n%s', cert, key)
    try:
        ctx.load_cert_chain(certfile = cert, keyfile = key)
    except Exception:
        logging.exception('Could not load certificates!!!\n')
        print_err(f'Error loading certificate pair!! Check the content of {DEBUG_FILE}')
        return None  # EIO /* I/O error */

    if DEBUG: logging.debug('\n... SSL context done.')
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
