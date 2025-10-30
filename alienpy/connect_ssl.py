"""alienpy:: SSL and certificate tooling"""

import datetime
import sys
import os
import logging
import uuid
import tempfile
import ssl
from typing import Optional

try:
    from cryptography import x509
except Exception:
    print("cryptography module could not be imported! Make sure you can do:\npython3 -c 'import cryptography'", file = sys.stderr, flush = True)
    sys.exit(1)

try:
    import OpenSSL
except Exception:
    print("OpenSSL module could not be loaded", file = sys.stderr, flush = True)
    sys.exit(1)

##   GLOBALS
from .setup_logging import DEBUG, DEBUG_FILE, print_err
from .data_structs import CertsInfo, RET, SSLctxException
from .global_vars import AlienSessionInfo, COLORS, TOKENCERT_NAME, TOKENKEY_NAME, USERCERT_NAME, USERKEY_NAME, USER_HOME, I_AM_GRID_JOB
from .tools_nowb import PrintColor, path_readable


def is_x509dir_valid(x509dir: str = '') -> bool:
    """Determine validity of X509_CERT_DIR"""
    if not os.path.isdir(x509dir): return False
    pem_files_in_dir = [f for f in os.listdir(x509dir) if os.path.isfile(f'{x509dir}/{f}') and f.endswith('.pem')]
    return len(pem_files_in_dir) > 0


def get_ca_path() -> str:
    """Return either the CA path or file, priority given to X509_CERT_FILE and X509_CERT_DIR"""
    # Fast path, when some local CAs are explicitly requested - ALIENPY_USE_LOCAL_CAS case
    local_ca_certs_dir = f'{USER_HOME}/.globus/certificates'
    use_local_cas_dir = os.getenv('ALIENPY_USE_LOCAL_CAS', default = '')

    if use_local_cas_dir:  # explicit requested by env var, so top priority
        # if ALIENPY_USE_LOCAL_CAS is set to a directory that is present we can assume that is the CAs location
        if os.path.isdir(use_local_cas_dir):
            local_ca_certs_dir = use_local_cas_dir

        # This is location of ALIEN-CAS repository download
        if is_x509dir_valid(local_ca_certs_dir) and os.path.isfile(f'{local_ca_certs_dir}/CERN-GridCA.pem'):
            logging.debug(f'CApath::LOCAL_CAS:: requested and set to {local_ca_certs_dir}')
            os.environ['X509_CERT_DIR'] = local_ca_certs_dir
            return local_ca_certs_dir

        msg = f'usage of local CAs was requested by presence of ALIENPY_USE_LOCAL_CAS, but no certificates found in {local_ca_certs_dir}!!!\nrun: "alien.py getCAcerts" first'
        print_err(msg)
        logging.error(msg)
        # do not exit, is fine to have empty CA path, to allow non-wb functions to work, including getCAcerts

    # Fast path 2, when some local CAs are explicitly requested - X509_CERT_DIR case
    x509dir = os.getenv('X509_CERT_DIR', default = '')
    if x509dir:
        if is_x509dir_valid(x509dir):
            logging.debug(f'CApath::X509_CERT_DIR:: requested and set to {x509dir}')
            return x509dir

        msg = f'X509_CERT_DIR set by environment is invalid! Check content of {x509dir}'
        print_err(msg)
        logging.error(msg)
        # do not exit, is fine to have empty CA path, to allow non-wb functions to work, including getCAcerts

    # X509_CERT_FILE case
    x509file = os.getenv('X509_CERT_FILE', default = '')
    if x509file:
        if os.path.isfile(x509file):
            logging.debug(f'CApath::X509_CERT_FILE:: requested and set to {x509file}')
            return x509file

        msg = f'X509_CERT_FILE set by environment but is missing! Check existence of {x509file}'
        print_err(msg)
        logging.error(msg)
        # do not exit, is fine to have empty CA path, to allow non-wb functions to work, including getCAcerts

    system_ca_path = '/etc/grid-security/certificates'
    alice_cvmfs_ca_path_lx = '/cvmfs/alice.cern.ch/etc/grid-security/certificates'
    alice_cvmfs_ca_path_macos = f'/Users/Shared{alice_cvmfs_ca_path_lx}'

    capath_default = ''

    if is_x509dir_valid(alice_cvmfs_ca_path_lx):
        capath_default = alice_cvmfs_ca_path_lx

    if not capath_default and is_x509dir_valid(alice_cvmfs_ca_path_macos):
        capath_default = alice_cvmfs_ca_path_macos

    if not capath_default and is_x509dir_valid(system_ca_path):
        capath_default = system_ca_path

    if not capath_default:
        msg = "No CA locations found!!! Connection will not be possible!! Either set X509_CERT_DIR to a known good CApath or run:\nalien.py getCAcerts\nto download CAs to ~/.globus/certificates"
        print_err(msg)
        logging.error(msg)
        # do not exit, is fine to have empty CA path, to allow non-wb functions to work, including getCAcerts

    if not capath_default: capath_default = 'empty_notvalid'
    os.environ['X509_CERT_DIR'] = capath_default
    logging.debug(f'CApath:: found and set to {capath_default}')
    return capath_default


def IsValidCert(fname: str) -> bool:
    """Check if the certificate file (argument) is present and valid. It will return false also for less than 5min of validity"""
    if not fname: return False
    cert_bytes = None
    try:
        with open(fname, "rb") as f: cert_bytes = f.read()
    except FileNotFoundError:
        if not I_AM_GRID_JOB:
            logging.error('IsValidCert:: certificate file %s not found', fname)
            base_fname = os.path.basename(fname)
            if 'tokencert' in base_fname or 'token' in base_fname:
                logging.error('IsValidCert:: This is a token check, it is normal to be missing')
        return False
    except Exception as e:
        if DEBUG: logging.exception(e)
        logging.error('IsValidCert:: Unknown exception reading %s', fname)
        return False

    if cert_bytes is None:
        msg = f'IsValidCert:: {fname} read but empty!'
        logging.error(msg)
        return False

    x509cert = None
    try:
        x509cert = x509.load_pem_x509_certificate(cert_bytes)
    except Exception as e:
        if DEBUG: logging.exception(e)
        logging.error('IsValidCert:: Unable to load certificate %s', fname)
        return False

    time_remaining = int(x509cert.not_valid_after_utc.timestamp()) - int(datetime.datetime.now(datetime.timezone.utc).timestamp())

    if time_remaining < 600:
        msg = f'IsValidCert:: Expired certificate {fname}'
        if DEBUG: print_err(msg)
        logging.error(msg)
    return time_remaining >= 600


def get_valid_certs() -> tuple:
    """Return valid names for user certificate or None"""
    if 'AlienSessionInfo' in globals() and AlienSessionInfo['verified_cert']: return AlienSessionInfo['user_cert'], AlienSessionInfo['user_key']

    FOUND = path_readable(USERCERT_NAME) and path_readable(USERKEY_NAME)
    if not FOUND:
        msg = None
        if I_AM_GRID_JOB:
            if DEBUG: msg = 'GRID jobs do not use usercert files, usercert missing is fine.'
        else:
            msg = f'User certificate files NOT FOUND or NOT accessible!!! Connection might be not be possible!!\nCheck content of {os.path.expanduser("~")}/.globus'
        if msg: logging.error(msg)
        return (None, None)

    INVALID = not IsValidCert(USERCERT_NAME)
    if INVALID:
        msg = f'Invalid/expired user certificate!! Check the content of {USERCERT_NAME}'
        logging.error(msg)
        return (None, None)

    if 'AlienSessionInfo' in globals():
        AlienSessionInfo['verified_cert'] = True  # This means that we already checked
        AlienSessionInfo['user_cert'] = USERCERT_NAME
        AlienSessionInfo['user_key'] = USERKEY_NAME
    return (USERCERT_NAME, USERKEY_NAME)


def get_valid_tokens() -> tuple:
    """Get the token filenames, including the temporary ones used as env variables"""
    global TOKENCERT_NAME, TOKENKEY_NAME
    cert_suffix = None
    ENV_TOKENCERT = ENV_TOKENKEY = None
    if not path_readable(TOKENCERT_NAME) and TOKENCERT_NAME.startswith('-----BEGIN CERTIFICATE-----'):  # and is not a file
        cert_suffix = f'_{str(os.getuid())}_{str(uuid.uuid4())}.pem'
        temp_cert = tempfile.NamedTemporaryFile(prefix = 'tokencert_', suffix = cert_suffix, delete = False)
        temp_cert.write(TOKENCERT_NAME.encode(encoding = "ascii", errors = "replace"))
        temp_cert.close()
        TOKENCERT_NAME = temp_cert.name  # temp file was created, let's give the filename to tokencert
        ENV_TOKENCERT = True
    if not path_readable(TOKENKEY_NAME) and TOKENKEY_NAME.startswith('-----BEGIN RSA PRIVATE KEY-----'):  # and is not a file
        temp_key = tempfile.NamedTemporaryFile(prefix = 'tokenkey_', suffix = cert_suffix, delete = False)
        temp_key.write(TOKENKEY_NAME.encode(encoding = "ascii", errors = "replace"))
        temp_key.close()
        TOKENKEY_NAME = temp_key.name  # temp file was created, let's give the filename to tokenkey
        ENV_TOKENKEY = True

    if IsValidCert(TOKENCERT_NAME) and path_readable(TOKENKEY_NAME):
        if 'AlienSessionInfo' in globals():
            AlienSessionInfo['verified_token'] = True
            AlienSessionInfo['token_cert'] = TOKENCERT_NAME
            AlienSessionInfo['token_key'] = TOKENKEY_NAME
            if ENV_TOKENCERT: AlienSessionInfo['templist'].append(TOKENCERT_NAME)  # type: ignore[attr-defined]
            if ENV_TOKENKEY: AlienSessionInfo['templist'].append(TOKENKEY_NAME)  # type: ignore[attr-defined]
        return (TOKENCERT_NAME, TOKENKEY_NAME)
    return (None, None)


def renewCredFilesInfo() -> CertsInfo:
    """Recheck and refresh the values of valid credential definitions"""
    token_cert, token_key = get_valid_tokens()
    user_cert, user_key = get_valid_certs()
    return CertsInfo(user_cert, user_key, token_cert, token_key)


def create_ssl_context(use_usercert: bool = False, user_cert: str = '', user_key: str = '', token_cert: str = '', token_key: str = '') -> ssl.SSLContext:
    """Create SSL context using either the default names for user certificate and token certificate or X509_USER_{CERT,KEY} JALIEN_TOKEN_{CERT,KEY} environment variables"""
    if use_usercert or not token_cert:
        if AlienSessionInfo: AlienSessionInfo['use_usercert'] = True
        cert, key = user_cert, user_key
    else:
        cert, key = token_cert, token_key

    if not cert or not key:
        print_err('create_ssl_context:: no certificate to be used for SSL context. This message should not be printed')
        return None

    if DEBUG: logging.debug('\nCert = %s\nKey = %s\nCreating SSL context .. ', cert, key)
    ssl_protocol = ssl.PROTOCOL_TLS if sys.version_info[1] < 10 else ssl.PROTOCOL_TLS_CLIENT
    ctx = ssl.SSLContext(ssl_protocol)
    ctx.options |= ssl.OP_NO_SSLv3
    ctx.verify_mode = ssl.CERT_REQUIRED  # CERT_NONE, CERT_OPTIONAL, CERT_REQUIRED
    ctx.check_hostname = False

    # ca_verify_location = get_ca_path()
    cafile = capath = None
    if os.path.isfile(CA_PATH):
        cafile = CA_PATH
    else:
        capath = CA_PATH

    logging.info('SSL context:: Loading verify location:\n%s', CA_PATH)
    try:
        ctx.load_verify_locations(cafile = cafile, capath = capath)
    except Exception as e:
        logging.error(f'Could not load verify location {CA_PATH}!!!\n')
        if DEBUG: logging.exception(e)
        print_err(f'Verify location could not be loaded!!! check content of >>> {CA_PATH} <<< and the log')
        return None  # EIO /* I/O error */

    if DEBUG: logging.debug('SSL context:: Loading cert,key pair:\n%s\n%s', cert, key)
    try:
        ctx.load_cert_chain(certfile = cert, keyfile = key)
    except Exception as e:
        logging.error(f'Could not load cert/key pair:\nCert: {cert}\nKey: {key}\n')
        if DEBUG: logging.exception(e)
        print_err(f'Error loading certificate pair!! Check the content of {DEBUG_FILE}')
        return None  # EIO /* I/O error */

    logging.info('\n... SSL context done.')
    return ctx


def make_connection_ctx(use_usercert: bool = False) -> Optional[ssl.SSLContext]:
    """Create SSL context using AlienSessionInfo information"""
    ctx = None
    # Check the content of AlienSessionInfo for values of cert and token files
    certs_info = None
    user_cert = user_key = token_cert = token_key = ''

    if 'AlienSessionInfo' in globals() and AlienSessionInfo['token_cert'] and AlienSessionInfo['token_key'] and AlienSessionInfo['user_cert'] and AlienSessionInfo['user_key']:
        user_cert, user_key = AlienSessionInfo['user_cert'], AlienSessionInfo['user_key']
        token_cert, token_key = AlienSessionInfo['token_cert'], AlienSessionInfo['token_key']
    else:
        certs_info = renewCredFilesInfo()
        user_cert, user_key = certs_info.user_cert, certs_info.user_key
        token_cert, token_key = certs_info.token_cert, certs_info.token_key

    # Check the presence of user certs and bailout before anything else
    if not token_cert and not user_cert:
        print_err(f'No valid user certificate or token found!! check {DEBUG_FILE} for further information and contact the developer if the information is not clear.')
        return None

    ctx = create_ssl_context(use_usercert, user_cert = user_cert, user_key = user_key, token_cert = token_cert, token_key = token_key)
    if not ctx:
        if not user_cert: user_cert = 'INVALID'
        if not user_key: user_key = 'INVALID'
        if not token_cert: token_cert = 'INVALID'
        if not token_key: token_key = 'INVALID'
        msg = f'Could NOT create SSL context with cert files:\n{user_cert} ; {user_key}\n{token_cert} ; {token_key}'
        print_err(f'{msg}\nCheck the logfile: {DEBUG_FILE}')
        raise SSLctxException('connect_ssl::make_connection_ctx SSL ctx not present!!!')

    return ctx


def CertInfo(fname: str) -> RET:
    """Print certificate information (subject, issuer, notbefore, notafter)"""
    if not fname:
        return RET(2, '', 'No certificate filename provided!')  # ENOENT /* No such file or directory */

    cert_bytes = None
    try:
        with open(fname, "rb") as f: cert_bytes = f.read()
    except Exception as e:
        if DEBUG: logging.exception(e)
        return RET(2, '', f'File >>> {fname} <<< not found/accessible!')  # ENOENT /* No such file or directory */

    if cert_bytes is None:
        msg = f'CertInfo:: {fname} read but empty!'
        logging.error(msg)
        return RET(2, '', msg)  # ENOENT /* No such file or directory */

    try:
        x509cert = x509.load_pem_x509_certificate(cert_bytes)
    except Exception as e:
        if DEBUG: logging.exception(e)
        return RET(5, '', f'CertInfo::load_pem_x509_certificate:: error loading certificate >>> {fname} <<<')  # EIO /* I/O error */

    utc_time_notafter = x509cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S")
    utc_time_notbefore = x509cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%S")

    issuer_comp_list = x509cert.issuer.rfc4514_string().split(',')
    issuer_comp_list.reverse()
    issuer = '/'.join(issuer_comp_list)

    subject_comp_list = x509cert.subject.rfc4514_string().split(',')
    subject_comp_list.reverse()
    subject = '/'.join(subject_comp_list)

    info = f'DN >>> {subject}\nISSUER >>> {issuer}\nBEGIN >>> {utc_time_notbefore}\nEXPIRE >>> {utc_time_notafter}'
    return RET(0, info)


def CertVerify(fname: str) -> RET:
    """Print certificate information (subject, issuer, notbefore, notafter)"""
    cert_bytes = None
    try:
        with open(fname, "rb") as f: cert_bytes = f.read()
    except Exception as e:
        if DEBUG: logging.exception(e)
        return RET(2, "", f"File >>> {fname} <<< not found/accesible")  # ENOENT /* No such file or directory */

    if cert_bytes is None:
        msg = f'CertVerify:: {fname} read but empty!'
        logging.error(msg)
        return RET(2, '', msg)  # ENOENT /* No such file or directory */

    try:
        x509cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_bytes)
    except Exception as e:
        if DEBUG: logging.exception(e)
        return RET(5, "", f"Could not load certificate >>> {fname} <<<")  # EIO /* I/O error */

    x509store = OpenSSL.crypto.X509Store()
    x509store.set_flags(OpenSSL.crypto.X509StoreFlags.ALLOW_PROXY_CERTS)

    cafile = capath = None
    if os.path.isfile(CA_PATH):
        cafile = CA_PATH
    else:
        capath = CA_PATH

    try:
        x509store.load_locations(cafile = cafile, capath = capath)
    except Exception as e:
        if DEBUG: logging.exception(e)
        return RET(5, '', f'Could not load verify location >>> {CA_PATH} <<<')  # EIO /* I/O error */

    store_ctx = OpenSSL.crypto.X509StoreContext(x509store, x509cert)
    try:
        store_ctx.verify_certificate()
        return RET(0, f'SSL Verification {PrintColor(COLORS.BIGreen)}successful{PrintColor(COLORS.ColorReset)} for {fname}')
    except Exception as e:
        if DEBUG: logging.exception(e)
        return RET(1, '', f'SSL Verification {PrintColor(COLORS.BIRed)}failed{PrintColor(COLORS.ColorReset)} for {fname}')


def CertKeyMatch(cert_fname: str, key_fname: str) -> RET:
    """Check if Certificate and key match"""
    cert_bytes = None
    try:
        with open(cert_fname, "rb") as f: cert_bytes = f.read()
        x509cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_bytes)
    except Exception as e:
        if DEBUG: logging.exception(e)
        return RET(5, "", f'Could not load certificate >>>{cert_fname}<<<')  # EIO /* I/O error */

    key_bytes = None
    try:
        with open(key_fname, "rb") as g: key_bytes = g.read()
        x509key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, key_bytes)
    except Exception as e:
        if DEBUG: logging.exception(e)
        return RET(5, "", f'Could not load key >>>{key_fname}<<<')  # EIO /* I/O error */

    ctx = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD)  # skipcq: PTC-W6001
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.use_privatekey(x509key)
    ctx.use_certificate(x509cert)

    cafile = capath = None
    if os.path.isfile(CA_PATH):
        cafile = CA_PATH
    else:
        capath = CA_PATH

    try:
        ctx.load_verify_locations(cafile = cafile, capath = capath)
    except Exception as e:
        if DEBUG: logging.exception(e)
        return RET(5, "", f"Could not load verify location >>>{CA_PATH}<<<")  # EIO /* I/O error */

    try:
        ctx.check_privatekey()
        return RET(0, f'Cert/key {PrintColor(COLORS.BIGreen)}match{PrintColor(COLORS.ColorReset)}!')
    except OpenSSL.SSL.Error:
        return RET(42, '', f'Cert/key {PrintColor(COLORS.BIRed)}DO NOT match{PrintColor(COLORS.ColorReset)}!')
    except Exception as e:
        if DEBUG: logging.exception(e)
        return RET(1, '', 'Cert/key match :: unknown error')


# HAVE A GLOBAL CA_PATH
CA_PATH = get_ca_path()

# Populate information in AlienSessionInfo
_ = renewCredFilesInfo()


if __name__ == '__main__':
    print('This file should not be executed!', file = sys.stderr, flush = True)
    sys.exit(95)
