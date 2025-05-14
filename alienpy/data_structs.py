"""alienpy:: Definitions of data structures"""

import sys
from typing import NamedTuple


##############################################
##   Start of data structures definitions
##############################################

class COLORS_COLL(NamedTuple):  # pylint: disable=inherit-non-class
    """Collection of colors for terminal printing"""
    ColorReset = '\033[00m'     # Text Reset
    Black = '\033[0;30m'        # Black
    Red = '\033[0;31m'          # Red
    Green = '\033[0;32m'        # Green
    Yellow = '\033[0;33m'       # Yellow
    Blue = '\033[0;34m'         # Blue
    Purple = '\033[0;35m'       # Purple
    Cyan = '\033[0;36m'         # Cyan
    White = '\033[0;37m'        # White
    BBlack = '\033[1;30m'       # Bold Black
    BRed = '\033[1;31m'         # Bold Red
    BGreen = '\033[1;32m'       # Bold Green
    BYellow = '\033[1;33m'      # Bold Yellow
    BBlue = '\033[1;34m'        # Bold Blue
    BPurple = '\033[1;35m'      # Bold Purple
    BCyan = '\033[1;36m'        # Bold Cyan
    BWhite = '\033[1;37m'       # Bold White
    UBlack = '\033[4;30m'       # Underline Black
    URed = '\033[4;31m'         # Underline Red
    UGreen = '\033[4;32m'       # Underline Green
    UYellow = '\033[4;33m'      # Underline Yellow
    UBlue = '\033[4;34m'        # Underline Blue
    UPurple = '\033[4;35m'      # Underline Purple
    UCyan = '\033[4;36m'        # Underline Cyan
    UWhite = '\033[4;37m'       # Underline White
    IBlack = '\033[0;90m'       # High Intensity Black
    IRed = '\033[0;91m'         # High Intensity Red
    IGreen = '\033[0;92m'       # High Intensity Green
    IYellow = '\033[0;93m'      # High Intensity Yellow
    IBlue = '\033[0;94m'        # High Intensity Blue
    IPurple = '\033[0;95m'      # High Intensity Purple
    ICyan = '\033[0;96m'        # High Intensity Cyan
    IWhite = '\033[0;97m'       # High Intensity White
    BIBlack = '\033[1;90m'      # Bold High Intensity Black
    BIRed = '\033[1;91m'        # Bold High Intensity Red
    BIGreen = '\033[1;92m'      # Bold High Intensity Green
    BIYellow = '\033[1;93m'     # Bold High Intensity Yellow
    BIBlue = '\033[1;94m'       # Bold High Intensity Blue
    BIPurple = '\033[1;95m'     # Bold High Intensity Purple
    BICyan = '\033[1;96m'       # Bold High Intensity Cyan
    BIWhite = '\033[1;97m'      # Bold High Intensity White
    On_Black = '\033[40m'       # Background Black
    On_Red = '\033[41m'         # Background Red
    On_Green = '\033[42m'       # Background Green
    On_Yellow = '\033[43m'      # Background Yellow
    On_Blue = '\033[44m'        # Background Blue
    On_Purple = '\033[45m'      # Background Purple
    On_Cyan = '\033[46m'        # Background Cyan
    On_White = '\033[47m'       # Background White
    On_IBlack = '\033[0;100m'   # High Intensity backgrounds Black
    On_IRed = '\033[0;101m'     # High Intensity backgrounds Red
    On_IGreen = '\033[0;102m'   # High Intensity backgrounds Green
    On_IYellow = '\033[0;103m'  # High Intensity backgrounds Yellow
    On_IBlue = '\033[0;104m'    # High Intensity backgrounds Blue
    On_IPurple = '\033[0;105m'  # High Intensity backgrounds Purple
    On_ICyan = '\033[0;106m'    # High Intensity backgrounds Cyan
    On_IWhite = '\033[0;107m'   # High Intensity backgrounds White


class XrdCpArgs(NamedTuple):  # pylint: disable=inherit-non-class
    """Structure to keep the set of xrootd flags used for xrootd copy process"""
    overwrite: bool = True
    batch: int = 8
    tpc: str = ''
    hashtype: str = ''
    cksum: bool = True
    timeout: int = 0
    rate: int = 0


class CopyFile(NamedTuple):  # pylint: disable=inherit-non-class
    """Structure to keep a generic copy task"""
    src: str = ''
    dst: str = ''
    isUpload: bool = False
    token_request: dict = {}
    lfn: str = ''


class CommitInfo(NamedTuple):  # pylint: disable=inherit-non-class
    """Structure for commit of successful xrootd write to file catalogue"""
    envelope: str = ''
    size: str = ''
    lfn: str = ''
    perm: str = ''
    expire: str = ''
    pfn: str = ''
    se: str = ''
    guid: str = ''
    md5: str = ''


class lfn2file(NamedTuple):  # pylint: disable=inherit-non-class
    """Map a lfn to file (and reverse)"""
    lfn: str = ''
    file: str = ''


class KV(NamedTuple):  # pylint: disable=inherit-non-class
    """Assign a value to a key"""
    key: str = ''
    val: str = ''


class CertsInfo(NamedTuple):  # pylint: disable=inherit-non-class
    """Store name information on certificates used for SSL context"""
    user_cert: str = ''
    user_key: str = ''
    token_cert: str = ''
    token_key: str = ''


class RET(NamedTuple):  # pylint: disable=inherit-non-class
    """Structure for POSIX like function return: exitcode, stdout, stderr, dictionary of server reply"""
    exitcode: int = -1
    out: str = ''
    err: str = ''
    ansdict: dict = {}

    def __bool__(self) -> bool:
        return self.exitcode == 0


class ALIEN_COLLECTION_EL(NamedTuple):  # pylint: disable=inherit-non-class
    """AliEn style xml collection element structure"""
    name: str = ''
    aclId: str = ''
    broken: str = ''
    ctime: str = ''
    dir: str = ''  # noqa: A003
    entryId: str = ''
    expiretime: str = ''
    gowner: str = ''
    guid: str = ''
    guidtime: str = ''
    jobid: str = ''
    lfn: str = ''
    md5: str = ''
    owner: str = ''
    perm: str = ''
    replicated: str = ''
    size: str = ''
    turl: str = ''
    type: str = ''  # noqa: A003


class STAT_FILEPATH(NamedTuple):  # pylint: disable=inherit-non-class
    """Stat attributes of a lfn"""
    path: str = ''
    type: str = ''  # noqa: A003
    perm: str = ''
    uid: str = ''
    gid: str = ''
    ctime: str = ''
    mtime: str = ''
    guid: str = ''
    size: str = ''
    md5: str = ''


if __name__ == '__main__':
    print('This file should not be executed!', file = sys.stderr, flush = True)
    sys.exit(95)
