'''alienpy:: file and path manipulation tools/helpers - not-networked'''


import uuid
from pathlib import Path
import xml.dom.minidom as MD  # nosec B408:blacklist
from .data_structs import *  # nosec PYL-W0614
from .tools_misc import *  # nosec PYL-W0614
import multiprocessing as mp
import traceback

NCPU = int(mp.cpu_count() * 0.8)  # use at most 80% of host CPUs


def common_path(path_list: list) -> str:
    """Return common path of a list of paths"""
    if not path_list: return ''
    if not isinstance(path_list, list): return ''
    common = ''
    try:
        common = os.path.commonpath(path_list)
    except:
        pass
    return common


def format_dst_fn(src_dir, src_file, dst, parent):
    """Return the destination filename given the source dir/name, destination directory and number of parents to keep"""
    # let's get destination file name (relative path with parent value)
    if src_dir != src_file:  # recursive operation
        total_relative_path = src_file.replace(src_dir, '', 1)
        src_dir_path = Path(src_dir)
        src_dir_parts = src_dir_path.parts
        if not src_dir.endswith('/'): src_dir_parts = src_dir_parts[:-1]
        src_dir = '/'.join(map(lambda x: str(x or ''), src_dir_parts))
        src_dir = src_dir.replace('//', '/')
        components_list = src_dir.split('/')
        components_list[0] = '/'  # first slash is lost in split
        file_components = len(components_list)  # it's directory'
        parent = min(parent, file_components)  # make sure maximum parent var point to first dir in path
        parent_selection = components_list[(file_components - parent):]
        rootdir_src_dir = '/'.join(parent_selection)
        file_relative_name = f'{rootdir_src_dir}/{total_relative_path}'
    else:
        src_file_path = Path(src_file)
        file_components = len(src_file_path.parts) - 1 - 1  # without the file and up to slash
        parent = min(parent, file_components)  # make sure maximum parent var point to first dir in path
        rootdir_src_file = src_file_path.parents[parent].as_posix()
        file_relative_name = src_file.replace(rootdir_src_file, '', 1)

    dst_file = f'{dst}/{file_relative_name}' if dst.endswith('/') else dst
    return os.path.normpath(dst_file)


def setDst(file: str = '', parent: int = 0) -> str:
    """For a given file path return the file path keeping the <parent> number of components"""
    p = Path(file)
    path_components = len(p.parts)
    if parent >= (path_components - 1): parent = path_components - 1 - 1  # IF parent >= number of components without filename THEN make parent = number of component without / and filename
    basedir = p.parents[parent].as_posix()
    if basedir == '/': return file
    return p.as_posix().replace(basedir, '', 1)


def pathtype_local(path: str) -> str:
    """Query if a local path is a file or directory, return f, d or empty"""
    if not path: return ''
    p = Path(path)
    if p.is_dir(): return str('d')
    if p.is_file(): return str('f')
    return ''


def fileIsValid(filename: str, size: Union[str, int], reported_md5: str, shallow_check: bool = False) -> RET:
    """Check if the file path is consistent with the size and md5 argument. N.B.! the local file will be deleted with size,md5 not match"""
    if os.path.isfile(filename):  # first check
        if int(os.stat(filename).st_size) != int(size):
            os.remove(filename)
            return RET(9, '', f'{filename} : Removed (invalid size)')
        if shallow_check:
            return RET(0, f'{filename} --> TARGET VALID (size match)')
        if md5(filename) != reported_md5:
            os.remove(filename)
            return RET(9, '', f'{filename} : Removed (invalid md5)')
        return RET(0, f'{filename} --> TARGET VALID (md5 match)')
    return RET(2, '', f'{filename} : No such file')  # ENOENT


def create_metafile(meta_filename: str, lfn: str, local_filename: str, size: Union[str, int], md5in: str, replica_list: Union[None, list] = None) -> str:
    """Generate a meta4 xrootd virtual redirector with the specified location and using the rest of arguments"""
    if not (meta_filename and replica_list): return ''
    try:
        with open(meta_filename, 'w', encoding="ascii", errors="replace") as f:
            published = str(datetime.datetime.now().replace(microsecond=0).isoformat())
            f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
            f.write(' <metalink xmlns="urn:ietf:params:xml:ns:metalink">\n')
            f.write(f'   <published>{published}</published>\n')
            f.write(f'   <file name="{local_filename}">\n')
            f.write(f'     <lfn>{lfn}</lfn>\n')
            f.write(f'     <size>{size}</size>\n')
            if md5in: f.write(f'     <hash type="md5">{md5in}</hash>\n')
            for url in replica_list:
                f.write(f'     <url><![CDATA[{url}]]></url>\n')
            f.write('   </file>\n')
            f.write(' </metalink>\n')
        return meta_filename
    except Exception:
        logging.error(traceback.format_exc())
        return ''


def get_lfn_meta(meta_fn: str) -> str:
    """Extract lfn value from metafile"""
    if 'meta4?' in meta_fn: meta_fn = meta_fn.partition('?')[0]
    if not os.path.isfile(meta_fn): return ''
    return MD.parse(meta_fn).documentElement.getElementsByTagName('lfn')[0].firstChild.nodeValue  # nosec B318:blacklist


def get_size_meta(meta_fn: str) -> int:
    """Extract size value from metafile"""
    if 'meta4?' in meta_fn: meta_fn = meta_fn.partition('?')[0]
    if not os.path.isfile(meta_fn): return int(0)
    return int(MD.parse(meta_fn).documentElement.getElementsByTagName('size')[0].firstChild.nodeValue)  # nosec B318:blacklist


def get_hash_meta(meta_fn: str) -> tuple:
    """Extract hash value from metafile"""
    if 'meta4?' in meta_fn: meta_fn = meta_fn.partition('?')[0]
    if not os.path.isfile(meta_fn): return ('', '')
    content = MD.parse(meta_fn).documentElement.getElementsByTagName('hash')[0]  # nosec B318:blacklist
    return (content.getAttribute('type'), content.firstChild.nodeValue)


def md5(input_file: str) -> str:
    """Compute the md5 digest of the specified file"""
    if not path_readable(input_file): return '-1'
    from hashlib import md5 as hash_md5
    BLOCKSIZE = 65536
    
    if hash_md5.__text_signature__ and 'usedforsecurity' in hash_md5.__text_signature__:
        hasher = hash_md5(usedforsecurity = False)
    else:
        hasher = hash_md5()  # nosec

    with open(input_file, 'rb', buffering = 0) as f:
        for chunk in iter(lambda: f.read(BLOCKSIZE), b''): hasher.update(chunk)
    return hasher.hexdigest()


def md5_mp(list_of_files: Union[None, list] = None) -> list:
    """Compute md5 hashes in parallel; the results are guaranteed (by documentation) to be in the order of input list"""
    if not list_of_files: return []
    hash_list = []
    with mp.Pool(processes = NCPU) as pool: hash_list = pool.map(md5, list_of_files)
    return hash_list


def expand_path_local(path_arg: str, strict: bool = False) -> str:
    """Given a string representing a local file, return a full path after interpretation of HOME location, current directory, . and .. and making sure there are only single /"""
    if not path_arg: return ''
    exp_path = None
    path_arg = lfn_prefix_re.sub('', path_arg)  # lets remove any prefixes
    try:
        exp_path = Path(path_arg).expanduser().resolve(strict).as_posix()
    except Exception:
        return ''
    if (len(exp_path) > 1 and path_arg.endswith('/')) or os.path.isdir(exp_path): exp_path = f'{exp_path}/'
    return exp_path  # noqa: R504


def check_path_perm(filepath: str, mode) -> bool:
    """Resolve a file/path and check if mode is valid"""
    filepath = expand_path_local(filepath, True)
    if not filepath: return False
    if not mode: mode = os.F_OK
    return os.access(filepath, mode, follow_symlinks = True)


def path_readable(filepath: str = '') -> bool:
    """Resolve a file/path and check if it is readable"""
    return check_path_perm(filepath, os.R_OK)


def path_writable(filepath: str = '') -> bool:
    """Resolve a file/path and check if it is writable"""
    return check_path_perm(filepath, os.W_OK)


def path_writable_any(filepath: str = '') -> bool:
    """Return true if any path in hierarchy is writable (starting with the longest path)"""
    filepath = expand_path_local(filepath)  # do not use strict as the destination directory could not yet exists
    if not filepath: return False
    paths_list = [p.as_posix() for p in Path(filepath).parents]
    if Path(filepath).is_dir(): paths_list.insert(0, filepath)
    return any(path_writable(p) for p in paths_list)


def path_local_stat(path: str, do_md5: bool = False) -> STAT_FILEPATH:
    """Get full information on a local path"""
    norm_path = expand_path_local(path)
    if not os.path.exists(norm_path): return STAT_FILEPATH(norm_path)
    filetype = 'd' if os.path.isdir(norm_path) else 'f'
    statinfo = os.stat(norm_path)
    perm = oct(statinfo.st_mode)[-3:]
    uid = uid2name(statinfo.st_uid)
    gid = gid2name(statinfo.st_gid)
    ctime = str(statinfo.st_ctime)
    mtime = str(statinfo.st_mtime)
    guid = ''
    size = str(statinfo.st_size)
    md5hash = ''
    if do_md5 and filetype == 'f': md5hash = md5(norm_path)
    return STAT_FILEPATH(norm_path, filetype, perm, uid, gid, ctime, mtime, guid, size, md5hash)


def list_files_local(search_dir: str, pattern: Union[None, REGEX_PATTERN_TYPE, str] = None, is_regex: bool = False, find_args: str = '') -> RET:
    """Return a list of files(local)(N.B! ONLY FILES) that match pattern found in dir"""
    if not search_dir: return RET(2, "", "No search directory specified")

    # let's process the pattern: extract it from src if is in the path globbing form
    regex = None
    is_single_file = False  # dir actually point to a file
    if '*' in search_dir:  # we have globbing in src path
        is_regex = False
        src_arr = search_dir.split("/")
        base_path_arr = []  # let's establish the base path
        for el in src_arr:
            if '*' not in el:
                base_path_arr.append(el)
            else:
                break
        for el in base_path_arr: src_arr.remove(el)  # remove the base path
        search_dir = '/'.join(base_path_arr) + '/'  # rewrite the source path without the globbing part
        pattern = '/'.join(src_arr)  # the globbing part is the rest of element that contain *
    else:  # pattern is specified by argument or not specified
        if pattern is None:
            if not search_dir.endswith('/'):  # this is a single file
                is_single_file = True
            else:
                pattern = '*'  # prefer globbing as default
        elif type(pattern) is REGEX_PATTERN_TYPE:  # unlikely but supported to match signatures
            regex = pattern
            is_regex = True
        elif is_regex and isinstance(pattern, str):  # it was explictly requested that pattern is regex
            regex = valid_regex(pattern)
            if regex is None:
                msg = f'list_files_grid:: {pattern} failed to re.compile'
                logging.error(msg)
                return RET(-1, '', msg)

    directory = None  # resolve start_dir to an absolute_path
    try:
        directory = Path(search_dir).expanduser().resolve(strict = True).as_posix()
    except FileNotFoundError:
        return RET(2, '', f'{search_dir} not found')
    except RuntimeError:
        return RET(2, '', f'Loop encountered along the resolution of {search_dir}')

    filter_args_list = None
    if find_args: filter_args_list = find_args.split()  # for local files listing we have only filtering options

    file_list = None  # make a list of filepaths (that match a regex or a glob)
    if is_single_file:
        file_list = [directory]
    elif is_regex:
        file_list = [os.path.join(root, f) for (root, dirs, files) in os.walk(directory) for f in files if regex.match(os.path.join(root, f))]
    else:
        file_list = [p.expanduser().resolve(strict = True).as_posix() for p in list(Path(directory).glob(f'**/{pattern}')) if p.is_file()]

    if not file_list:
        return RET(2, '', f"No files found in :: {directory} /pattern: {pattern} /find_args: {find_args}")

    # convert the file_list to a list of file properties dictionaries
    results_list = [file2file_dict(filepath) for filepath in file_list]

    results_list_filtered = []
    # items that pass the conditions are the actual/final results
    for found_lfn_dict in results_list:  # parse results to apply filters
        if not filter_file_prop(found_lfn_dict, directory, filter_args_list, regex): continue
        # at this point all filters were passed
        results_list_filtered.append(found_lfn_dict)

    if not results_list_filtered:
        return RET(2, '', f'No files passed the filters :: {directory} /pattern: {pattern} /find_args: {find_args}')

    ansdict = {"results": results_list_filtered}
    lfn_list = [get_lfn_key(lfn_obj) for lfn_obj in results_list_filtered]
    stdout = '\n'.join(lfn_list)
    return RET(exitcode, stdout, '', ansdict)


def file_set_atime(path: str):
    """Set atime of file to now"""
    if not os.path.isfile(path): return
    file_stat = os.stat(path)
    os.utime(path, (datetime.datetime.now().timestamp(), file_stat.st_mtime))


def file2file_dict(fn: str) -> dict:
    """Take a string as path and retur a dict with file propreties"""
    try:
        file_path = Path(fn)
    except Exception:
        return {}
    try:
        file_name = file_path.expanduser().resolve(strict = True)
    except Exception:
        return {}
    if file_name.is_dir(): return {}

    file_dict = {"file": file_name.as_posix()}
    file_dict["lfn"] = file_name.as_posix()
    file_dict["size"] = str(file_name.stat().st_size)
    file_dict["mtime"] = str(int(file_name.stat().st_mtime * 1000))
    file_dict["md5"] = md5(file_name.as_posix())
    file_dict["owner"] = pwd.getpwuid(file_name.stat().st_uid).pw_name
    file_dict["gowner"] = gid2name(file_name.stat().st_gid)
    return file_dict


def filter_file_prop(f_obj: dict, base_dir: str, find_opts: Union[str, list, None], compiled_regex = None) -> bool:
    """Return True if an file dict object pass the conditions in find_opts"""
    if not f_obj or not base_dir: return False
    if f_obj['lfn'].endswith('.'): return False

    if not find_opts: return True
    opts = find_opts.split() if isinstance(find_opts, str) else find_opts.copy()
    lfn = get_lfn_key(f_obj)
    if not base_dir.endswith('/'): base_dir = f'{base_dir}/'
    relative_lfn = lfn.replace(base_dir, '')  # it will have N directories depth + 1 file components

    # string/pattern exclusion
    exclude_string = get_arg_value(opts, '-exclude')
    if exclude_string and exclude_string in relative_lfn: return False  # this is filtering out the string from relative lfn

    exclude_regex = get_arg_value(opts, '-exclude_re')
    if exclude_regex and compiled_regex and compiled_regex.match(relative_lfn): return False

    min_size = get_arg_value(opts, '-minsize')
    if min_size:
        if not min_size.isdigit() or min_size.startswith("-"):
            print_err(f'filter_file_prop::minsize arg not recognized: {" ".join(opts)}')
            return False
        if int(f_obj["size"]) < abs(int(min_size)): return False

    max_size = get_arg_value(opts, '-maxsize')
    if max_size:
        if not max_size.isdigit() or max_size.startswith("-"):
            print_err(f'filter_file_prop::maxsize arg not recognized: {" ".join(opts)}')
            return False
        if int(f_obj["size"]) > abs(int(max_size)): return False

    jobid = get_arg_value(opts, '-jobid')
    if jobid:
        if not jobid.isdigit() or jobid.startswith("-"):
            print_err(f'filter_file_prop::Missing argument in list:: {" ".join(opts)}')
            return False

        if "jobid" not in f_obj:
            print_err('filter_file_prop::jobid - could not find jobid information in file dictionary, selection failed!')
            return False
        if f_obj["jobid"] != jobid: return False

    user = get_arg_value(opts, '-user')
    if user:
        if not user.isalpha() or user.startswith("-"):
            print_err(f'filter_file_prop::Missing argument in list:: {" ".join(opts)}')
            return False
        if f_obj["owner"] != user: return False

    group = get_arg_value(opts, '-group')
    if group:
        if not group.isalpha() or group.startswith("-"):
            print_err(f'filter_file_prop::Missing argument in list:: {" ".join(opts)}')
            return False
        if f_obj["gowner"] != group: return False

    min_ctime = get_arg_value(opts, '-min-ctime')
    if min_ctime and min_ctime.startswith("-"):
        print_err(f'filter_file_prop::min-ctime arg not recognized: {" ".join(opts)}')
        return False

    max_ctime = get_arg_value(opts, '-max-ctime')
    if max_ctime and max_ctime.startswith("-"):
        print_err(f'filter_file_prop::max-ctime arg not recognized: {" ".join(opts)}')
        return False

    # the argument can be a string with a form like: '20.12.2016 09:38:42,76','%d.%m.%Y %H:%M:%S,%f'
    # see: https://docs.python.org/3.6/library/datetime.html#strftime-strptime-behavior
    if min_ctime or max_ctime:
        dict_time = f_obj.get("ctime", '')
        if not dict_time: dict_time = f_obj.get("mtime", '')
        if not dict_time or not dict_time.isdigit():
            print_err('filter_file_prop::min/max-ctime - could not find time information in file dictionary, selection failed!')
            return False
        if min_ctime:
            min_ctime = time_str2unixmili(min_ctime)
            if int(dict_time) < min_ctime: return False
        if max_ctime:
            max_ctime = time_str2unixmili(max_ctime)
            if int(dict_time) > max_ctime: return False

    min_depth = get_arg_value(opts, '-mindepth')
    if min_depth:
        if not min_depth.isdigit() or min_depth.startswith("-"):
            print_err(f'filter_file_prop::mindepth arg not recognized: {" ".join(opts)}')
            return False
        min_depth = abs(int(min_depth)) + 1  # add +1 for the always present file component of relative_lfn
        if len(relative_lfn.split('/')) < min_depth: return False

    max_depth = get_arg_value(opts, '-maxdepth')
    if max_depth:
        if not max_depth.isdigit() or max_depth.startswith("-"):
            print_err(f'filter_file_prop::maxdepth arg not recognized: {" ".join(opts)}')
            return False
        max_depth = abs(int(max_depth)) + 1  # add +1 for the always present file component of relative_lfn
        if len(relative_lfn.split('/')) > max_depth: return False

    return True


def lfn2tmp_fn(lfn: str = '', uuid5: bool = False) -> str:
    """make temporary file name that can be reconstructed back to the lfn"""
    if not lfn: return str(uuid.uuid4())
    if uuid5:
        return str(uuid.uuid5(uuid.NAMESPACE_URL, lfn))
    return lfn.replace("/", '%%')


def make_tmp_fn(lfn: str = '', ext: str = '', uuid5: bool = False) -> str:
    """make temporary file path string either random or based on grid lfn string"""
    if not ext: ext = f'_{str(os.getuid())}.alienpy_tmp'
    return f'{TMPDIR}/{lfn2tmp_fn(lfn, uuid5)}{ext}'


def get_lfn_name(tmp_name: str = '', ext: str = '') -> str:
    lfn = tmp_name.replace(ext, '') if ext else tmp_name.replace(f'_{str(os.getuid())}.alienpy_tmp', '')
    return lfn.replace(f'{TMPDIR}/', '').replace("%%", "/")


if __name__ == '__main__':
    print('This file should not be executed!', file = sys.stderr, flush = True)
    sys.exit(95)
