"""alienpy:: XRootD related tooling/helpers"""

import os
import re
import subprocess
import shlex
import sys
from typing import Union
import logging

from .data_structs import CommitInfo, RET, STAT_FILEPATH, lfn2file
from .setup_logging import DEBUG, print_err
from .global_vars import AlienSessionInfo, COLORS, REGEX_PATTERN_TYPE, lfn_prefix_re, specs_split
from .wb_api import SendMsg, SendMsgMulti, retf_print
from .tools_nowb import CreateJsonCommand, PrintColor, create_metafile, filter_file_prop, get_arg, get_arg_value, get_arg_value_multiple, get_lfn_key, make_tmp_fn, valid_regex, md5


def lfnAccessUrl(wb, lfn: str, local_file: str = '', specs: Union[None, list, str] = None, isWrite: bool = False, strictspec: bool = False, httpurl: bool = False) -> dict:
    """Query central services for the access envelope of a lfn, it will return a lfn:server answer with envelope pairs"""
    if not wb: return {}
    if not lfn: return {}
    if not specs: specs = []
    if specs and isinstance(specs, str): specs = specs_split.split(specs)
    if isWrite:
        if not local_file or not os.path.exists(local_file):
            print_err(f'lfnAccessUrl/write token:: invalid local file: {local_file}')
            return {}
        access_type = 'write'
        size = int(os.stat(local_file).st_size)
        # compute here as we will tell xrootd to compare with what was sent
        md5sum = md5(local_file)
        files_with_default_replicas = ['.sh', '.C', '.jdl', '.xml']
        if any(lfn.endswith(ext) for ext in files_with_default_replicas) and size < 1048576 and not specs:  # we have a special lfn
            specs.append('disk:4')  # and no specs defined then default to disk:4
        get_envelope_arg_list = ['-s', size, '-m', md5sum, access_type, lfn]
        if not specs: specs.append('disk:2')  # hard default if nothing is specified
    else:
        access_type = 'read'
        get_envelope_arg_list = [access_type, lfn]

    if specs: get_envelope_arg_list.append(",".join(specs))
    if httpurl: get_envelope_arg_list.insert(0, '-u')
    if strictspec: get_envelope_arg_list.insert(0, '-f')
    ret_obj = SendMsg(wb, 'access', get_envelope_arg_list, opts = 'nomsg')
    if ret_obj.exitcode != 0 or 'results' not in ret_obj.ansdict:
        ret_obj = ret_obj._replace(err = f'No token for {lfn} :: errno {ret_obj.exitcode} -> {ret_obj.err}')
        retf_print(ret_obj, opts = 'err noprint')
        return {}
    return ret_obj.ansdict


def lfn2uri(wb, lfn: str, local_file: str = '', specs: Union[None, list, str] = None, isWrite: bool = False, strictspec: bool = False, httpurl: bool = False) -> str:
    """Return the list of access URIs for all replica of an ALICE lfn - can be used directly with xrdcp"""
    result = lfnAccessUrl(wb, lfn, local_file, specs, isWrite, strictspec, httpurl)
    if not result: return ''
    output_list = []
    for replica in result['results']:
        output_list.append(repr(f"{replica['url']}?xrd.wantprot=unix&authz={replica['envelope']}"))
    return '\n'.join(output_list)


def lfn2meta(wb, lfn: str, local_file: str = '', specs: Union[None, list, str] = None, isWrite: bool = False, strictspec: bool = False, httpurl: bool = False) -> str:
    """Create metafile for download of an ALICE lfn and return it's location - can be used directly with xrdcp"""
    if isWrite:
        print_err('Metafile creation possible only for download')
        return ''
    result = lfnAccessUrl(wb, lfn, local_file, specs, isWrite, strictspec, httpurl)
    if not result: return ''
    size_4meta = result['results'][0]['size']  # size SHOULD be the same for all replicas
    md5_4meta = result['results'][0]['md5']  # the md5 hash SHOULD be the same for all replicas
    file_in_zip = None
    url_list_4meta = []
    for replica in result['results']:
        url_components = replica['url'].rsplit('#', maxsplit = 1)
        if len(url_components) > 1: file_in_zip = url_components[1]
        # if is_pfn_readable(url_components[0]):  # it is a lot cheaper to check readability of replica than to try and fail a non-working replica
        url_list_4meta.append(f'{url_components[0]}?xrd.wantprot=unix&authz={replica["envelope"]}')

    # Create the metafile as a temporary uuid5 named file (the lfn can be retrieved from meta if needed)
    metafile = create_metafile(make_tmp_fn(lfn, '.meta4', uuid5 = True), lfn, local_file, size_4meta, md5_4meta, url_list_4meta)
    if not metafile:
        print_err(f"Could not create the download metafile for {lfn}")
        return ''
    subprocess.run(shlex.split(f'mv {metafile} {os.getcwd()}/'), check = False)  # keep it in local directory  # nosec
    metafile = os.path.realpath(os.path.basename(metafile))
    return f'{metafile}?xrdcl.unzip={file_in_zip}' if (file_in_zip and 'ALIENPY_NOXRDZIP' not in os.environ) else f'{metafile}'


def lfn2fileTokens(wb, arg_lfn2file: lfn2file, specs: Union[None, list, str] = None, isWrite: bool = False, strictspec: bool = False, httpurl: bool = False) -> dict:
    """Query central services for the access envelope of a lfn, it will return a lfn:server answer with envelope pairs"""
    if not wb: return {}
    if not arg_lfn2file: return {}
    lfn = arg_lfn2file.lfn
    file = arg_lfn2file.file
    if not specs: specs = []
    if specs and isinstance(specs, str): specs = specs_split.split(specs)
    result = lfnAccessUrl(wb, lfn, file, specs, isWrite, strictspec, httpurl)
    if not result:
        return {"lfn": lfn, "answer": {}}
    qos_tags = [el for el in specs if 'ALICE::' not in el]  # for element in specs, if not ALICE:: then is qos tag
    SEs_list_specs = [el for el in specs if 'ALICE::' in el]  # explicit requests of SEs
    SEs_list_total = [replica["se"] for replica in result["results"]]
    # let's save for each replica the original request info
    for replica in result["results"]:
        replica["qos_specs"] = qos_tags  # qos tags from specs
        replica["SElist_specs"] = SEs_list_specs  # SE from specs
        replica["SElist"] = SEs_list_total  # list of SEs that were used
        replica["file"] = file
        replica["lfn"] = lfn
    return {"lfn": lfn, "answer": result}


def lfn2fileTokens_list(wb, input_lfn_list: list, specs: Union[None, list, str] = None, isWrite: bool = False, strictspec: bool = False, httpurl: bool = False) -> list:
    """Query central services for the access envelope of the list of lfns, it will return a list of lfn:server answer with envelope pairs"""
    if not wb: return []
    access_list = []
    if not input_lfn_list: return access_list
    if specs is None: specs = []
    for l2f in input_lfn_list: access_list.append(lfn2fileTokens(wb, l2f, specs, isWrite, strictspec, httpurl))
    return access_list


def path_grid_writable(file_stat: STAT_FILEPATH) -> bool:
    """Return writable status for a GRID path, for the current user"""
    p_user = int(file_stat['perm'][0])
    p_group = int(file_stat['perm'][1])
    p_others = int(file_stat['perm'][2])
    writable_user = writable_group = writable_others = False
    write_perm = {2, 6, 7}
    if AlienSessionInfo['user'] == file_stat['uid'] and p_user in write_perm: writable_user = True
    if AlienSessionInfo['user'] == file_stat['gid'] and p_group in write_perm: writable_group = True
    if p_others in write_perm: writable_others = True
    return writable_user or writable_group or writable_others


def expand_path_grid(path_arg: str) -> str:
    """Given a string representing a GRID file (lfn), return a full path after interpretation of AliEn HOME location, current directory, . and .. and making sure there are only single /"""
    is_dir = path_arg.endswith('/')
    exp_path = lfn_prefix_re.sub('', path_arg)  # lets remove any prefixes
    exp_path = re.sub(r"^\/*\%ALIEN[\/\s]*", AlienSessionInfo['alienHome'], exp_path)  # replace %ALIEN token with user grid home directory
    if exp_path == '.': exp_path = AlienSessionInfo['currentdir']
    if exp_path == '~': exp_path = AlienSessionInfo['alienHome']
    if exp_path.startswith('./'): exp_path = exp_path.replace('.', AlienSessionInfo['currentdir'], 1)
    if exp_path.startswith('~/'): exp_path = exp_path.replace('~', AlienSessionInfo['alienHome'], 1)  # replace ~ for the usual meaning
    if not exp_path.startswith('/'): exp_path = f'{AlienSessionInfo["currentdir"]}/{exp_path}'  # if not full path add current directory to the referenced path
    exp_path = os.path.normpath(exp_path)
    if is_dir: exp_path = f'{exp_path}/'
    return exp_path  # noqa: R504


def path_grid_stat(wb, path: str) -> STAT_FILEPATH:
    """Get full information on a GRID path/lfn"""
    norm_path = expand_path_grid(path)
    ret_obj = SendMsg(wb, 'stat', [norm_path], opts = 'nomsg log')
    if ret_obj.exitcode != 0: return STAT_FILEPATH(norm_path)
    file_stat = ret_obj.ansdict["results"][0]  # stat can query and return multiple results, but we are using only one
    mtime = file_stat.get('mtime', '')
    guid = file_stat.get('guid', '')
    size = file_stat.get('size', '')
    md5hash = file_stat.get('md5', '')
    return STAT_FILEPATH(file_stat['lfn'], file_stat['type'], file_stat['perm'], file_stat['owner'], file_stat['gowner'], file_stat['ctime'],
                         mtime, guid, size, md5hash)


def lfnIsValid(wb, lfn: str, local_file: str, shallow_check: bool = False, removeTarget: bool = True) -> RET:
    """Check if remote lfn corresponds with local file (source is local, target is remote lfn); target will be removed if present and not match the source"""
    local_file_stat = None
    if os.path.isfile(local_file): local_file_stat = os.stat(local_file)
    if not local_file_stat: return RET(2, '', 'Missing local file')

    lfn_stat = path_grid_stat(wb, lfn)  # check each destination lfn
    if not lfn_stat.size: return RET(2, '', '')

    if int(local_file_stat.st_size) != int(lfn_stat.size):
        if removeTarget:
            ret_obj = SendMsg(wb, 'rm', ['-f', lfn], opts = 'nomsg')
            msg = f'{lfn} : Removed (invalid size)'
        else:
            msg = f'{lfn} : Mismatched size'
        return RET(9, '', msg)

    if int(local_file_stat.st_mtime * 1000) > int(lfn_stat.mtime):  # higher mtime --> newer file; if local_file(source) is newer than lfn(destination) then remove destination
        if removeTarget:
            ret_obj = SendMsg(wb, 'rm', ['-f', lfn], opts = 'nomsg')
            msg = f'{lfn} : Removed (source/local_file newer than destination/lfn)'
        else:
            msg = f'{lfn} : source/local_file newer than destination/lfn'
        return RET(9, '', msg)

    if shallow_check:
        return RET(0, f'{lfn} --> TARGET VALID (size match, source/local_file older than destination/lfn)')

    if md5(local_file) != lfn_stat.md5:
        if removeTarget:
            ret_obj = SendMsg(wb, 'rm', ['-f', lfn], opts = 'nomsg')
            msg = f'{lfn} : Removed (invalid md5)'
        else:
            msg = f'{lfn} : Older than local file'
        return RET(9, '', msg)

    return RET(0, f'{lfn} --> TARGET VALID (md5 match)')


def xrdcp_help() -> str:
    return f'''Command format is of the form of (with the strict order of arguments):
        cp <options> src dst
        or
        cp <options> -input input_file
        or
        cp <options> -dst dest_dir file1 file2 ... fileN
where src|dst are local files if prefixed with file:// or file: or grid files otherwise
and -input argument is a file with >src dst< pairs
after each src,dst can be added comma separated specifiers list in the form of: @<QOS>:N,SE1,SE2,!SE3
QOS is a tag of the storage element (usually "disk") followed by the N requested replicas
Additional replicas can be requested by the name of storage elements. (additional to QOS specifications),
or exclusion of storages (prefixing with exclamation mark).
%ALIEN alias have the special meaning of AliEn user home directory
options are the following :
-h : print help
-dryrun                  : just print the src,dst pairs that would have been transferred without actually doing so
-f | -force              : Do md5 verification of already present destination
-S <additional streams>   : uses num additional parallel streams to do the transfer. (max = 15)
-chunks <nr chunks>      : number of chunks that should be requested in parallel
-chunksz <bytes>         : chunk size (bytes)
-parent N                : keep last N path components into destination filepath
-rmprefix N              : remove first N path components from full source path and keep the rest as basepath for destination
-T <nr_copy_jobs>        : number of parallel copy jobs from a set (for recursive copy); defaults to 8 for downloads
-timeout <seconds>       : the job will fail if did not finish in this nr of seconds
-retry <times>           : retry N times the copy process if failed
-ratethreshold <bytes/s> : fail the job if the speed is lower than specified bytes/s
-noxrdzip                : circumvent the XRootD mechanism of zip member copy and download the archive and locally extract the intended member.
N.B.!!! for recursive copy (all files) the same archive will be downloaded for each member.
If there are problems with native XRootD zip mechanism, download only the zip archive and locally extract the contents

For the recursive copy of directories the following options (of the find command) can be used:
-j jobid           : select only the files created by the job with jobid (for recursive copy)
-l int             : copy only <count> nr of files (for recursive copy)
-o int             : skip first <offset> files found in the src directory (for recursive copy)
-e exclude_pattern : exclude files that match this pattern (for recursive copy)

Further filtering of the files can be applied with the following options:
-glob    <globbing pattern> : this is the usual AliEn globbing format; {PrintColor(COLORS.BIGreen)}N.B. this is NOT a REGEX!!!{PrintColor(COLORS.ColorReset)} defaults to all "*"
-select  <pattern>          : select only these files to be copied; {PrintColor(COLORS.BIGreen)}N.B. this is a REGEX applied to full path!!!{PrintColor(COLORS.ColorReset)}
-name    <pattern>          : select only these files to be copied; {PrintColor(COLORS.BIGreen)}N.B. this is a REGEX applied to a directory or file name!!!{PrintColor(COLORS.ColorReset)}
-name    <verb>_string      : where verb = begin|contain|ends|ext and string is the text selection criteria.
verbs are aditive  e.g. -name begin_myf_contain_run1_ends_bla_ext_root
{PrintColor(COLORS.BIRed)}N.B. the text to be filtered cannot have underline i.e >_< within!!!{PrintColor(COLORS.ColorReset)}

-exclude     string            : (client-side) exclude result containing this string
-exclude_re  pattern           : (client-side) exclude result matching this regex
-user        string            : (client-side) match the user
-group       string            : (client-side) match the group
-jobid       string            : (client-side) match the jobid
-minsize   / -maxsize    int   : (client-side) restrict results to min/max bytes (inclusive)
-mindepth  / -maxdepth   int   : (client-side) restrict results to min/max depth
-min-ctime / -max-ctime  int(unix time) : (client-side) restrict results age to min/max unix-time
'''


def pathtype_grid(wb, path: str) -> str:
    """Query if a lfn is a file or directory, return f, d or empty"""
    if not wb or not path: return ''
    ret_obj = SendMsg(wb, 'type', [path], opts = 'nomsg log')
    if ret_obj.exitcode != 0: return ''
    file_stat_dict = ret_obj.ansdict['results'][0] if ret_obj.ansdict['results'] else {}
    file_type = file_stat_dict.get('type', '')
    return file_type[0] if file_type else ''  # return only first letter of 'type' attribute


def commit(wb, tokenstr: str, size: int, lfn: str, perm: str, expire: str, pfn: str, se: str, guid: str, md5sum: str) -> RET:
    """Upon successful xrootd upload to server, commit the guid name into central catalogue"""
    if not wb: return RET()
    return SendMsg(wb, 'commit', [tokenstr, int(size), lfn, perm, expire, pfn, se, guid, md5sum], opts = 'log')


def commitFile(wb, lfnInfo: CommitInfo) -> RET:
    """Upon successful xrootd upload to server, commit the guid name into central catalogue"""
    if not wb or not lfnInfo: return RET()
    return SendMsg(wb, 'commit', [lfnInfo.envelope, int(lfnInfo.size), lfnInfo.lfn, lfnInfo.perm, lfnInfo.expire, lfnInfo.pfn, lfnInfo.se, lfnInfo.guid, lfnInfo.md5], opts = 'log')


def commitFileList(wb, lfnInfo_list: list) -> list:  # returns list of RET
    """Upon successful xrootd upload to server, commit the guid name into central catalogue for a list of pfns"""
    if not wb or not lfnInfo_list: return []
    batch_size = 64
    batches_list = [lfnInfo_list[x: x + batch_size] for x in range(0, len(lfnInfo_list), batch_size)]
    commit_results = []
    for batch in batches_list:
        commit_list = []
        for file_commit in batch:
            jsoncmd = CreateJsonCommand('commit', [file_commit.envelope, int(file_commit.size), file_commit.lfn,
                                                   file_commit.perm, file_commit.expire, file_commit.pfn, file_commit.se,
                                                   file_commit.guid, file_commit.md5],
                                        'nokeys')
            commit_list.append(jsoncmd)
        commit_results.extend(SendMsgMulti(wb, commit_list, 'log'))
    return commit_results


def list_files_grid(wb, search_dir: str, pattern: Union[None, REGEX_PATTERN_TYPE, str] = None, is_regex: bool = False, find_args: Union[str, list, None] = None) -> RET:
    """Return a list of files(lfn/grid files) that match pattern found in search_dir
    Returns a RET object (from find), and takes: wb, directory, pattern, is_regex, find_args
    """
    if not search_dir: return RET(-1, "", "No search directory specified")

    if find_args is None: find_args = []
    find_args_list = find_args.split() if isinstance(find_args, str) else find_args.copy()

    # lets process the pattern: extract it from src if is in the path globbing form
    is_single_file = False  # dir actually point to a file

    dir_arg_list = search_dir.split()
    if len(dir_arg_list) > 1:  # dir is actually a list of arguments
        if not pattern: pattern = dir_arg_list.pop(-1)
        search_dir = dir_arg_list.pop(-1)
        if dir_arg_list: find_args = ' '.join(dir_arg_list)

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
    else:  # pattern is specified by argument
        if pattern is None:
            if not search_dir.endswith('/'):  # this is a single file
                is_single_file = True
            else:
                pattern = '*'  # prefer globbing as default
        elif isinstance(pattern, REGEX_PATTERN_TYPE):  # unlikely but supported to match signatures # noqa: PIE789
            pattern = pattern.pattern  # We pass the regex pattern into command as string
            is_regex = True

        # it was explicitly requested that pattern is regex
        if is_regex and isinstance(pattern, str) and valid_regex(pattern) is None:
            msg = f'list_files_grid:: {pattern} failed to re.compile'
            logging.error(msg)
            return RET(-1, '', msg)

    # remove default from additional args
    filter_args_list = []
    get_arg(find_args_list, '-v')
    get_arg(find_args_list, '-a')
    get_arg(find_args_list, '-s')
    get_arg(find_args_list, '-f')
    get_arg(find_args_list, '-d')
    get_arg(find_args_list, '-w')
    get_arg(find_args_list, '-wh')

    exclude_str_list = get_arg_value_multiple(find_args_list, '-exclude')
    for ex_str_pat in exclude_str_list:
        filter_args_list.extend(['-exclude', ex_str_pat])

    compiled_regex_list = []
    exclude_re_arg_list = get_arg_value_multiple(find_args_list, '-exclude_re')
    for ex_re_pat in exclude_re_arg_list:
        compiled_regex_list.append(re.compile(ex_re_pat))  # precompile the regex for exclusion

    min_depth = get_arg_value(find_args_list, '-mindepth')
    if min_depth:
        if not min_depth.isdigit() or min_depth.startswith("-"):
            print_err(f'list_files_grid::mindepth arg not recognized: {" ".join(find_args_list)}')
        else:
            filter_args_list.extend(['-mindepth', min_depth])

    max_depth = get_arg_value(find_args_list, '-maxdepth')
    if max_depth:
        if not max_depth.isdigit() or max_depth.startswith("-"):
            print_err(f'list_files_grid::maxdepth arg not recognized: {" ".join(find_args_list)}')
        else:
            filter_args_list.extend(['-maxdepth', max_depth])

    min_size = get_arg_value(find_args_list, '-minsize')
    if min_size:
        if not min_size.isdigit() or min_size.startswith("-"):
            print_err(f'list_files_grid::minsize arg not recognized: {" ".join(find_args_list)}')
        else:
            filter_args_list.extend(['-minsize', min_size])

    max_size = get_arg_value(find_args_list, '-maxsize')
    if max_size:
        if not max_size.isdigit() or max_size.startswith("-"):
            print_err(f'list_files_grid::maxsize arg not recognized: {" ".join(find_args_list)}')
        else:
            filter_args_list.extend(['-maxsize', max_size])

    min_ctime = get_arg_value(find_args_list, '-min-ctime')
    if min_ctime:
        if min_ctime.startswith("-"):
            print_err(f'list_files_grid::min-ctime arg not recognized: {" ".join(find_args_list)}')
        else:
            filter_args_list.extend(['-min-ctime', min_ctime])

    max_ctime = get_arg_value(find_args_list, '-max-ctime')
    if max_ctime:
        if max_ctime.startswith("-"):
            print_err(f'list_files_grid::max-ctime arg not recognized: {" ".join(find_args_list)}')
        else:
            filter_args_list.extend(['-max-ctime', max_ctime])

    jobid = get_arg_value(find_args_list, '-jobid')
    if jobid:
        if not jobid.isdigit() or jobid.startswith("-"):
            print_err(f'list_files_grid::jobid arg not recognized: {" ".join(find_args_list)}')
        else:
            filter_args_list.extend(['-jobid', jobid])

    user = get_arg_value(find_args_list, '-user')
    if user:
        if not user.isalpha() or user.startswith("-"):
            print_err(f'list_files_grid::user arg not recognized: {" ".join(find_args_list)}')
        else:
            filter_args_list.extend(['-user', user])

    group = get_arg_value(find_args_list, '-group')
    if group:
        if not group.isalpha() or group.startswith("-"):
            print_err(f'list_files_grid::group arg not recognized: {" ".join(find_args_list)}')
        else:
            filter_args_list.extend(['-group', group])

    # create and return the list object just for a single file
    if is_single_file:
        send_opts = 'nomsg' if not DEBUG else ''
        ret_obj = SendMsg(wb, 'stat', [search_dir], opts = send_opts)
    else:
        find_args_default = ['-f', '-a', '-s']
        if is_regex: find_args_default.insert(0, '-r')
        if find_args_list: find_args_default.extend(find_args_list)  # insert any other additional find arguments
        find_args_default.append(search_dir)
        find_args_default.append(pattern)
        send_opts = 'nomsg' if not DEBUG else ''
        ret_obj = SendMsg(wb, 'find', find_args_default, opts = send_opts)

    if ret_obj.exitcode != 0:
        logging.error('list_files_grid error:: %s %s %s', search_dir, pattern, find_args)
        return ret_obj
    if 'results' not in ret_obj.ansdict or not ret_obj.ansdict["results"]:
        logging.error('list_files_grid exitcode==0 but no results(!!!):: %s /pattern: %s /find_args: %s', search_dir, pattern, find_args)
        return RET(2, '', f'No files found in :: {search_dir} /pattern: {pattern} /find_args: {find_args}')

    exitcode = ret_obj.exitcode
    stderr = ret_obj.err
    results_list = ret_obj.ansdict["results"]
    results_list_filtered = []
    # items that pass the conditions are the actual/final results

    for found_lfn_dict in results_list:  # parse results to apply filters
        if filter_file_prop(found_lfn_dict, search_dir, filter_args_list, compiled_regex_list):
            results_list_filtered.append(found_lfn_dict)  # at this point all filters were passed

    if not results_list_filtered:
        return RET(2, "", f"No files passed the filters :: {search_dir} /pattern: {pattern} /find_args: {find_args}")

    ansdict = {"results": results_list_filtered}
    lfn_list = [get_lfn_key(lfn_obj) for lfn_obj in results_list_filtered]
    stdout = '\n'.join(lfn_list)
    return RET(exitcode, stdout, stderr, ansdict)


def extract_glob_pattern(path_arg: str) -> tuple:
    """Extract glob pattern from a path"""
    if not path_arg: return '', ''
    base_path = pattern = ''
    if '*' in path_arg:  # we have globbing in src path
        path_components = path_arg.split("/")
        base_path_arr = []  # let's establish the base path
        for el in path_components:
            if '*' not in el: base_path_arr.append(el)
            else: break

        for el in base_path_arr: path_components.remove(el)  # remove the base path components (those without *) from full path components
        base_path = f'{"/".join(base_path_arr)}{"/" if base_path_arr else ""}'  # rewrite the source path without the globbing part
        pattern = '/'.join(path_components)  # the globbing part is the rest of element that contain *
    else:
        base_path = path_arg
    return (base_path, pattern)


def path_type(path_arg: str) -> tuple:
    """Check if path is local or grid; default is grid and local must have file: prefix"""
    location = 'local' if path_arg.startswith('file:') else 'grid'
    return (path_arg, location)


if __name__ == '__main__':
    print('This file should not be executed!', file = sys.stderr, flush = True)
    sys.exit(95)
