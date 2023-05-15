"""WEBSOCKET:: Tools (not-networked) for WebSOcket communications"""

import os
import json
import shlex

from .global_vars import *  # nosec PYL-W0614
from .data_structs import *  # nosec PYL-W0614
from .tools_nowb import *  # nosec PYL-W0614
from .setup_logging import print_out, print_err
from .tools_stackcmd import push2stack, deque_pop_pos


def PrintDict(in_arg: Union[str, dict, list, None] = None, compact: bool = False):
    """Print a dictionary in a nice format"""
    if not in_arg: return
    if isinstance(in_arg, str):
        try:
            in_arg = json.loads(in_arg)
        except Exception as e:
            print_err(f'PrintDict:: Could not load argument as json!\n{e!r}')
            return
    if isinstance(in_arg, dict) or isinstance(in_arg, list):
        indent = None if compact else 2
        separators = (',', ':') if compact else None
        if 'HAS_PPRINT' in globals() and HAS_PPRINT:
            print_json(data = in_arg)
        else:
            print_out(json.dumps(in_arg, sort_keys = True, indent = indent, separators = separators, skipkeys = False))


def retf_print(ret_obj: RET, opts: str = '') -> int:
    """Process a RET object; it will return the exitcode
    opts content will steer the logging and message printing:
     - noprint : silence all stdout/stderr printing
     - noerr/noout : silence the respective messages
     - info/warn/err/debug : will log the stderr to that facility
     - json : will print just the json (if present)
    """
    if 'json' in opts:
        if ret_obj.ansdict:
            PrintDict(ret_obj.ansdict)
        else:
            print_err('This command did not return a json dictionary')
        return ret_obj.exitcode

    if ret_obj.exitcode != 0:
        if 'debug' in opts:
            logging.debug(ret_obj.err)
        elif 'info' in opts:
            logging.info(ret_obj.err)
        elif 'warn' in opts:
            logging.warning(ret_obj.err)
        else:
            logging.error(ret_obj.err)
        if ret_obj.err and not ('noerr' in opts or 'noprint' in opts): print_err(f'{ret_obj.err.strip()}')
    else:
        if ret_obj.out and not ('noout' in opts or 'noprint' in opts): print_out(f'{ret_obj.out.strip()}')
    return ret_obj.exitcode


def GetMeta(result: dict) -> dict:
    """Return metadata of an JAliEn response"""
    if not result: return {}
    if isinstance(result, dict) and 'metadata' in result: return result['metadata']
    return {}


def retf_result2ret(result: Union[str, dict, None]) -> RET:
    """Convert AliEn answer dictionary to RET object"""
    if not result: return RET(61, '', 'Empty input')  # type: ignore [call-arg]
    out_dict = None
    if isinstance(result, str):
        try:
            out_dict = json.loads(result)
        except Exception as e:
            msg = f'retf_result2ret:: Could not load argument as json!\n{e!r}'
            logging.error(msg)
            return RET(22, '', msg)  # type: ignore [call-arg]
    elif isinstance(result, dict):
        out_dict = result
    else:
        msg = f'retf_result2ret:: Wrong type of argument'
        logging.error(msg)
        return RET(42, '', msg)  # type: ignore [call-arg]

    if 'metadata' not in out_dict or 'results' not in out_dict:  # these works only for AliEn responses
        msg = 'retf_results2ret:: Dictionary does not have AliEn answer format'
        logging.error(msg)
        return RET(42, '', msg)  # type: ignore [call-arg]

    session_state_update(out_dict)  ## ALWAYS UPDATE GLOBAL STATE
    message_list = [str(item['message']) for item in out_dict['results'] if 'message' in item]
    output = '\n'.join(message_list)
    return RET(int(out_dict["metadata"]["exitcode"]), output.strip(), out_dict["metadata"]["error"], out_dict)  # type: ignore [call-arg]


def session_state_update (out_dict: dict) -> None:
    """Update global AlienSessionInfo with status of the latest command"""
    if 'AlienSessionInfo' in globals():  # update global state of session
        AlienSessionInfo['user'] = out_dict["metadata"]["user"]  # always update the current user
        current_dir = out_dict["metadata"]["currentdir"]

        # if this is first connection, current dir is alien home
        if not AlienSessionInfo['alienHome']: AlienSessionInfo['alienHome'] = current_dir

        # update the current current/previous dir status
        # previous/current have the meaning of before and after command execution
        prev_dir = AlienSessionInfo['currentdir']  # last known current dir
        if prev_dir != current_dir:
            AlienSessionInfo['currentdir'] = current_dir
            AlienSessionInfo['prevdir'] = prev_dir

        # update directory stack (pushd/popd/dirs)
        short_current_dir = current_dir.replace(AlienSessionInfo['alienHome'][:-1], '~')
        short_current_dir = short_current_dir[:-1]  # remove the last /
        if AlienSessionInfo['pathq']:
            if AlienSessionInfo['pathq'][0] != short_current_dir: AlienSessionInfo['pathq'][0] = short_current_dir
        else:
            push2stack(short_current_dir)


def CreateJsonCommand(cmdline: Union[str, dict], args: Union[None, list] = None, opts: str = '', get_dict: bool = False) -> Union[str, dict]:
    """Return a json with command and argument list"""
    if not cmdline: return ''
    if args is None: args = []
    if isinstance(cmdline, dict):
        if not 'command' in cmdline or 'options' not in cmdline: return ''
        out_dict = cmdline.copy()
        if 'showmsg' in opts: opts = opts.replace('nomsg', '')
        if 'showkeys' in opts: opts = opts.replace('nokeys', '')
        if 'nomsg' in opts: out_dict["options"].insert(0, '-nomsg')
        if 'nokeys' in opts: out_dict["options"].insert(0, '-nokeys')
        return out_dict if get_dict else json.dumps(out_dict)

    if not args:
        args = shlex.split(cmdline)
        cmd = args.pop(0) if args else ''
    else:
        cmd = cmdline
    if 'nomsg' in opts: args.insert(0, '-nomsg')
    if 'nokeys' in opts: args.insert(0, '-nokeys')
    jsoncmd = {"command": cmd, "options": args}
    return jsoncmd if get_dict else json.dumps(jsoncmd)


class Msg:
    """Class to create json messages to be sent to server"""
    __slots__ = ('cmd', 'args', 'opts')

    def __init__(self, cmd: str = '', args: Union[str, list, None] = None, opts: str = '') -> None:
        self.cmd = cmd
        self.opts = opts
        if not args:
            self.args = []
        elif isinstance(args, str):
            self.args = shlex.split(args)
        elif isinstance(args, list):
            self.args = args.copy()

    def add_arg(self, arg: Union[str, list, None]) -> None:
        if not arg: return
        if isinstance(arg, str): self.args.extend(shlex.split(arg))
        if isinstance(arg, list): self.args.extend(arg)

    def msgdict(self) -> dict:
        return CreateJsonCommand(self.cmd, self.args, self.opts, True)

    def msgstr(self) -> str:
        return CreateJsonCommand(self.cmd, self.args, self.opts)

    def __call__(self) -> tuple:
        return (self.cmd, self.args, self.opts)

    def __bool__(self):
        return bool(self.cmd)


if __name__ == '__main__':
    print('This file should not be executed!', file = sys.stderr, flush = True)
    sys.exit(95)
    
    
    
    

