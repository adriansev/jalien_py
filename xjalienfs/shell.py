#!/usr/bin/env python3
import argparse
from xjalienfs import alien
import tempfile
import shlex
from cmd2 import Cmd as cmd, with_argparser, rl_utils
import logging
import os
import subprocess
import sys
import asyncio
from xjalienfs import utils
from cmd2 import Cmd2ArgumentParser as ACArgumentParser
import websockets

if sys.version_info[0] != 3 or sys.version_info[1] < 6:
    print("This script requires a minimum of Python version 3.6")
    sys.exit(1)

websocket = None
local_file_system = True
cassandra_error = 'This command can only be run on jSh, use the "switch" command to change shell.'


class Commander(cmd):
    os.chdir(os.getenv('HOME'))
    intro = 'Welcome to the jAliEn shell. Try ? or help to list commands.\nTo change between the grid and your local ' \
            'file system, use the "switch" command. '
    if local_file_system:
        prompt = os.path.abspath(os.curdir) + ' >'
    else:
        prompt = alien.currentdir + ' >'
    file = None
    cd_parser = None
    parser = ACArgumentParser()

    async def initiate_connection(self) -> websockets.connect:
        global websocket
        ssl_context = alien.create_ssl_context()
        websocket = await websockets.connect(alien.fHostWSUrl, ssl=ssl_context, max_queue=4, max_size=16 * 1024 * 1024,
                                             close_timeout=60, ping_timeout=60, ping_interval=60)
        return websocket

    def __init__(self):
        global websocket

        # Initiate cmd2. Set history file and allow the use of IPython to create scripts
        cmd.__init__(self, persistent_history_file=os.getenv('HOME') + '/history.txt', use_ipython=True)

        # Give scripts made by the user access to this class
        self.locals_in_py = True

        # Sets the completer for lcd equal to the local file system
        self.complete_lcd = self.path_complete

        # Start the websocket connection and get a list of commands/set global variables in alien
        websocket = asyncio.get_event_loop().run_until_complete(self.initiate_connection())
        alien.websocket = websocket
        asyncio.get_event_loop().run_until_complete(alien.JAlienConnect('commandlist'))

        # Set the completer for cd equal to all files/directories in the current directory
        ls_list = asyncio.get_event_loop().run_until_complete(utils.get_completer_list(websocket))
        self.cd_parser = self.parser.add_argument('cd', choices=ls_list, type=str)

    def decorator(self, local=local_file_system):
        if local:
            self.cd_parser.choices = asyncio.get_event_loop().run_until_complete(utils.get_completer_list(websocket))
        else:
            self.cd_parser.choices = asyncio.get_event_loop().run_until_complete(utils.get_completer_list(websocket))


    def do_echo(self, arg):
        """"Print what you write"""
        if local_file_system:
            rl_utils.rl_set_prompt('heisann')
            rl_utils.rl_force_redisplay()
            self.run_on_local_shell('echo ' + arg)
        else:
            print(arg)


    def do_quit(self, arg):
        """"Exit the shell"""

        print('Goodbye!')
        exit(0)

    def do_lcd(self, arg):
        """Change local directory"""
        os.chdir(arg)
        self.prompt = os.path.abspath(os.curdir) + ' >'

    @with_argparser(parser)
    def do_cd(self, arg: argparse.Namespace):
        """Change directory"""
        if local_file_system:
            os.chdir(arg)
            self.prompt = os.path.abspath(os.curdir) + ' >'
        else:
            self.parseCMD(arg.__statement__.raw)
            self.prompt = alien.currentdir + ' >'
            self.decorator()

    def do_ls(self, arg):
        """List of all entities in current path"""
        if local_file_system:
            print(os.listdir(os.curdir))
        else:
            self.parseCMD('ls ' + arg)
        return 5

    def do_less(self, arg):
        """Read content in file"""
        if local_file_system:
            self.run_on_local_shell('less ' + arg)

    def do_switch(self, arg):
        """Change between your local file system and the grid"""
        global local_file_system
        local_file_system = not local_file_system
        if local_file_system:
            self.prompt = os.path.abspath(os.curdir) + ' >'
        else:
            self.prompt = alien.currentdir + ' >'

    def do_vim(self, arg):
        """Edit text file"""
        if local_file_system:

            EDITOR = os.environ.get('EDITOR') if os.environ.get('EDITOR') else 'vim'  # that easy!
            with tempfile.NamedTemporaryFile(suffix=".tmp") as tf:
                tf.flush()
                subprocess.call([EDITOR, tf.name])
                # do the parsing with `tf` using regular File operations.
                # for instance:
                tf.seek(0)
                edited_message = tf.read()

    def do_get(self, arg):
        """???"""
        if local_file_system:
            print("This command ")
        else:
            self.parseCMD('get ' + arg)

    def do_ls_csd(self, arg):
        """Runs the ls command in Cassandra. Can only be run on jSh"""
        global cassandra_error
        if local_file_system:
            print(cassandra_error)
        else:
            self.parseCMD('ls_csd ' + arg)

    def do_cat(self, arg):
        """Reads a file and writes it to output"""
        if local_file_system:
            self.run_on_local_shell('cat ' + arg)
        else:
            self.parseCMD('cat ' + arg)

    def do_cat_csd(self, arg):
        """Reads a file and writes it to output. Can only be run on jSh"""
        global cassandra_error
        if local_file_system:
            print(cassandra_error)
        else:
            self.parseCMD('cat_csd ' + arg)

    def do_whereis(self, arg):
        """Locates source/binary and manuals sections for specified files"""
        if local_file_system:
            self.run_on_local_shell('whereis ' + arg)
        else:
            self.parseCMD('whereis ' + arg)

    def do_whereis_csd(self, arg):
        """Locates source/binary and manuals sections for specified files"""
        if local_file_system:
            print(cassandra_error)
        else:
            self.parseCMD('whereis_csd ' + arg)

    def do_cp(self, arg):
        """Copies file"""
        if local_file_system:
            self.run_on_local_shell('cp ' + arg)
        else:
            self.parseCMD('cp ' + arg)

    def do_cp_csd(self, arg):
        """Copies File"""
        if local_file_system:
            print(cassandra_error)
        else:
            self.parseCMD('cp_csd ' + arg)

    def do_time(self, arg):
        """Usage: time <times> <command> [command_arguments]"""
        if local_file_system:
            self.run_on_local_shell('time ' + arg)
        else:
            self.parseCMD('time ' + arg)

    def do_mkdir(self, arg):
        """Create Directory"""
        if local_file_system:
            try:
                os.mkdir(arg)
            except FileExistsError:
                print('The directory ' + arg + ' already exist')
        else:
            self.parseCMD('mkdir ' + arg)

    def do_mkdir_csd(self, arg):
        """Create Directory"""
        if local_file_system:
            print(cassandra_error)
        else:
            self.parseCMD('mkdir_csd ' + arg)

    def do_find(self, arg):
        """Finds and locates matching filenames"""
        if local_file_system:
            self.run_on_local_shell('find ' + arg)
        else:
            self.parseCMD('find ' + arg)

    def do_find_csd(self, arg):
        """Finds and locates matching filenames"""
        if local_file_system:
            print(cassandra_error)
        else:
            self.parseCMD('find_csd ' + arg)

    def do_listFilesFromCollection(self, arg):
        """..."""
        if local_file_system:
            print('Cannot run locally')
        else:
            self.parseCMD('listFilesFromCollection ' + arg)

    def do_submit(self, arg):
        """Submits file"""
        if local_file_system:
            print('Cannot run locally')
        else:
            self.parseCMD('submit ' + arg)

    def do_motd(self, arg):
        """Message of the day!"""
        if local_file_system:
            print('Have a great day!')
        else:
            self.parseCMD('motd ' + arg)

    def do_access(self, arg):
        """..."""
        if local_file_system:
            print('Cannot be run locally')
        else:
            self.parseCMD('access ' + arg)

    def do_commit(self, arg):
        """..."""
        if local_file_system:
            print('Cannot run locally')
        else:
            self.parseCMD('commit ' + arg)

    def do_packages(self, arg):
        """List available packages"""
        if local_file_system:
            print('Cannot be run locally')
        else:
            self.parseCMD('packages ' + arg)

    def do_pwd(self, arg):
        """Prints current directory"""
        if local_file_system:
            self.run_on_local_shell('pwd ' + arg)
        else:
            self.parseCMD('pwd ' + arg)

    def do_ps(self, arg):
        """Reports information on running processes"""
        if local_file_system:
            self.run_on_local_shell('ps ' + arg)
        else:
            self.parseCMD('ps ' + arg)

    def do_rmdir(self, arg):
        """Remove directories"""
        if local_file_system:
            self.run_on_local_shell('rmdir ' + arg)
        else:
            self.parseCMD('rmdir ' + arg)

    def do_rm(self, arg):
        """Remove files"""
        if local_file_system:
            self.run_on_local_shell('rm ' + arg)
        else:
            self.parseCMD('rm ' + arg)

    def do_rm_csd(self, arg):
        """Remove files"""
        if local_file_system:
            print(cassandra_error)
        else:
            self.parseCMD('rm_csd ' + arg)

    def do_mv(self, arg):
        """Move files"""
        if local_file_system:
            self.run_on_local_shell('mv ' + arg)
        else:
            self.parseCMD('mv ' + arg)

    def do_mv_csd(self, arg):
        """Move files"""
        if local_file_system:
            print(cassandra_error)
        else:
            self.parseCMD('mv_csd ' + arg)

    def do_masterjob(self, arg):
        """..."""
        if local_file_system:
            print('Cannot be run locally')
        else:
            self.parseCMD('masterjob ' + arg)

    def do_user(self, arg):
        """Change role of user specified"""
        if local_file_system:
            print('Cannot be run locally')
        else:
            self.parseCMD('user ' + arg)

    def do_touch(self, arg):
        """Create file"""
        if local_file_system:
            self.run_on_local_shell('touch ' + arg)
        else:
            self.parseCMD('touch ' + arg)

    def do_touch_csd(self, arg):
        """Create file"""
        if local_file_system:
            print(cassandra_error)
        else:
            self.parseCMD('touch_csd ' + arg)

    def do_type(self, arg):
        """..."""
        if local_file_system:
            self.run_on_local_shell('type ' + arg)
        else:
            self.parseCMD('type ' + arg)

    def do_kill(self, arg):
        """Kill process"""
        if local_file_system:
            self.run_on_local_shell('kill ' + arg)
        else:
            self.parseCMD('kill ' + arg)

    def do_lfn2guid(self, arg):
        """Prints guid for given lfn"""
        if local_file_system:
            print('Cannot be run locally')
        else:
            self.parseCMD('lfn2guid ' + arg)

    def do_guid2lfn(self, arg):
        """Prints lfn for given guid"""
        if local_file_system:
            print('Cannot be run locally')
        else:
            self.parseCMD('guid2lfn ' + arg)

    def do_guid2lfn_csd(self, arg):
        """Prints lfn for given guid"""
        if local_file_system:
            print('Cannot be run locally')
        else:
            self.parseCMD('guid2lfn_csd ' + arg)

    def do_w(self, arg):
        """Get list of active/waiting jobs"""
        if local_file_system:
            print('Cannot be run locally')
        else:
            self.parseCMD('w ' + arg)

    def do_uptime(self, arg):
        """Get list of running/waiting jobs and active users"""
        if local_file_system:
            print('Cannot be run locally')
        else:
            self.parseCMD('uptime ' + arg)

    def do_chown(self, arg):
        """Changes an owner or a group for a file"""
        if local_file_system:
            self.run_on_local_shell('chown ' + arg)
        else:
            self.parseCMD('chown ' + arg)

    def do_chown_csd(self, arg):
        """Changes an owner or a group for a file"""
        if local_file_system:
            print(cassandra_error)
        else:
            self.parseCMD('chown_csd ' + arg)

    def do_deleteMirror(self, arg):
        """Removes a replica of a file from the catalogue"""
        if local_file_system:
            print('Cannot be run locally')
        else:
            self.parseCMD('deleteMirror ' + arg)

    def do_df(self, arg):
        """Shows free disk space"""
        if local_file_system:
            self.run_on_local_shell('df ' + arg)
        else:
            self.parseCMD('df ' + arg)

    def do_du(self, arg):
        """Gives the disk space usage of a directory"""
        if local_file_system:
            self.run_on_local_shell('du ' + arg)
        else:
            self.parseCMD('du ' + arg)

    def do_fquota(self, arg):
        """Displays information about File Quotas"""
        if local_file_system:
            print('Cannot be run locally')
        else:
            self.parseCMD('fquota ' + arg)

    def do_jquota(self, arg):
        """Displays information about Job Quotas"""
        if local_file_system:
            print('Cannot be run locally')
        else:
            self.parseCMD('jquota ' + arg)

    def do_listSEDistance(self, arg):
        """Returns the closest working SE for a particular site"""
        if local_file_system:
            print('Cannot be run locally')
        else:
            self.parseCMD('listSEDistance ' + arg)

    def do_listTransfer(self, arg):
        """Returns all the transfers that are waiting in the system"""
        if local_file_system:
            print('Cannot be run locally')
        else:
            self.parseCMD('listTransfer ' + arg)

    def do_md5sum(self, arg):
        """Returns MD5 checksum of given filename or guid"""
        if local_file_system:
            print('Cannot be run locally')
        else:
            self.parseCMD('md5sum ' + arg)

    def do_mirror(self, arg):
        """Mirror copies a file into another SE"""
        if local_file_system:
            print('Cannot be run locally')
        else:
            self.parseCMD('mirror ' + arg)

    def do_resubmit(self, arg):
        """Resubmits a job or a group of jobs by IDs"""
        if local_file_system:
            print('Cannot be run locally')
        else:
            self.parseCMD('resubmit ' + arg)

    def do_top(self, arg):
        """Display and update information about running processes"""
        if local_file_system:
            self.run_on_local_shell('top ' + arg)
        else:
            self.parseCMD('top ' + arg)

    def do_groups(self, arg):
        """Shows the groups current user is a member of"""
        if local_file_system:
            print('Cannot be run locally')
        else:
            self.parseCMD('groups ' + arg)

    def do_token(self, arg):
        """..."""
        if local_file_system:
            print('Cannot be run locally')
        else:
            self.parseCMD('token ' + arg)

    def do_uuid(self, arg):
        """Returns info about given lfn"""
        if local_file_system:
            print('Cannot be run locally')
        else:
            self.parseCMD('uuid ' + arg)

    def do_stat(self, arg):
        """..."""
        if local_file_system:
            self.run_on_local_shell('stat ' + arg)
        else:
            self.parseCMD('stat ' + arg)

    def do_listSEs(self, arg):
        """Print all (or a subset) of the defined SEs with their details"""
        if local_file_system:
            print('Cannot be run locally')
        else:
            self.parseCMD('listSEs ' + arg)

    def do_xrdstat(self, arg):
        """..."""
        if local_file_system:
            print('Cannot be run locally')
        else:
            self.parseCMD('xrdstat ' + arg)

    def do_whois(self, arg):
        """Usage: whois [account name]"""
        if local_file_system:
            self.run_on_local_shell('whois ' + arg)
        else:
            self.parseCMD('whois ' + arg)

    '''
    def settings_ns_provider(self) -> argparse.Namespace:
        ns = argparse.Namespace()
        ns.app_settings = 
    '''

    '''
    def do_(self, arg):
        """XX"""
        if local_file_system:
            self.run_on_local_shell(' ' + arg)
        else:
            self.parseCMD(' ' + arg)
    '''


    def parseCMD(self, args):
        args = shlex.split(args)
        cmd1 = args.pop(0)
        #jsoncmd = CreateJsonCommand(cmd1, args)
        #if DEBUG: print(jsoncmd)
        if args:
            print(args)
            asyncio.get_event_loop().run_until_complete(alien.JAlienConnect(cmd1, args))
        else:
            asyncio.get_event_loop().run_until_complete(alien.JAlienConnect(cmd1))

    def run_on_local_shell(self, arg):
        shellcmd_out= subprocess.Popen(arg, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
        stdout, stderr = shellcmd_out.communicate()
        if stdout: print(stdout.decode())
        if stderr: print(stderr.decode())


def main():
    # Let's start the connection
    logger = logging.getLogger('websockets')
    logger.setLevel(logging.ERROR)
    # logger.setLevel(logging.DEBUG)
    logger.addHandler(logging.StreamHandler())

    script_name = sys.argv[0]
    if '_json' in script_name: json_output = bool(True)
    if '_json_all' in script_name: json_meta_output = bool(True)
    app = Commander()
    app.cmdloop()

if __name__ == '__main__':
    main()
