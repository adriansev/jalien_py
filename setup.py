import os
import sys
import setuptools
import traceback

try:
    from alienpy.version import ALIENPY_VERSION_HASH, ALIENPY_VERSION_DATE, ALIENPY_VERSION_STR
except Exception:
    try:
        from xjalienfs.version import ALIENPY_VERSION_HASH, ALIENPY_VERSION_DATE, ALIENPY_VERSION_STR
    except Exception:
        traceback.print_exc()
        print('Failed to get version from file. Using 0.0.0')
        ALIENPY_VERSION_STR = '0.0.0'

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

base_requirements = [ 'async-stagger >= 0.3.1', 'pyOpenSSL >= 25.0.0', 'rich', 'requests', ]
local_requirements = [ 'xrootd >= 5.8.2' ]

if sys.version_info[1] < 7:
    base_requirements.append('websockets <= 9.1')
else:
    base_requirements.append('websockets >= 15.0.0')

if sys.platform == 'darwin':
    base_requirements.append('gnureadline')

# ALICE have XRootD built in a separate recipe
selected_requirements = base_requirements

if "ALIBUILD" not in os.environ:
    selected_requirements = base_requirements + local_requirements

setuptools.setup(
    name = "alienpy",
    version = ALIENPY_VERSION_STR,
    packages = setuptools.find_packages(),
    author = "Adrian Sevcenco",
    author_email = "adrian.sevcenco@cern.ch",
    description = "Websocket based cli interface for ALICE experiment GRID infrastructure",
    long_description = long_description,
    long_description_content_type = "text/markdown",
    url = "https://gitlab.cern.ch/jalien/xjalienfs",
    install_requires = selected_requirements,
    python_requires = '>=3.9',
    license = "BSD-3-Clause",
    classifiers = [
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
        ],
    project_urls = {
        "Dev git": "https://github.com/adriansev/jalien_py",
        "Issues": "https://github.com/adriansev/jalien_py/issues",
        "Changelog": "https://github.com/adriansev/jalien_py/commits/master",
        "Documentation": "https://jalien.docs.cern.ch",
        "CERN Mattermost/JAliEn": "https://mattermost.web.cern.ch/alice/channels/jalien",
        },
    entry_points = {'console_scripts': [
                                       'alien.py = alienpy.alien:main',
                                       'alien_cmd = alienpy.alien:main',
                                       'alien_cp = alienpy.alien:main',
                                       'alien_find = alienpy.alien:main',
                                       'alien_guid2lfn = alienpy.alien:main',
                                       'alien_lfn2guid = alienpy.alien:main',
                                       'alien_ls = alienpy.alien:main',
                                       'alien_mirror = alienpy.alien:main',
                                       'alien_mkdir = alienpy.alien:main',
                                       'alien_mv = alienpy.alien:main',
                                       'alien_pfn = alienpy.alien:main',
                                       'alien_ps = alienpy.alien:main',
                                       'alien_pwd = alienpy.alien:main',
                                       'alien_rm = alienpy.alien:main',
                                       'alien_rmdir = alienpy.alien:main',
                                       'alien_stat = alienpy.alien:main',
                                       'alien_submit = alienpy.alien:main',
                                       'alien_whereis = alienpy.alien:main',
                                       'alien-cert-info = alienpy.alien:cmd_cert_info',
                                       'alien-token-info = alienpy.alien:cmd_token_info',
                                       'alien-token-init = alienpy.alien:cmd_token_init',
                                       'alien-token-destroy = alienpy.alien:cmd_token_destroy',
                                       'alien_home = alienpy.alien:cmd_home'
                                       ]
                    },
    scripts = [ 'examples/alien_wbtime', ],
    keywords = 'CERN ALICE JAliEn GRID',
)

