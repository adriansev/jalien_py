import setuptools
import os
import sys


def get_version_from_file():
    try:
        f = open('alienpy/VERSION', encoding="ascii")
        version = f.read().strip()
        f.close()
        return version
    except Exception as e:
        print('Failed to get version from file. Using unknown')
        return 'unknown'


with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

base_requirements = [ 'async-stagger', 'pyOpenSSL', 'rich', 'requests', ]
alibuild_requirements = [ 'gnureadline' ]
local_requirements = [ 'xrootd' ]

if sys.version_info[1] < 7:
    base_requirements.append('websockets<=9.1')
else:
    base_requirements.append('websockets')

# ALICE needs gnureadline as the python built does not have built-in readline for macos reasons
# also the xrootd is built in a separate recipe
if "ALIBUILD" in os.environ.keys():
    selected_requirements = base_requirements + alibuild_requirements
else:
    selected_requirements = base_requirements + local_requirements

setuptools.setup(
    name="alienpy",
    version=get_version_from_file(),
    author="Adrian Sevcenco",
    author_email="adrian.sevcenco@cern.ch",
    description="Websocket based cli interface for ALICE experiment GRID infrastructure",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://gitlab.cern.ch/jalien/xjalienfs",
    packages=setuptools.find_packages(),
    install_requires=selected_requirements,
    python_requires='>=3.6',
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
    ],
    project_urls={
        "Dev git": "https://github.com/adriansev/jalien_py",
        "Issues": "https://github.com/adriansev/jalien_py/issues",
        "Changelog": "https://github.com/adriansev/jalien_py/commits/master",
        "Documentation": "https://jalien.docs.cern.ch",
        "CERN Mattermost/JAliEn": "https://mattermost.web.cern.ch/alice/channels/jalien",
    },
    entry_points = {
        'console_scripts': [
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
            'alien_rm = alienpy.alien:main',
            'alien_rmdir = alienpy.alien:main',
            'alien_stat = alienpy.alien:main',
            'alien_submit = alienpy.alien:main',
            'alien_whereis = alienpy.alien:main',
            'alien-cert-info = alienpy.alien:cmd_cert_info',
            'alien-token-info = alienpy.alien:cmd_token_info',
            'alien-token-init = alienpy.alien:cmd_token_init',
            'alien-token-destroy = alienpy.alien:cmd_token_destroy',
        ]
    },
    scripts = [
        'examples/alien_wbtime',
        ],
    data_files = [('alienpy', ['alienpy/VERSION'])],
    keywords = 'CERN ALICE JAliEn GRID',

)

