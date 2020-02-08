import setuptools
import os

with open("README.md", "r") as fh:
    long_description = fh.read()

alibuild_requirements = [
        'readline',
        'async-stagger',
        'websockets',
        'pyOpenSSL',
    ]

standard_requirements = alibuild_requirements + ["xrootd"]

selected_requirements = standard_requirements if "ALIBUILD" not in os.environ.keys() else alibuild_requirements

setuptools.setup(
    name="xjalienfs",
    version="0.0.1",
    author="ALICE JAliEn",
    author_email="jalien@cern.ch",
    description="Websocket based cli interface for ALICE experiment GRID infrastructure",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://gitlab.cern.ch/jalien/xjalienfs",
    packages=setuptools.find_packages(),
    install_requires=selected_requirements,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: BSD 3-Clause License",
        "Operating System :: OS Independent",
    ],
    scripts = [
        'bin/alien_pfn',
    ],
    entry_points = {
        'console_scripts': [
            'aliensh = xjalienfs.alien:main',
            'alien_cmd = xjalienfs.alien:main',
            'alien_cp = xjalienfs.alien:cmd_cp',
            'alien_find = xjalienfs.alien:cmd_find',
            'alien_guid2lfn = xjalienfs.alien:cmd_guid2lfn',
            'alien_lfn2guid = xjalienfs.alien:cmd_lfn2guid',
            'alien_ls = xjalienfs.alien:cmd_ls',
            'alien_mirror = xjalienfs.alien:cmd_mirror',
            'alien_mkdir = xjalienfs.alien:cmd_mkdir',
            'alien_mv = xjalienfs.alien:cmd_mv',
            'alien_ps = xjalienfs.alien:cmd_ps',
            'alien_rm = xjalienfs.alien:cmd_rm',
            'alien_rmdir = xjalienfs.alien:cmd_rmdir',
            'alien_stat = xjalienfs.alien:cmd_stat',
            'alien_submit = xjalienfs.alien:cmd_submit',
            'alien-token-info = xjalienfs.alien:cmd_token_info',
            'alien-token-init = xjalienfs.alien:cmd_token_init',
            'alien_whereis = xjalienfs.alien:cmd_whereis',
        ]
    }
)

