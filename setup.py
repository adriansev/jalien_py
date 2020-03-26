import setuptools
import os

with open("README.md", "r") as fh:
    long_description = fh.read()

standard_requirements = [
        'async-stagger',
        'websockets',
        'pyOpenSSL',
        'xrootd',
    ]

if "ALIBUILD" not in os.environ.keys():
    selected_requirements = standard_requirements
else:
    standard_requirements.remove('xrootd')
    selected_requirements = standard_requirements + ['gnureadline']

setuptools.setup(
    name="xjalienfs",
    version="1.0.8",
    author="ALICE JAliEn",
    author_email="jalien@cern.ch",
    description="Websocket based cli interface for ALICE experiment GRID infrastructure",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://gitlab.cern.ch/jalien/xjalienfs",
    packages=setuptools.find_packages(),
    install_requires=selected_requirements,
    python_requires='>=3.6',
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: BSD 3-Clause License",
        "Operating System :: OS Independent",
    ],
    project_urls={
        "Developer git": "https://github.com/adriansev/jalien_py",
        "Project(experiment) git": "https://gitlab.cern.ch/jalien/xjalienfs",
        "Issues": "https://github.com/adriansev/jalien_py/issues",
    },
    entry_points = {
        'console_scripts': [
            'alien.py = xjalienfs.alien:main',
            'alien_cmd = xjalienfs.alien:main',
            'alien_cp = xjalienfs.alien:main',
            'alien_find = xjalienfs.alien:main',
            'alien_guid2lfn = xjalienfs.alien:main',
            'alien_lfn2guid = xjalienfs.alien:main',
            'alien_ls = xjalienfs.alien:main',
            'alien_mirror = xjalienfs.alien:main',
            'alien_mkdir = xjalienfs.alien:main',
            'alien_mv = xjalienfs.alien:main',
            'alien_pfn = xjalienfs.alien:main',
            'alien_ps = xjalienfs.alien:main',
            'alien_rm = xjalienfs.alien:main',
            'alien_rmdir = xjalienfs.alien:main',
            'alien_stat = xjalienfs.alien:main',
            'alien_submit = xjalienfs.alien:main',
            'alien_whereis = xjalienfs.alien:main',
            'alien-token-info = xjalienfs.alien:cmd_token_info',
            'alien-token-init = xjalienfs.alien:cmd_token_init',
            'alien-token-destroy = xjalienfs.alien:cmd_token_destroy',
        ]
    }
)

