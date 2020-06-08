import setuptools
import os


def get_version_from_file():
    try:
        f = open('./VERSION')
        version = f.read().split('/n')[0]
        f.close()
        return version
    except:
        print('Failed to get version from file. Using unknown')
        return 'unknown'


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
    name="alienpy",
    version=get_version_from_file(),
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
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
    ],
    project_urls={
        "Dev git": "https://github.com/adriansev/jalien_py",
        "Issues": "https://github.com/adriansev/jalien_py/issues",
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
            'alien-token-info = alienpy.alien:cmd_token_info',
            'alien-token-init = alienpy.alien:cmd_token_init',
            'alien-token-destroy = alienpy.alien:cmd_token_destroy',
        ]
    },
    keywords = 'CERN ALICE JAliEn GRID',



)

