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

alibuild_requirements = standard_requirements + ['gnureadline']
selected_requirements = standard_requirements if "ALIBUILD" not in os.environ.keys() else alibuild_requirements

setuptools.setup(
    name="xjalienfs",
    version="1.0.5",
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

    entry_points = {
        'console_scripts': [
            'alien.py = xjalienfs.alien:main',
        ]
    }
)

