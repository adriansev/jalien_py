import setuptools
import os

with open("README.md", "r") as fh:
    long_description = fh.read()

alibuild_requirements = [
        'gnureadline',
        'async-stagger',
        'websockets',
        'pyOpenSSL',
    ]

standard_requirements = alibuild_requirements + ["pyxrootd"]

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
)

