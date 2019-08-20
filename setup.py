import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

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
    install_requires=[
        'urllib3',
        'pathlib2',
        'websockets',
        'pyOpenSSL',
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: BSD 3-Clause License",
        "Operating System :: OS Independent",
    ],
)

