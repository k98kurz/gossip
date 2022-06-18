from setuptools import setup, find_packages

with open('readme.md', 'r') as f:
    readme = f.read()

with open('license.txt', 'r') as f:
    license = f.read()

with open('requirements.txt', 'r') as f:
    requirements = f.read()

setup(
    name='Gossip',
    version='0.0.1',
    author='k98kurz@github',
    url='https://github.com/k98kurz/gossip',
    description='Simple library for building applications that use a gossip protocol.',
    long_description=readme,
    license=license,
    packages=find_packages(exclude=('tests', 'docs', 'examples')),
    install_requires=requirements,
    python_requires='>=3.6.0',
    classifiers=[
        "Programming Language :: Python :: 3",
        "Development Status :: 2 - Pre-Alpha",
        "Intended Audience :: Developers",
        "Topic :: Communications",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries",
        "Topic :: System :: Networking",
        "License :: OSI Approved :: ISC License (ISCL)",
    ],
)