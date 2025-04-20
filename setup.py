from setuptools import setup, find_packages

with open("README", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name='pyserpent',
    version='1.0.1',
    description='Pure Python implementation of the Serpent block cipher with CBC mode and PKCS#7 padding',
    author='svvqt',
    author_email='kon.vitkovskii@gmail.com',
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/svvqt/pyserpent",
    packages=["pyserpent"],
    classifiers=[
        'Programming Language :: Python :: 3',
        'Topic :: Security :: Cryptography',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
)