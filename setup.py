import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="binalyzer",
    version="0.0.1",
    author="Nicolaas",
    author_email="nweidema@usc.edu",
    description="A framework for running analyses on a number of target binary executables automatically.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/usc-isi-bass/binalyzer",
    packages=setuptools.find_packages(),
    license="GNU General Public License v3.0"
)

