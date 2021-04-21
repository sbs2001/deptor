import sys
from collections import namedtuple

Package = namedtuple("Package", ("name", "version"))

def detect():
    packages = []
    for package_spec in sys.stdin:
        name, version = package_spec.split("==")
        packages.append(
            Package(
                name=name,
                version=version.replace("\n", "")
            )
        )
    
    return packages
