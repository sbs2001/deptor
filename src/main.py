import os
import json
import sys

import package_detector
from univers.versions import PYPIVersion
from univers.version_specifier import VersionSpecifier


def build_index(): 
    package_vulnerability_index = {}
    response_path = os.path.join( os.path.dirname(os.path.abspath(__file__)) , "response.json")
    with open(response_path) as f :
        response = json.load(f)
        for edge in response[0]["data"]["securityVulnerabilities"]["edges"]:
            package_name = edge["node"]["package"]["name"].lower()
            vulnerable_range = edge["node"]["vulnerableVersionRange"]
            
            if package_name not in package_vulnerability_index: 
                package_vulnerability_index[package_name] = []
            
            package_vulnerability_index[package_name].append({})
            package_vulnerability_index[package_name][-1]["version_range"] = vulnerable_range
            package_vulnerability_index[package_name][-1]["vulnerabilities"] = []

            for vulnerability_ids in edge["node"]["advisory"]["identifiers"]:
                package_vulnerability_index[package_name][-1]["vulnerabilities"].append(
                    vulnerability_ids["value"]
                )
    
    return package_vulnerability_index

def build_report(package_vulnerability_index, detected_packages):
    report = []
    _package_index = {}
    for index,package in enumerate(detected_packages):
        if package not in _package_index:
            report.append(
                {
                    "package_name":package.name,
                    "package_version": package.version,
                    "vulnerabilities":[]
                }
            )
            _package_index[package.name] = index
        else:
            index = _package_index[package.name]
        
        if package.name in package_vulnerability_index:
            version_object = PYPIVersion(package.version)
            for vulnerability_data in package_vulnerability_index[package.name]:
                if version_object in VersionSpecifier.from_scheme_version_spec_string("pypi",vulnerability_data["version_range"]):
                    report[index]["vulnerabilities"].extend(vulnerability_data["vulnerabilities"])
    
    return json.dumps(report, indent=4)


if __name__ == "__main__":
    detected_packages = package_detector.detect()
    package_vulnerability_index = build_index()
    print(build_report(package_vulnerability_index, detected_packages))


