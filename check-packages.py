#!/usr/bin/env python3

import yaml
import sys
import argparse
import re
from pathlib import Path
from typing import List, Dict, Any, Tuple

def parse_package_list(file_path: str) -> List[Dict[str, str]]:
    """Parse a package list file."""
    if not Path(file_path).exists():
        print(f"❌ Package list file not found: {file_path}")
        sys.exit(1)
    
    packages = []
    with open(file_path, 'r') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if line and not line.startswith('#'):
                parts = line.split()
                if len(parts) >= 2:
                    packages.append({
                        'name': parts[0],
                        'version': parts[1]
                    })
                elif len(parts) == 1:
                    packages.append({
                        'name': parts[0],
                        'version': 'any'
                    })
                else:
                    print(f"⚠️  Skipping invalid line {line_num}: {line}")
    
    return packages

def detect_lockfile_type(lockfile_path: str) -> str:
    """Detect the type of lockfile (pnpm or yarn)."""
    if not Path(lockfile_path).exists():
        return "unknown"
    
    with open(lockfile_path, 'r') as f:
        first_lines = ''.join(f.readlines()[:10])
        
        if 'lockfileVersion:' in first_lines or 'pnpm-lock.yaml' in lockfile_path:
            return "pnpm"
        elif 'yarn lockfile v' in first_lines or 'yarn.lock' in lockfile_path:
            return "yarn"
        else:
            return "unknown"

def parse_yarn_lockfile(lockfile_path: str) -> Dict[str, Any]:
    """Parse a yarn.lock file."""
    packages = {}
    current_package = None
    current_data = {}
    
    with open(lockfile_path, 'r') as f:
        lines = f.readlines()
    
    for line in lines:
        line = line.rstrip()
        
        # Skip comments and empty lines
        if line.startswith('#') or not line.strip():
            continue
        
        # Check if this is a package declaration line
        if not line.startswith(' ') and not line.startswith('\t'):
            # Save previous package if exists
            if current_package and current_data:
                # Extract package name from the key (handle multiple selectors)
                package_name = extract_package_name_from_yarn_key(current_package)
                if package_name:
                    packages[package_name] = current_data
            
            # Start new package
            current_package = line.rstrip(':')
            current_data = {'yarn_key': current_package}
            
        elif line.strip().startswith('version'):
            # Extract version
            version_match = re.search(r'version\s+"([^"]+)"', line)
            if version_match:
                current_data['version'] = version_match.group(1)
                
        elif line.strip().startswith('resolved'):
            # Extract resolved URL
            resolved_match = re.search(r'resolved\s+"([^"]+)"', line)
            if resolved_match:
                current_data['resolved'] = resolved_match.group(1)
    
    # Don't forget the last package
    if current_package and current_data:
        package_name = extract_package_name_from_yarn_key(current_package)
        if package_name:
            packages[package_name] = current_data
    
    return {'packages': packages, 'type': 'yarn'}

def extract_package_name_from_yarn_key(yarn_key: str) -> str:
    """Extract package name from yarn lockfile key."""
    # Handle cases like: "@apollo/client@^3.8.7", "classnames@^2.3.1", etc.
    # Split by comma for multiple version selectors
    first_selector = yarn_key.split(',')[0].strip()
    
    # Remove quotes if present
    first_selector = first_selector.strip('"')
    
    # Extract package name (everything before the last @)
    if '@' in first_selector:
        # Handle scoped packages like @apollo/client@^3.8.7
        if first_selector.startswith('@'):
            # For scoped packages, find the second @ (the version one)
            parts = first_selector.split('@')
            if len(parts) >= 3:  # @scope/package@version
                return f"@{parts[1]}"
            elif len(parts) == 2:  # @scope/package (no version)
                return first_selector
        else:
            # Regular package like classnames@^2.3.1
            return first_selector.split('@')[0]
    
    return first_selector

def load_pnpm_lockfile(lockfile_path: str) -> Dict[str, Any]:
    """Load and parse the pnpm lockfile."""
    if not Path(lockfile_path).exists():
        print(f"❌ Lockfile not found: {lockfile_path}")
        sys.exit(1)
    
    try:
        with open(lockfile_path, 'r') as f:
            return yaml.safe_load(f)
    except yaml.YAMLError as e:
        print(f"❌ Error parsing lockfile: {e}")
        sys.exit(1)

def load_lockfile(lockfile_path: str) -> Dict[str, Any]:
    """Load and parse a lockfile (auto-detect type)."""
    if not Path(lockfile_path).exists():
        print(f"❌ Lockfile not found: {lockfile_path}")
        sys.exit(1)
    
    lockfile_type = detect_lockfile_type(lockfile_path)
    
    if lockfile_type == "pnpm":
        return load_pnpm_lockfile(lockfile_path)
    elif lockfile_type == "yarn":
        return parse_yarn_lockfile(lockfile_path)
    else:
        print(f"❌ Unsupported lockfile format: {lockfile_path}")
        print("   Supported formats: pnpm-lock.yaml, yarn.lock")
        sys.exit(1)

def find_package_in_lockfile(lockfile_data: Dict[str, Any], package_name: str) -> List[Dict[str, Any]]:
    """Find a package in the lockfile data (supports both pnpm and yarn)."""
    results = []
    lockfile_type = lockfile_data.get('type', 'pnpm')
    
    if lockfile_type == 'pnpm':
        # PNPM lockfile format
        # Check importers section (direct dependencies)
        if 'importers' in lockfile_data:
            for importer, data in lockfile_data['importers'].items():
                # Check dependencies
                if 'dependencies' in data and package_name in data['dependencies']:
                    dep_info = data['dependencies'][package_name]
                    results.append({
                        'type': 'dependency',
                        'importer': importer,
                        'specifier': dep_info.get('specifier', ''),
                        'version': dep_info.get('version', '').split('(')[0]  # Remove peer deps info
                    })
                
                # Check devDependencies
                if 'devDependencies' in data and package_name in data['devDependencies']:
                    dep_info = data['devDependencies'][package_name]
                    results.append({
                        'type': 'devDependency',
                        'importer': importer,
                        'specifier': dep_info.get('specifier', ''),
                        'version': dep_info.get('version', '').split('(')[0]
                    })
        
        # Check packages section for transitive dependencies
        if 'packages' in lockfile_data:
            for package_key in lockfile_data['packages']:
                if f'/{package_name}@' in package_key or package_key.startswith(f'{package_name}@'):
                    results.append({
                        'type': 'transitive',
                        'package_key': package_key,
                        'data': lockfile_data['packages'][package_key]
                    })
    
    elif lockfile_type == 'yarn':
        # Yarn lockfile format
        if 'packages' in lockfile_data:
            if package_name in lockfile_data['packages']:
                package_data = lockfile_data['packages'][package_name]
                results.append({
                    'type': 'dependency',  # Yarn doesn't distinguish between dep/devDep in lockfile
                    'importer': '.',
                    'specifier': package_data.get('yarn_key', ''),
                    'version': package_data.get('version', '')
                })
    
    return results

def check_packages(packages_to_check: List[Dict[str, str]], lockfile_path: str = 'pnpm-lock.yaml') -> List[Dict[str, Any]]:
    """Check if potentially vulnerable packages exist in the lockfile."""
    lockfile_type = detect_lockfile_type(lockfile_path)
    print(f"🔍 Checking for potentially vulnerable packages in {lockfile_type} lockfile...\n")
    
    lockfile_data = load_lockfile(lockfile_path)
    results = []
    
    for package in packages_to_check:
        name = package['name']
        expected_version = package['version']
        
        print(f"Checking for: {name}@{expected_version}")
        
        found = find_package_in_lockfile(lockfile_data, name)
        
        if not found:
            print(f"✅ Safe: {name} not found in lockfile\n")
            results.append({
                'name': name,
                'expected_version': expected_version,
                'status': 'safe-not-found'
            })
        else:
            vulnerable_found = False
            for result in found:
                if result['type'] in ['dependency', 'devDependency']:
                    actual_version = result['version']
                    version_match = (expected_version == 'any' or 
                                   expected_version in actual_version or 
                                   actual_version == expected_version)
                    
                    if version_match:
                        print(f"🚨 SECURITY RISK: Found vulnerable package as {result['type']} in \"{result['importer']}\"")
                        print(f"   Specifier: {result['specifier']}")
                        print(f"   Vulnerable version: {actual_version}")
                        print(f"   ⚠️  This version has known security issues!\n")
                        vulnerable_found = True
                        
                        results.append({
                            'name': name,
                            'expected_version': expected_version,
                            'actual_version': actual_version,
                            'status': 'vulnerable',
                            'type': result['type'],
                            'importer': result['importer']
                        })
                    else:
                        print(f"✅ Safe: Found {result['type']} but different version")
                        print(f"   Found version: {actual_version} (not vulnerable)")
                        print(f"   Vulnerable version: {expected_version}\n")
                        
                        results.append({
                            'name': name,
                            'expected_version': expected_version,
                            'actual_version': actual_version,
                            'status': 'safe-different-version',
                            'type': result['type'],
                            'importer': result['importer']
                        })
                
                elif result['type'] == 'transitive':
                    # Check if transitive dependency version matches vulnerable version
                    package_key = result['package_key']
                    if f'@{expected_version}' in package_key or (expected_version == 'any'):
                        print(f"🚨 SECURITY RISK: Found as vulnerable transitive dependency: {package_key}")
                        print(f"   ⚠️  This version has known security issues!\n")
                        vulnerable_found = True
                        
                        results.append({
                            'name': name,
                            'expected_version': expected_version,
                            'status': 'vulnerable-transitive',
                            'package_key': package_key
                        })
                    else:
                        print(f"✅ Safe: Found as transitive dependency but different version: {package_key}\n")
                        results.append({
                            'name': name,
                            'expected_version': expected_version,
                            'status': 'safe-transitive',
                            'package_key': package_key
                        })
            
            if not vulnerable_found and not any(r['status'].startswith('vulnerable') for r in results if r['name'] == name):
                # Package exists but no vulnerable versions found
                print(f"✅ Safe: {name} found but no vulnerable versions detected\n")
    
    return results

def print_summary(results: List[Dict[str, Any]]):
    """Print a summary of the security check results."""
    print('\n📊 Security Check Summary:')
    print('=' * 50)
    
    vulnerable = [r for r in results if r['status'].startswith('vulnerable')]
    safe = [r for r in results if r['status'].startswith('safe')]
    
    print(f"Total packages checked: {len(results)}")
    print(f"🚨 Vulnerable packages found: {len(vulnerable)}")
    print(f"✅ Safe: {len(safe)}")
    
    if vulnerable:
        print('\n🚨 SECURITY RISKS DETECTED:')
        print('-' * 30)
        for pkg in vulnerable:
            if pkg['status'] == 'vulnerable':
                print(f"  {pkg['name']}@{pkg['actual_version']} ({pkg['type']} in {pkg['importer']})")
            elif pkg['status'] == 'vulnerable-transitive':
                print(f"  {pkg['package_key']} (transitive dependency)")
        
        print(f"\n⚠️  IMMEDIATE ACTION REQUIRED!")
        print(f"   Found {len(vulnerable)} vulnerable package(s) that need to be updated or removed.")
        
    else:
        print(f"\n🎉 No vulnerable packages detected!")
        print(f"   All checked packages are either not present or using safe versions.")

def main():
    """Main function."""
    # Default packages to check
    default_packages = [
        {'name': 'cbre-flow-common', 'version': '99.6.0'},
        {'name': '@asyncapi/diff', 'version': '0.5.2'},
        {'name': '@asyncapi/avro-schema-parser', 'version': '3.0.26'}
    ]
    
    parser = argparse.ArgumentParser(
        description='Security scanner: Check for vulnerable packages in lockfiles (pnpm-lock.yaml or yarn.lock)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Vulnerable package list file format:
  package-name    vulnerable-version
  @scope/package  1.2.3
  another-pkg     any

The script will flag packages as security risks if they match the specified versions.
Use 'any' to flag any version of a package.

Supported lockfile formats:
  - pnpm-lock.yaml (pnpm)
  - yarn.lock (Yarn Classic)

Examples:
  python check-packages.py --packages vulnerable-packages.txt
  python check-packages.py --lockfile ./other-project/pnpm-lock.yaml
  python check-packages.py --lockfile ./yarn-project/yarn.lock
        """
    )
    
    parser.add_argument(
        '-p', '--packages',
        help='Path to file containing vulnerable packages to check for'
    )
    parser.add_argument(
        '-l', '--lockfile',
        default='pnpm-lock.yaml',
        help='Path to lockfile: pnpm-lock.yaml or yarn.lock (default: ./pnpm-lock.yaml)'
    )
    
    args = parser.parse_args()
    
    # Determine which packages to check
    if args.packages:
        packages_to_check = parse_package_list(args.packages)
    else:
        packages_to_check = default_packages
        print("ℹ️  Using default vulnerable package list. Use --packages to specify a custom list.\n")
    
    try:
        results = check_packages(packages_to_check, args.lockfile)
        print_summary(results)
        
        # Exit with error code if any vulnerable packages found
        has_vulnerabilities = any(r['status'].startswith('vulnerable') for r in results)
        
        if has_vulnerabilities:
            sys.exit(1)  # Exit with error for CI/CD integration
            
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()