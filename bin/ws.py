#!/usr/bin/env python3

import argparse
import glob
import os
import sys

def detect_trailing_whitespace(file_path):
    """Detect lines with trailing whitespace in a file."""
    trailing_lines = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                if line.rstrip('\n\r') != line.rstrip():
                    trailing_lines.append((line_num, line.rstrip('\n\r')))
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return []
    return trailing_lines

def remove_trailing_whitespace(file_path):
    """Remove trailing whitespace from a file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        # Remove trailing whitespace from each line but preserve line endings
        cleaned_lines = []
        for line in lines:
            if line.endswith('\n'):
                cleaned_lines.append(line.rstrip() + '\n')
            else:
                cleaned_lines.append(line.rstrip())
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.writelines(cleaned_lines)
        return True
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description='Detect and optionally remove trailing whitespace from Rust files')
    parser.add_argument('-d', '--delete', action='store_true', 
                       help='Remove trailing whitespace instead of just detecting it')
    parser.add_argument('paths', nargs='*', default=['src/scan/*.rs'],
                       help='File paths or patterns to process (default: src/scan/*.rs)')
    
    args = parser.parse_args()
    
    # Collect all files to process
    all_files = []
    for pattern in args.paths:
        if '*' in pattern or '?' in pattern:
            all_files.extend(glob.glob(pattern))
        elif os.path.isfile(pattern):
            all_files.append(pattern)
        else:
            print(f"Warning: {pattern} is not a valid file or pattern")
    
    if not all_files:
        print("No files found to process")
        sys.exit(1)
    
    print(f"Processing {len(all_files)} files...")
    
    if args.delete:
        # Remove trailing whitespace
        success_count = 0
        for file_path in all_files:
            print(f"Cleaning: {file_path}")
            if remove_trailing_whitespace(file_path):
                success_count += 1
        
        print(f"\n✅ Successfully cleaned {success_count}/{len(all_files)} files")
        
        # Verify removal
        print("\nVerifying removal...")
        total_issues = 0
        for file_path in all_files:
            issues = detect_trailing_whitespace(file_path)
            if issues:
                total_issues += len(issues)
                print(f"  ❌ {file_path}: Still has {len(issues)} lines with trailing whitespace")
        
        if total_issues == 0:
            print("  ✅ All trailing whitespace has been removed!")
        else:
            print(f"  ❌ {total_issues} lines still have trailing whitespace")
    else:
        # Just detect trailing whitespace
        total_issues = 0
        files_with_issues = 0
        
        for file_path in all_files:
            issues = detect_trailing_whitespace(file_path)
            if issues:
                files_with_issues += 1
                total_issues += len(issues)
                print(f"\n📄 {file_path}:")
                for line_num, line_content in issues[:5]:  # Show first 5 issues per file
                    print(f"  Line {line_num}: {repr(line_content)}")
                if len(issues) > 5:
                    print(f"  ... and {len(issues) - 5} more lines")
        
        if total_issues == 0:
            print("✅ No trailing whitespace found!")
        else:
            print(f"\n📊 Summary: {total_issues} lines with trailing whitespace in {files_with_issues} files")
            print("Run with -d flag to remove trailing whitespace")

if __name__ == "__main__":
    main() 