"""
Fix encoding issues in Python scripts by removing emojis
Run this if you get UnicodeEncodeError on Windows
"""
import re
from pathlib import Path

def remove_emojis(text):
    """Remove emoji characters from text"""
    # Pattern to match emojis
    emoji_pattern = re.compile(
        "["
        "\U0001F600-\U0001F64F"  # emoticons
        "\U0001F300-\U0001F5FF"  # symbols & pictographs
        "\U0001F680-\U0001F6FF"  # transport & map symbols
        "\U0001F1E0-\U0001F1FF"  # flags (iOS)
        "\U00002702-\U000027B0"
        "\U000024C2-\U0001F251"
        "]+",
        flags=re.UNICODE
    )
    return emoji_pattern.sub('', text)

def fix_file(filepath):
    """Fix encoding in a single file"""
    try:
        # Read file with UTF-8 encoding
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Remove emojis
        fixed_content = remove_emojis(content)
        
        # Write back with UTF-8 encoding
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(fixed_content)
        
        print(f"✓ Fixed: {filepath}")
        return True
    except Exception as e:
        print(f"✗ Error fixing {filepath}: {e}")
        return False

def main():
    """Fix all Python ML scripts"""
    print("=" * 60)
    print("Fixing Encoding Issues in ML Scripts")
    print("=" * 60)
    
    scripts = ['b_kfinal.py', 'shap_explaienr.py', 'nn.py']
    
    fixed_count = 0
    for script in scripts:
        if Path(script).exists():
            if fix_file(script):
                fixed_count += 1
        else:
            print(f"⚠ File not found: {script}")
    
    print("\n" + "=" * 60)
    print(f"Fixed {fixed_count}/{len(scripts)} files")
    print("=" * 60)
    
    if fixed_count > 0:
        print("\n✓ Encoding issues fixed!")
        print("  You can now run the backend without encoding errors.")
    else:
        print("\n⚠ No files were fixed. Check that the scripts exist.")

if __name__ == "__main__":
    main()