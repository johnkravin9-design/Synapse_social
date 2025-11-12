import re

# Read the file
with open('app.py', 'r') as f:
    content = f.read()

# Remove duplicate login routes
# Keep only one login route definition
login_pattern = r'@app\.route\(\'/login\'\).*?def login_page.*?(?=@app\.route|def |\Z)'
matches = list(re.finditer(login_pattern, content, re.DOTALL))

if len(matches) > 1:
    # Keep only the first occurrence
    first_match = matches[0]
    for match in matches[1:]:
        content = content.replace(match.group(0), '')
    print("Removed duplicate login routes")

# Write back
with open('app.py', 'w') as f:
    f.write(content)

print("Fixed duplicate routes")
