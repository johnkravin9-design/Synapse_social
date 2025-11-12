import os
import re

def extract_content(html_file):
    """Extract content between body tags"""
    with open(html_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Extract title
    title_match = re.search(r'<title>(.*?)</title>', content)
    title = title_match.group(1) if title_match else 'Synapse'
    
    # Extract body content (everything between <body> and </body>)
    body_match = re.search(r'<body[^>]*>(.*?)</body>', content, re.DOTALL)
    if not body_match:
        return None, None
    
    body_content = body_match.group(1)
    
    # Remove existing nav elements
    body_content = re.sub(r'<nav.*?</nav>', '', body_content, flags=re.DOTALL)
    
    # Extract just the main content area
    main_match = re.search(r'<div class="max-w.*?$', body_content, re.DOTALL)
    if main_match:
        body_content = '<div class="' + main_match.group(0)
    
    return title, body_content

def create_extends_template(filename, title, content):
    """Create new template that extends base.html"""
    template = f'''{{%extends "base.html" %}}

{{%block title %}}{title}{{%endblock %}}

{{%block content %}}
{content}
{{%endblock %}}
'''
    
    with open(f'templates/{filename}', 'w', encoding='utf-8') as f:
        f.write(template)

# List of templates to convert (excluding base.html and those already using Jinja)
templates_to_convert = [
    'feed.html',
    'explore.html', 
    'reels.html',
    'messages.html',
    'notifications.html',
    'profile.html',
    'settings.html',
    'create.html',
    'saved.html'
]

print("🔄 Converting templates to use base.html navigation...")

for template in templates_to_convert:
    filepath = f'templates/{template}'
    if os.path.exists(filepath):
        title, content = extract_content(filepath)
        if title and content:
            create_extends_template(template, title, content)
            print(f"✅ Converted {template}")
        else:
            print(f"⚠️  Skipped {template} (couldn't extract content)")
    else:
        print(f"❌ {template} not found")

print("\n✨ All templates updated!")
