import sys

with open("app.py", "r", encoding="utf-8") as f:
    text = f.read()

# Remove problematic invisible characters
cleaned = text.replace('\u200e', '').replace('\u200f', '')

with open("app_clean.py", "w", encoding="utf-8") as f:
    f.write(cleaned)

print("✅ Non-printable characters removed. Saved as app_clean.py")
