from app import app

print("📋 Defined Routes:")
for rule in app.url_map.iter_rules():
    methods = ','.join(rule.methods)
    print(f"  {rule.rule} -> {rule.endpoint} [{methods}]")

print(f"\\n🔧 Total routes: {len(list(app.url_map.iter_rules()))}")
