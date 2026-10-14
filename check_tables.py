import sqlite3
conn = sqlite3.connect(r"D:\develop\tiga-case\backend\data\tiga.db")
cur = conn.cursor()
cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '%mcp%'")
print("MCP tables:", cur.fetchall())
cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
all_tables = cur.fetchall()
print(f"Total tables: {len(all_tables)}")
conn.close()
