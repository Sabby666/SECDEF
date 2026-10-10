import sys
import json
import sqlite3

def main():
    try:
        raw = sys.stdin.read()
        if not raw:
            print("[]")
            return
        payload = json.loads(raw)
        sql = payload["sql"]
        params = payload.get("params", [])
        conn = sqlite3.connect("apps/control-plane/asm_dev.db")
        c = conn.cursor()
        c.execute(sql, params)
        rows = c.fetchall()
        conn.close()
        print(json.dumps(rows))
    except Exception as e:
        sys.stderr.write(f"Error: {e}\n")
        print("[]")

if __name__ == "__main__":
    main()
