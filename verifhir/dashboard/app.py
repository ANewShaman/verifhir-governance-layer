import sys, os, time

print("BOOT: app.py loaded", flush=True)

print("BOOT: python", sys.version, flush=True)
print("BOOT: cwd", os.getcwd(), flush=True)
print("BOOT: files", os.listdir("."), flush=True)

if os.environ.get("AZURE_HEALTH_CHECK") == "1":
    print("BOOT: HEALTH CHECK OK", flush=True)
