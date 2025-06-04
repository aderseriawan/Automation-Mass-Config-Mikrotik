#!/usr/bin/env sh
set -e

python - <<'PY'
import sys, django, os
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "NA_Project.settings")
django.setup(set_prefix=False)
from django.conf import settings
if getattr(settings, "STATIC_ROOT", None):
    import subprocess, shlex
    cmd = "python manage.py collectstatic --noinput --clear"
    print("Collecting static files…")
    subprocess.run(shlex.split(cmd), check=True)
else:
    print("STATIC_ROOT not set – skipping collectstatic")
PY

exec "$@"