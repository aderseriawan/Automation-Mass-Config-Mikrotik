#!/usr/bin/env sh
set -e

# hanya collectstatic, TANPA migrate
python manage.py collectstatic --noinput --clear

exec "$@"
