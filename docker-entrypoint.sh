#!/usr/bin/env sh
set -e

# database & static
python manage.py migrate --noinput
python manage.py collectstatic --noinput --clear

# buat superuser kalau belum ada (hindari error env kosong)
if [ -n "$DJANGO_SUPERUSER_USERNAME" ] && [ -n "$DJANGO_SUPERUSER_EMAIL" ] && [ -n "$DJANGO_SUPERUSER_PASSWORD" ]; then
  python manage.py shell <<PY
from django.contrib.auth import get_user_model
User = get_user_model()
u = "$DJANGO_SUPERUSER_USERNAME"
if not User.objects.filter(username=u).exists():
    User.objects.create_superuser(u, "$DJANGO_SUPERUSER_EMAIL", "$DJANGO_SUPERUSER_PASSWORD")
PY
fi

exec "$@"
