#!/bin/bash
pip install -r requirements.txt
python manage.py migrate
python manage.py cleanup_stale_reservations --older-than-hours 24
python manage.py collectstatic --noinput