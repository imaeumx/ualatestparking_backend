from django.db import migrations, models
from django.conf import settings
import base64
import secrets

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad


def get_des_key_bytes():
    # Use the same env key as runtime code so migrated data can still be
    # decrypted by application endpoints after deployment.
    raw_key = (getattr(settings, 'DES_SECRET_KEY', '') or '').strip()
    if not raw_key:
        return b'UA-KEY-1'

    try:
        key_bytes = base64.b64decode(raw_key, validate=True)
    except Exception:
        key_bytes = raw_key.encode('utf-8', errors='ignore')

    if len(key_bytes) < 8:
        key_bytes = key_bytes.ljust(8, b'0')
    return key_bytes[:8]


def encrypt_des_text(value):
    # Keep migration behavior aligned with production helper in views.py.
    normalized_value = '' if value is None else str(value)
    if normalized_value == '':
        return ''

    iv = secrets.token_bytes(8)
    cipher = DES.new(get_des_key_bytes(), DES.MODE_CBC, iv=iv)
    encrypted = cipher.encrypt(pad(normalized_value.encode('utf-8'), DES.block_size))
    return base64.b64encode(iv + encrypted).decode('ascii')


def decrypt_des_text(value):
    # Gracefully handles legacy plain text values by returning as-is on failure.
    normalized_value = '' if value is None else str(value)
    if normalized_value == '':
        return ''

    try:
        payload = base64.b64decode(normalized_value)
        if len(payload) <= DES.block_size:
            return normalized_value

        iv = payload[:DES.block_size]
        encrypted = payload[DES.block_size:]
        cipher = DES.new(get_des_key_bytes(), DES.MODE_CBC, iv=iv)
        decrypted = unpad(cipher.decrypt(encrypted), DES.block_size)
        return decrypted.decode('utf-8')
    except Exception:
        return normalized_value


def encrypt_existing_userregistration_fields(apps, schema_editor):
    UserRegistration = apps.get_model('registration', 'UserRegistration')

    for user in UserRegistration.objects.all():
        # Decrypt-first-then-encrypt prevents double-encryption if any rows were
        # already encrypted before this migration is applied.
        user.first_name = encrypt_des_text(decrypt_des_text(user.first_name))
        user.last_name = encrypt_des_text(decrypt_des_text(user.last_name))
        user.email = encrypt_des_text(decrypt_des_text(user.email))
        user.password = encrypt_des_text(decrypt_des_text(user.password))
        user.save(update_fields=['first_name', 'last_name', 'email', 'password'])


def reverse_encrypt_existing_userregistration_fields(apps, schema_editor):
    UserRegistration = apps.get_model('registration', 'UserRegistration')

    for user in UserRegistration.objects.all():
        # Rollback path restores plain values for all transformed fields.
        user.first_name = decrypt_des_text(user.first_name)
        user.last_name = decrypt_des_text(user.last_name)
        user.email = decrypt_des_text(user.email)
        user.password = decrypt_des_text(user.password)
        user.save(update_fields=['first_name', 'last_name', 'email', 'password'])


class Migration(migrations.Migration):

    dependencies = [
        ('registration', '0009_vehicleapplication_admin_notes'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userregistration',
            name='first_name',
            field=models.TextField(),
        ),
        migrations.AlterField(
            model_name='userregistration',
            name='last_name',
            field=models.TextField(),
        ),
        migrations.AlterField(
            model_name='userregistration',
            name='email',
            field=models.TextField(),
        ),
        migrations.RunPython(
            encrypt_existing_userregistration_fields,
            reverse_encrypt_existing_userregistration_fields,
        ),
    ]