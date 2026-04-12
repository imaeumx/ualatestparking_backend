import base64
import hashlib

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from django.core.management.base import BaseCommand
from django.db import transaction

from registration.models import VehicleApplication
from registration.views import decrypt_des_text, encrypt_des_text


def derive_des_key_bytes(raw_key):
    normalized = (raw_key or '').strip()
    if not normalized:
        return b'UA-KEY-1'

    try:
        key_bytes = base64.b64decode(normalized, validate=True)
    except Exception:
        key_bytes = normalized.encode('utf-8', errors='ignore')

    if len(key_bytes) < 8:
        key_bytes = key_bytes.ljust(8, b'0')
    return key_bytes[:8]


def decrypt_des_cbc_with_custom_key(cipher_text, raw_key):
    normalized = '' if cipher_text is None else str(cipher_text)
    if not normalized:
        return ''

    try:
        payload = base64.b64decode(normalized)
        if len(payload) <= DES.block_size:
            return normalized

        iv = payload[:DES.block_size]
        encrypted = payload[DES.block_size:]
        cipher = DES.new(derive_des_key_bytes(raw_key), DES.MODE_CBC, iv=iv)
        decrypted = unpad(cipher.decrypt(encrypted), DES.block_size)
        return decrypted.decode('utf-8')
    except Exception:
        return normalized


def decrypt_cryptojs_salted_with_passphrase(cipher_text, passphrase):
    normalized = '' if cipher_text is None else str(cipher_text)
    if not normalized:
        return ''

    try:
        payload = base64.b64decode(normalized)
        if not payload.startswith(b'Salted__') or len(payload) <= 16:
            return normalized

        salt = payload[8:16]
        encrypted = payload[16:]
        passphrase_bytes = (passphrase or '').encode('utf-8')

        derived = b''
        block = b''
        while len(derived) < 16:
            block = hashlib.md5(block + passphrase_bytes + salt).digest()
            derived += block

        key = derived[:8]
        iv = derived[8:16]
        cipher = DES.new(key, DES.MODE_CBC, iv=iv)
        decrypted = unpad(cipher.decrypt(encrypted), DES.block_size)
        return decrypted.decode('utf-8')
    except Exception:
        return normalized


class Command(BaseCommand):
    help = (
        'Normalize VehicleApplication owner_name/plate_number encryption so all decrypt with the current '
        'DES_SECRET_KEY. Tries current key decrypt first, then legacy key fallback.'
    )

    def add_arguments(self, parser):
        parser.add_argument(
            '--legacy-key',
            type=str,
            default='UA-SECRET-KEY',
            help='Legacy passphrase/key to try for old rows (default: UA-SECRET-KEY).',
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Preview updates without writing changes.',
        )

    def handle(self, *args, **options):
        legacy_key = (options.get('legacy_key') or '').strip()
        dry_run = bool(options.get('dry_run'))

        total_rows = VehicleApplication.objects.count()
        updated_rows = 0
        skipped_rows = 0
        unresolved_rows = []

        self.stdout.write(self.style.WARNING(f'Checking {total_rows} vehicle application row(s)...'))

        qs = VehicleApplication.objects.all().order_by('id')

        with transaction.atomic():
            for row in qs:
                owner_raw = row.owner_name or ''
                plate_raw = row.plate_number or ''

                owner_plain = decrypt_des_text(owner_raw)
                plate_plain = decrypt_des_text(plate_raw)

                owner_resolved = owner_plain != owner_raw or owner_raw == ''
                plate_resolved = plate_plain != plate_raw or plate_raw == ''

                # Fallback 1: legacy DES-CBC with legacy key.
                if not owner_resolved:
                    owner_candidate = decrypt_des_cbc_with_custom_key(owner_raw, legacy_key)
                    if owner_candidate != owner_raw:
                        owner_plain = owner_candidate
                        owner_resolved = True

                if not plate_resolved:
                    plate_candidate = decrypt_des_cbc_with_custom_key(plate_raw, legacy_key)
                    if plate_candidate != plate_raw:
                        plate_plain = plate_candidate
                        plate_resolved = True

                # Fallback 2: legacy CryptoJS/OpenSSL salted passphrase mode.
                if not owner_resolved:
                    owner_candidate = decrypt_cryptojs_salted_with_passphrase(owner_raw, legacy_key)
                    if owner_candidate != owner_raw:
                        owner_plain = owner_candidate
                        owner_resolved = True

                if not plate_resolved:
                    plate_candidate = decrypt_cryptojs_salted_with_passphrase(plate_raw, legacy_key)
                    if plate_candidate != plate_raw:
                        plate_plain = plate_candidate
                        plate_resolved = True

                if not owner_resolved or not plate_resolved:
                    skipped_rows += 1
                    unresolved_rows.append((row.id, row.sticker_id or '---'))
                    continue

                next_owner = encrypt_des_text(owner_plain)
                next_plate = encrypt_des_text(plate_plain)

                # Always rewrite resolved rows so everything uses current key format.
                if not dry_run:
                    row.owner_name = next_owner
                    row.plate_number = next_plate
                    row.save(update_fields=['owner_name', 'plate_number'])

                updated_rows += 1

            if dry_run:
                transaction.set_rollback(True)

        mode_label = 'DRY RUN' if dry_run else 'APPLIED'
        self.stdout.write(self.style.SUCCESS(f'{mode_label}: updated {updated_rows} row(s), unresolved {skipped_rows} row(s).'))

        if unresolved_rows:
            preview = ', '.join([f'id={row_id}/sticker={sticker}' for row_id, sticker in unresolved_rows[:20]])
            self.stdout.write(self.style.WARNING(f'Unresolved sample: {preview}'))
