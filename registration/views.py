import json
import base64
import secrets
import re
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from datetime import date
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from .models import UserRegistration, VehicleApplication, ParkingReservation
from django.utils import timezone
from django.core import signing
from django.core.signing import BadSignature, SignatureExpired
from django.db import IntegrityError


PERSONNEL_ROLES = {'root_admin', 'admin', 'guard'}
ADMIN_ROLES = {'root_admin', 'admin'}
AUTH_TOKEN_SALT = 'ua-parking-auth'
AUTH_TOKEN_MAX_AGE_SECONDS = 60 * 60 * 12


def normalize_username(value):
    return (value or '').strip()


def get_user_by_username(username):
    normalized_username = normalize_username(username)
    if not normalized_username:
        raise UserRegistration.DoesNotExist()
    return UserRegistration.objects.get(username__iexact=normalized_username)


def generate_next_sticker_id():
    """
    Generate the next unique sticker ID in UA-XXX format.
    Uses highest numeric suffix + 1 to avoid duplicates after status changes.
    """
    max_num = 0
    for sid in VehicleApplication.objects.exclude(sticker_id__isnull=True).exclude(sticker_id='').values_list('sticker_id', flat=True):
        if isinstance(sid, str) and sid.startswith('UA-'):
            num_part = sid[3:]
            if num_part.isdigit():
                max_num = max(max_num, int(num_part))
    return f"UA-{str(max_num + 1).zfill(3)}"


def get_val(data, key_camel, key_snake):
    """
    Helper function to handle both camelCase (React) and snake_case (Django) keys.
    Returns the value from either key format to ensure compatibility.
    """
    return data.get(key_camel) or data.get(key_snake)


def is_valid_password(password):
    """
    Password must be at least 8 characters and include one uppercase letter and one digit.
    """
    if not isinstance(password, str):
        return False
    return bool(re.match(r'^(?=.*[A-Z])(?=.*\d).{8,}$', password))


def get_current_semester_range(today=None):
    """
    Return current semester start/end dates.
    1st sem: Aug-Dec, 2nd sem: Jan-May, 3rd/summer sem: Jun-Jul.
    """
    today = today or date.today()
    year = today.year
    month = today.month

    if 8 <= month <= 12:
        return date(year, 8, 1), date(year, 12, 31)
    if 1 <= month <= 5:
        return date(year, 1, 1), date(year, 5, 31)
    return date(year, 6, 1), date(year, 7, 31)


def is_sticker_valid_for_current_semester(sticker_obj, today=None):
    """Check if sticker expiration is within the current semester window."""
    if not sticker_obj or not sticker_obj.expiration_date:
        return False

    semester_start, semester_end = get_current_semester_range(today)
    return semester_start <= sticker_obj.expiration_date <= semester_end


def issue_auth_token(username, role):
    """Issue signed role-bound auth token."""
    payload = {
        'username': username,
        'role': (role or '').strip().lower()
    }
    return signing.dumps(payload, salt=AUTH_TOKEN_SALT)


def get_token_payload(auth_token):
    """Validate and decode signed auth token."""
    if not auth_token:
        return None

    try:
        payload = signing.loads(auth_token, salt=AUTH_TOKEN_SALT, max_age=AUTH_TOKEN_MAX_AGE_SECONDS)
        if not isinstance(payload, dict):
            return None
        return payload
    except (BadSignature, SignatureExpired):
        return None


def authorize_request(request, data, allowed_roles):
    """Authorize request via signed token from JSON body or query params."""
    body_data = data or {}
    auth_token = body_data.get('auth_token') or request.GET.get('auth_token')
    payload = get_token_payload(auth_token)
    if not payload:
        return None

    role = (payload.get('role') or '').strip().lower()
    if role not in allowed_roles:
        return None
    return payload


def get_des_key_bytes():
    """Return an 8-byte DES key derived from settings.DES_SECRET_KEY."""
    # The shared key is stored as base64 in env (.env). If decoding fails,
    # we treat it as raw text and normalize to 8 bytes for DES compatibility.
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


def encrypt_des_text(plain_text):
    """Encrypt plain text with DES-CBC and a random IV."""
    normalized_value = '' if plain_text is None else str(plain_text)
    if normalized_value == '':
        return ''

    # CBC requires a random IV per encryption call so the same input does not
    # produce the same ciphertext repeatedly.
    iv = secrets.token_bytes(8)
    cipher = DES.new(get_des_key_bytes(), DES.MODE_CBC, iv=iv)
    encrypted = cipher.encrypt(pad(normalized_value.encode('utf-8'), DES.block_size))
    # We prepend IV to ciphertext so decryption can reconstruct the same state.
    return base64.b64encode(iv + encrypted).decode('ascii')


def decrypt_des_text(cipher_text):
    """Decrypt DES-CBC payloads; fall back to the original value for legacy plain text."""
    normalized_value = '' if cipher_text is None else str(cipher_text)
    if normalized_value == '':
        return ''

    try:
        payload = base64.b64decode(normalized_value)
        if len(payload) <= DES.block_size:
            return normalized_value

        # Split combined payload: [8-byte IV][ciphertext bytes...]
        iv = payload[:DES.block_size]
        encrypted = payload[DES.block_size:]
        cipher = DES.new(get_des_key_bytes(), DES.MODE_CBC, iv=iv)
        decrypted = unpad(cipher.decrypt(encrypted), DES.block_size)
        return decrypted.decode('utf-8')
    except Exception:
        # Legacy compatibility: old rows may still contain plain text values.
        return normalized_value


def passwords_match(stored_password, incoming_password):
    """Compare a stored DES-encrypted password against a candidate password."""
    if incoming_password is None:
        return False

    stored_value = '' if stored_password is None else str(stored_password)
    incoming_value = str(incoming_password)
    # Backward compatibility for rows created before encryption rollout.
    if stored_value == incoming_value:
        return True

    try:
        return decrypt_des_text(stored_value) == incoming_value
    except Exception:
        return False


@csrf_exempt
def get_des_key(request):
    if request.method != 'GET':
        return JsonResponse({'status': 'error', 'message': 'Method not allowed'}, status=405)

    return JsonResponse({
        'status': 'success',
        'des_key': getattr(settings, 'DES_SECRET_KEY', '')
    })


@csrf_exempt
def login_user(request):
    """
    Authenticate user login.
    Accepts username and password, returns user data on success.
    Includes emergency admin access for demo purposes.
    """
    if request.method != 'POST':
        return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=405)

    try:
        data = json.loads(request.body)
        username = normalize_username(data.get('username'))
        incoming_pass = data.get('password')

        if not username or not incoming_pass:
            return JsonResponse({'status': 'error', 'message': 'Username and password are required.'}, status=400)

        if username.lower() == 'rootadmin' and incoming_pass == 'rootadmin123':
            root_role = 'root_admin'
            return JsonResponse({
                'status': 'success',
                'user': {
                    'username': 'rootadmin',
                    'first_name': 'Root',
                    'last_name': 'Admin',
                    'email': '',
                    'role': root_role,
                    'identifier': 'System Root',
                    'auth_token': issue_auth_token('rootadmin', root_role)
                }
            })

        try:
            user = get_user_by_username(username)
        except UserRegistration.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'User not found'}, status=404)

        if passwords_match(user.password, incoming_pass):
            user_role = (getattr(user, 'role', '') or '').strip().lower()
            return JsonResponse({
                'status': 'success',
                'user': {
                    'username': user.username,
                    'first_name': decrypt_des_text(getattr(user, 'firstName', getattr(user, 'first_name', ''))),
                    'last_name': decrypt_des_text(getattr(user, 'lastName', getattr(user, 'last_name', ''))),
                    'email': decrypt_des_text(getattr(user, 'email', '')),
                    'role': user_role,
                    'identifier': user.identifier,
                    'auth_token': issue_auth_token(user.username, user_role)
                }
            })

        return JsonResponse({'status': 'error', 'message': 'Invalid Credentials'}, status=401)

    except json.JSONDecodeError:
        return JsonResponse({'status': 'error', 'message': 'Invalid JSON'}, status=400)


@csrf_exempt
def create_personnel_account(request):
    """
    Create a new personnel account (admin or guard).
    Only root admin can perform this action.
    """
    if request.method != 'POST':
        return JsonResponse({'status': 'error', 'message': 'Method not allowed'}, status=405)

    try:
        data = json.loads(request.body)
        auth_payload = authorize_request(request, data, {'root_admin'})
        if not auth_payload:
            return JsonResponse({'status': 'error', 'message': 'Unauthorized action.'}, status=403)

        role = (data.get('role') or '').strip().lower()
        username = (data.get('username') or '').strip()
        password = (data.get('password') or '').strip()
        first_name = (data.get('first_name') or '').strip()
        last_name = (data.get('last_name') or '').strip()
        email = (data.get('email') or '').strip()

        if role not in ('admin', 'guard'):
            return JsonResponse({'status': 'error', 'message': 'Role must be admin or guard.'}, status=400)

        if not all([username, password, first_name, last_name, email]):
            return JsonResponse({'status': 'error', 'message': 'Missing required fields.'}, status=400)

        if not is_valid_password(password):
            return JsonResponse({
                'status': 'error',
                'message': 'Password must be at least 8 characters long and include at least one uppercase letter and one number.'
            }, status=400)

        if UserRegistration.objects.filter(username__iexact=username).exists():
            return JsonResponse({'status': 'error', 'message': 'Username already exists.'}, status=400)

        UserRegistration.objects.create(
            first_name=encrypt_des_text(first_name),
            last_name=encrypt_des_text(last_name),
            email=encrypt_des_text(email),
            username=username,
            password=encrypt_des_text(password),
            identifier='Personnel Account',
            role=role
        )

        return JsonResponse({'status': 'success', 'message': f'{role.title()} account created successfully.'})
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


@csrf_exempt
def update_profile(request):
    """
    Update user profile information (identifier and/or password).
    Requires username to identify the user.
    """
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            target_username = normalize_username(data.get('username'))
            auth_token = data.get('auth_token')
            token_payload = get_token_payload(auth_token)
            if not token_payload:
                return JsonResponse({'status': 'error', 'message': 'Unauthorized action.'}, status=403)

            requester_username = normalize_username(token_payload.get('username'))
            requester_role = (token_payload.get('role') or '').strip().lower()
            can_update = requester_username.lower() == target_username.lower() or requester_role in PERSONNEL_ROLES
            if not can_update:
                return JsonResponse({'status': 'error', 'message': 'Unauthorized action.'}, status=403)

            user = get_user_by_username(target_username)

            user.identifier = data.get('identifier')

            incoming_new_password = data.get('password')
            incoming_old_password = data.get('oldPassword') or data.get('old_password')

            if incoming_new_password:
                if not incoming_old_password:
                    return JsonResponse({'status': 'error', 'message': 'Old password is required.'}, status=400)

                if not is_valid_password(incoming_new_password):
                    return JsonResponse({
                        'status': 'error',
                        'message': 'New password must be at least 8 characters long and include at least one uppercase letter and one number.'
                    }, status=400)

                if not passwords_match(user.password, incoming_old_password):
                    return JsonResponse({'status': 'error', 'message': 'Old password is incorrect.'}, status=400)

                user.password = encrypt_des_text(incoming_new_password)

            user.save()
            return JsonResponse({'status': 'success'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


@csrf_exempt
def register_user(request):
    """
    Register a new user account.
    Creates UserRegistration record with provided information.
    """
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            incoming_password = data.get('password')

            if not is_valid_password(incoming_password):
                return JsonResponse({
                    'status': 'error',
                    'message': 'Password must be at least 8 characters long and include at least one uppercase letter and one number.'
                }, status=400)

            UserRegistration.objects.create(
                first_name=encrypt_des_text(get_val(data, 'firstName', 'first_name')),
                last_name=encrypt_des_text(get_val(data, 'lastName', 'last_name')),
                email=encrypt_des_text(data.get('email')),
                username=data.get('username'),
                password=encrypt_des_text(incoming_password),
                identifier=data.get('identifier'),
                role=data.get('role')
            )
            return JsonResponse({'status': 'success'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=400)
    return JsonResponse({'status': 'error'}, status=405)


@csrf_exempt
def submit_vehicle(request):
    """
    Submit a new vehicle parking application.
    Creates VehicleApplication record linked to the user.
    """
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            username = normalize_username(data.get('username'))
            auth_token = data.get('auth_token')
            token_payload = get_token_payload(auth_token)
            if not token_payload:
                return JsonResponse({'status': 'error', 'message': 'Unauthorized action.'}, status=403)

            requester_username = normalize_username(token_payload.get('username'))
            requester_role = (token_payload.get('role') or '').strip().lower()
            can_submit_for_user = requester_username.lower() == username.lower() or requester_role in PERSONNEL_ROLES
            if not can_submit_for_user:
                return JsonResponse({'status': 'error', 'message': 'Unauthorized action.'}, status=403)

            payment_method = get_val(data, 'paymentMethod', 'payment_method')
            payment_reference = get_val(data, 'paymentReference', 'payment_reference')
            plate_number = get_val(data, 'plateNumber', 'plate_number')

            if not payment_method or not payment_reference:
                return JsonResponse({'status': 'error', 'message': 'Payment method and payment reference are required.'}, status=400)

            if not plate_number:
                return JsonResponse({'status': 'error', 'message': 'Plate number is required.'}, status=400)

            if VehicleApplication.objects.filter(plate_number=plate_number).exists():
                return JsonResponse({
                    'status': 'error',
                    'message': 'Plate number already exists. Please use a unique plate number.'
                }, status=400)

            user_profile = get_user_by_username(username)

            VehicleApplication.objects.create(
                applicant_username=username,
                owner_name=get_val(data, 'ownerName', 'owner_name'),
                plate_number=plate_number,
                vehicle_type=get_val(data, 'vehicleType', 'vehicle_type'),
                payment_method=payment_method,
                payment_reference=payment_reference,
                status="Pending",
                is_seen=True,
                role=getattr(user_profile, 'role', 'User'),
                identifier=getattr(user_profile, 'identifier', 'N/A')
            )
            return JsonResponse({'status': 'success'})
        except UserRegistration.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'User profile not found'}, status=404)
        except IntegrityError:
            return JsonResponse({
                'status': 'error',
                'message': 'Plate number already exists. Please use a unique plate number.'
            }, status=400)
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


@csrf_exempt
def update_status(request):
    """
    Update application status (Approve/Reject/Reset).
    When approving, generates sticker ID and sets expiration to semester end.
    """
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            auth_payload = authorize_request(request, data, ADMIN_ROLES)
            if not auth_payload:
                return JsonResponse({'status': 'error', 'message': 'Unauthorized action.'}, status=403)

            v = VehicleApplication.objects.get(id=data.get('id'))
            v.status = data.get('status')
            v.admin_notes = (data.get('admin_notes') or '').strip()
            v.is_seen = False

            # Ensure approved records always have a sticker and semester expiration.
            if v.status == "Approved":
                if not v.sticker_id:
                    v.sticker_id = generate_next_sticker_id()

                if not v.expiration_date:
                    _, semester_end = get_current_semester_range(date.today())
                    v.expiration_date = semester_end

            try:
                v.save()
            except IntegrityError:
                return JsonResponse({'status': 'error', 'message': 'Update failed.'}, status=400)
            return JsonResponse({'status': 'success'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


@csrf_exempt
def mark_notifications_read(request):
    """
    Mark all notifications as read for a user.
    Updates is_seen flag for all user's applications.
    """
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            user_nm = (data.get('username') or '').strip()
            auth_token = data.get('auth_token')
            token_payload = get_token_payload(auth_token)
            if not token_payload:
                return JsonResponse({'status': 'error', 'message': 'Unauthorized action.'}, status=403)

            requester_username = (token_payload.get('username') or '').strip()
            requester_role = (token_payload.get('role') or '').strip().lower()
            can_mark = requester_username == user_nm or requester_role in PERSONNEL_ROLES
            if not can_mark:
                return JsonResponse({'status': 'error', 'message': 'Unauthorized action.'}, status=403)

            VehicleApplication.objects.filter(applicant_username=user_nm).update(is_seen=True)
            return JsonResponse({'status': 'success'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


def get_admin_records(request):
    """
    Get all vehicle applications for admin dashboard.
    Returns all applications with full details.
    """
    try:
        auth_payload = authorize_request(request, None, PERSONNEL_ROLES)
        if not auth_payload:
            return JsonResponse({'status': 'error', 'message': 'Unauthorized action.'}, status=403)

        vehicles = list(VehicleApplication.objects.all().values())
        return JsonResponse(vehicles, safe=False)
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


def get_user_records(request):
    """
    Get vehicle applications for a specific user.
    Used by user dashboard to show their application history.
    """
    try:
        user_nm = request.GET.get('username')
        auth_token = request.GET.get('auth_token')
        token_payload = get_token_payload(auth_token)

        if not user_nm or not token_payload:
            return JsonResponse({'status': 'error', 'message': 'Unauthorized action.'}, status=403)

        requester_username = (token_payload.get('username') or '').strip()
        requester_role = (token_payload.get('role') or '').strip().lower()
        can_view = requester_username == user_nm or requester_role in PERSONNEL_ROLES

        if not can_view:
            return JsonResponse({'status': 'error', 'message': 'Unauthorized action.'}, status=403)

        vehicles = list(VehicleApplication.objects.filter(applicant_username=user_nm).values())
        return JsonResponse(vehicles, safe=False)
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


@csrf_exempt
def submit_reservation(request):
    """
    Submit a new parking spot reservation for admin approval.
    Creates ParkingReservation record with 'pending' status.
    Requires: username, sticker_id, reserved_spots (json array), 
              reservation_reason, reserved_for_datetime
    """
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            username = (data.get('username') or '').strip()
            auth_token = data.get('auth_token')
            token_payload = get_token_payload(auth_token)
            if not token_payload:
                return JsonResponse({'status': 'error', 'message': 'Unauthorized action.'}, status=403)

            requester_username = (token_payload.get('username') or '').strip()
            requester_role = (token_payload.get('role') or '').strip().lower()
            can_submit_for_user = requester_username == username or requester_role in PERSONNEL_ROLES
            if not can_submit_for_user:
                return JsonResponse({'status': 'error', 'message': 'Unauthorized action.'}, status=403)

            sticker_id = data.get('sticker_id')
            reservation_category = data.get('reservation_category')
            reserved_spots = data.get('reserved_spots')  # Should be a list like [1, 2, 3]
            reason = data.get('reservation_reason')
            reserved_for = data.get('reserved_for_datetime')
            
            # Validation
            if not all([username, reserved_spots, reason, reserved_for]):
                return JsonResponse({
                    'status': 'error',
                    'message': 'Missing required fields: username, reserved_spots, reason, datetime'
                }, status=400)

            if not isinstance(reserved_spots, list):
                return JsonResponse({
                    'status': 'error',
                    'message': 'reserved_spots must be a list of spot numbers.'
                }, status=400)

            # Normalize to unique integer spot IDs so overlap checks are reliable.
            normalized_reserved_spots = []
            for spot in reserved_spots:
                try:
                    normalized_reserved_spots.append(int(spot))
                except (TypeError, ValueError):
                    return JsonResponse({
                        'status': 'error',
                        'message': 'reserved_spots contains invalid spot number(s).'
                    }, status=400)

            normalized_reserved_spots = sorted(set(normalized_reserved_spots))
            if not normalized_reserved_spots:
                return JsonResponse({
                    'status': 'error',
                    'message': 'Please provide at least one valid spot number.'
                }, status=400)
            
            # Verify user exists
            user = get_user_by_username(username)

            category = (reservation_category or '').strip().lower()
            requires_sticker = category in ('', 'single')

            if requires_sticker:
                if not sticker_id:
                    return JsonResponse({
                        'status': 'error',
                        'message': 'UA sticker ID is required for this reservation type.'
                    }, status=400)

                # Verify sticker is approved, belongs to user, and valid for current semester.
                sticker_record = VehicleApplication.objects.filter(
                    applicant_username__iexact=username,
                    sticker_id=sticker_id.upper(),
                    status='Approved'
                ).first()

                if not sticker_record:
                    return JsonResponse({
                        'status': 'error',
                        'message': 'Invalid sticker ID or not approved'
                    }, status=400)

                if not is_sticker_valid_for_current_semester(sticker_record, date.today()):
                    return JsonResponse({
                        'status': 'error',
                        'message': 'Sticker is not valid for the current semester.'
                    }, status=400)

                sticker_for_db = sticker_id.upper()
            else:
                # School/Org related bulk reservations can be requested by representative names.
                sticker_for_db = 'N/A'

            # Block submitting a reservation for spots already approved for another user.
            conflict_spots = set()
            # This server-side guard prevents stale clients from double-booking the same spots.
            approved_other_reservations = ParkingReservation.objects.filter(status='approved').exclude(applicant_username=username)
            for existing_reservation in approved_other_reservations:
                try:
                    existing_spots = json.loads(existing_reservation.reserved_spots or '[]')
                except json.JSONDecodeError:
                    existing_spots = []

                existing_spot_ids = set()
                for spot in existing_spots:
                    try:
                        existing_spot_ids.add(int(spot))
                    except (TypeError, ValueError):
                        continue

                overlap = existing_spot_ids.intersection(normalized_reserved_spots)
                if overlap:
                    conflict_spots.update(overlap)

            if conflict_spots:
                sorted_conflicts = sorted(conflict_spots)
                return JsonResponse({
                    'status': 'error',
                    'message': f"Spot(s) {', '.join(str(spot) for spot in sorted_conflicts)} are already reserved by another user.",
                    'conflict_spots': sorted_conflicts
                }, status=409)
            
            # Convert reserved_spots list to JSON string
            import json as json_lib
            reserved_spots_str = json_lib.dumps(normalized_reserved_spots)
            
            # Create reservation with pending status
            reservation = ParkingReservation.objects.create(
                applicant_username=username,
                sticker_id=sticker_for_db,
                reserved_spots=reserved_spots_str,
                reservation_reason=reason,
                reserved_for_datetime=reserved_for,
                status='pending'
            )
            
            return JsonResponse({
                'status': 'success',
                'reservation_id': reservation.id,
                'message': 'Reservation submitted for admin approval'
            })
            
        except UserRegistration.DoesNotExist:
            return JsonResponse({
                'status': 'error',
                'message': 'User not found'
            }, status=404)
        except Exception as e:
            return JsonResponse({
                'status': 'error',
                'message': str(e)
            }, status=500)


def get_user_reservations(request):
    """
    Get all reservations for a specific user.
    Includes pending, approved, denied, and cancelled reservations.
    """
    try:
        username = normalize_username(request.GET.get('username'))
        auth_token = request.GET.get('auth_token')
        token_payload = get_token_payload(auth_token)

        if not username or not token_payload:
            return JsonResponse({'status': 'error', 'message': 'Unauthorized action.'}, status=403)

        requester_username = normalize_username(token_payload.get('username'))
        requester_role = (token_payload.get('role') or '').strip().lower()
        can_view = requester_username.lower() == username.lower() or requester_role in PERSONNEL_ROLES
        if not can_view:
            return JsonResponse({'status': 'error', 'message': 'Unauthorized action.'}, status=403)
        
        reservations = list(ParkingReservation.objects.filter(
            applicant_username__iexact=username
        ).values().order_by('-created_at'))
        
        # Convert reserved_spots from JSON string to list
        for res in reservations:
            try:
                res['reserved_spots'] = json.loads(res['reserved_spots'])
            except:
                res['reserved_spots'] = []
        
        return JsonResponse(reservations, safe=False)
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


def get_approved_reservations_map(request):
    """
    Get all approved reservations for parking map synchronization.
    Any authenticated user can read this so all users see reserved slots.
    """
    try:
        auth_token = request.GET.get('auth_token')
        token_payload = get_token_payload(auth_token)
        if not token_payload:
            return JsonResponse({'status': 'error', 'message': 'Unauthorized action.'}, status=403)

        reservations = list(ParkingReservation.objects.filter(
            status='approved'
        ).values().order_by('-created_at'))

        # Always return a list so the parking map can consume this payload consistently.
        for res in reservations:
            try:
                res['reserved_spots'] = json.loads(res['reserved_spots'])
            except Exception:
                res['reserved_spots'] = []

        return JsonResponse(reservations, safe=False)
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


def get_pending_reservations(request):
    """
    Get all pending reservations for admin dashboard.
    Only returns reservations with status='pending'.
    """
    try:
        auth_payload = authorize_request(request, None, PERSONNEL_ROLES)
        if not auth_payload:
            return JsonResponse({'status': 'error', 'message': 'Unauthorized action.'}, status=403)

        reservations = list(ParkingReservation.objects.filter(
            status='pending'
        ).values().order_by('created_at'))
        
        # Convert reserved_spots from JSON string to list
        for res in reservations:
            try:
                res['reserved_spots'] = json.loads(res['reserved_spots'])
            except:
                res['reserved_spots'] = []
        
        return JsonResponse(reservations, safe=False)
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


def get_all_reservations(request):
    """
    Get all reservations for admin dashboard.
    Returns pending, approved, and denied records.
    """
    try:
        auth_payload = authorize_request(request, None, PERSONNEL_ROLES)
        if not auth_payload:
            return JsonResponse({'status': 'error', 'message': 'Unauthorized action.'}, status=403)

        reservations = list(ParkingReservation.objects.all().values().order_by('-created_at'))

        # Convert reserved_spots from JSON string to list
        for res in reservations:
            try:
                res['reserved_spots'] = json.loads(res['reserved_spots'])
            except:
                res['reserved_spots'] = []

        return JsonResponse(reservations, safe=False)
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


@csrf_exempt
def approve_reservation(request):
    """
    Admin endpoint to approve a pending reservation.
    Updates reservation status to 'approved' and sets approved_by/approved_at.
    """
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            reservation_id = data.get('reservation_id')
            admin_notes = data.get('admin_notes', '')
            auth_payload = authorize_request(request, data, ADMIN_ROLES)
            if not auth_payload:
                return JsonResponse({'status': 'error', 'message': 'Unauthorized action.'}, status=403)

            admin_username = auth_payload.get('username')
            
            reservation = ParkingReservation.objects.get(id=reservation_id)
            
            if reservation.status != 'pending':
                return JsonResponse({
                    'status': 'error',
                    'message': 'Only pending reservations can be approved'
                }, status=400)
            
            reservation.status = 'approved'
            reservation.approved_at = timezone.now()
            reservation.approved_by_username = admin_username
            reservation.admin_notes = admin_notes
            reservation.save()
            
            return JsonResponse({
                'status': 'success',
                'message': 'Reservation approved'
            })
            
        except ParkingReservation.DoesNotExist:
            return JsonResponse({
                'status': 'error',
                'message': 'Reservation not found'
            }, status=404)
        except Exception as e:
            return JsonResponse({
                'status': 'error',
                'message': str(e)
            }, status=500)


@csrf_exempt
def deny_reservation(request):
    """
    Admin endpoint to deny a pending reservation.
    Updates reservation status to 'denied' with optional admin notes.
    """
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            reservation_id = data.get('reservation_id')
            admin_notes = data.get('admin_notes', 'No reason provided')
            auth_payload = authorize_request(request, data, ADMIN_ROLES)
            if not auth_payload:
                return JsonResponse({'status': 'error', 'message': 'Unauthorized action.'}, status=403)

            admin_username = auth_payload.get('username')
            
            reservation = ParkingReservation.objects.get(id=reservation_id)
            
            if reservation.status != 'pending':
                return JsonResponse({
                    'status': 'error',
                    'message': 'Only pending reservations can be denied'
                }, status=400)
            
            reservation.status = 'denied'
            reservation.approved_by_username = admin_username  # Track who denied it
            reservation.admin_notes = admin_notes
            reservation.save()
            
            return JsonResponse({
                'status': 'success',
                'message': 'Reservation denied'
            })
            
        except ParkingReservation.DoesNotExist:
            return JsonResponse({
                'status': 'error',
                'message': 'Reservation not found'
            }, status=404)
        except Exception as e:
            return JsonResponse({
                'status': 'error',
                'message': str(e)
            }, status=500)


@csrf_exempt
def update_reservation_admin(request):
    """
    Admin endpoint to edit reservation status and notes.
    Supports pending/approved/denied/cancelled transitions.
    """
    if request.method != 'POST':
        return JsonResponse({'status': 'error', 'message': 'Method not allowed'}, status=405)

    try:
        data = json.loads(request.body)
        auth_payload = authorize_request(request, data, PERSONNEL_ROLES)
        if not auth_payload:
            return JsonResponse({'status': 'error', 'message': 'Unauthorized action.'}, status=403)

        reservation_id = data.get('reservation_id')
        next_status = (data.get('status') or '').strip().lower()
        admin_notes = (data.get('admin_notes') or '').strip()

        if not reservation_id:
            return JsonResponse({'status': 'error', 'message': 'reservation_id is required'}, status=400)

        valid_statuses = {'pending', 'approved', 'denied', 'cancelled'}
        if next_status and next_status not in valid_statuses:
            return JsonResponse({'status': 'error', 'message': 'Invalid reservation status'}, status=400)

        reservation = ParkingReservation.objects.get(id=reservation_id)
        old_status = (reservation.status or '').lower()

        if next_status:
            reservation.status = next_status
        reservation.admin_notes = admin_notes
        reservation.approved_by_username = auth_payload.get('username')

        if next_status == 'approved' and reservation.approved_at is None:
            reservation.approved_at = timezone.now()

        reservation.save()

        return JsonResponse({
            'status': 'success',
            'message': 'Reservation updated',
            'old_status': old_status,
            'new_status': reservation.status
        })
    except ParkingReservation.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': 'Reservation not found'}, status=404)
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)
