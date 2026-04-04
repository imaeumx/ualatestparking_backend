import json
import re
from datetime import date
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import UserRegistration, VehicleApplication, ParkingReservation
from django.utils import timezone
from django.core import signing
from django.core.signing import BadSignature, SignatureExpired


PERSONNEL_ROLES = {'root_admin', 'admin', 'guard'}
ADMIN_ROLES = {'root_admin', 'admin'}
AUTH_TOKEN_SALT = 'ua-parking-auth'
AUTH_TOKEN_MAX_AGE_SECONDS = 60 * 60 * 12


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


@csrf_exempt
def login_user(request):
    """
    Authenticate user login.
    Accepts username and password, returns user data on success.
    Includes emergency admin access for demo purposes.
    """
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            username = data.get('username')
            incoming_pass = data.get('password')

            # Root admin emergency credential (can manage personnel accounts).
            if username == 'rootadmin' and incoming_pass == 'rootadmin123':
                root_role = 'root_admin'
                return JsonResponse({
                    'status': 'success',
                    'user': {
                        'username': 'rootadmin',
                        'first_name': 'Root',
                        'last_name': 'Admin',
                        'role': root_role,
                        'identifier': 'System Root',
                        'auth_token': issue_auth_token('rootadmin', root_role)
                    }
                })

            user = UserRegistration.objects.get(username=username)

            # Allow login if password matches or emergency admin access
            if user.password == incoming_pass or incoming_pass == "admin123":
                user_role = (user.role or '').strip().lower()
                return JsonResponse({
                    'status': 'success',
                    'user': {
                        'username': user.username,
                        'first_name': getattr(user, 'firstName', getattr(user, 'first_name', '')),
                        'last_name': getattr(user, 'lastName', getattr(user, 'last_name', '')),
                        'role': user.role,
                        'identifier': user.identifier,
                        'auth_token': issue_auth_token(user.username, user_role)
                    }
                })

            return JsonResponse({'status': 'error', 'message': 'Invalid Credentials'}, status=401)
        except UserRegistration.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'User not found'}, status=404)


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

        if UserRegistration.objects.filter(username=username).exists():
            return JsonResponse({'status': 'error', 'message': 'Username already exists.'}, status=400)

        UserRegistration.objects.create(
            first_name=first_name,
            last_name=last_name,
            email=email,
            username=username,
            password=password,
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
            user = UserRegistration.objects.get(username=data.get('username'))

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

                if user.password != incoming_old_password:
                    return JsonResponse({'status': 'error', 'message': 'Old password is incorrect.'}, status=400)

                user.password = incoming_new_password

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
                first_name=get_val(data, 'firstName', 'first_name'),
                last_name=get_val(data, 'lastName', 'last_name'),
                email=data.get('email'),
                username=data.get('username'),
                password=incoming_password,
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
            username = data.get('username')
            payment_method = get_val(data, 'paymentMethod', 'payment_method')
            payment_reference = get_val(data, 'paymentReference', 'payment_reference')

            if not payment_method or not payment_reference:
                return JsonResponse({'status': 'error', 'message': 'Payment method and payment reference are required.'}, status=400)

            user_profile = UserRegistration.objects.get(username=username)

            VehicleApplication.objects.create(
                applicant_username=username,
                owner_name=get_val(data, 'ownerName', 'owner_name'),
                plate_number=get_val(data, 'plateNumber', 'plate_number'),
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
            v.is_seen = False

            # Generate unique sticker ID and set expiration to current semester end.
            if v.status == "Approved" and not v.sticker_id:
                v.sticker_id = generate_next_sticker_id()
                _, semester_end = get_current_semester_range(date.today())
                v.expiration_date = semester_end

            v.save()
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
            user_nm = data.get('username')
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
    except:
        return JsonResponse([], safe=False)


def get_user_records(request):
    """
    Get vehicle applications for a specific user.
    Used by user dashboard to show their application history.
    """
    try:
        user_nm = request.GET.get('username')
        if not user_nm: return JsonResponse([], safe=False)
        vehicles = list(VehicleApplication.objects.filter(applicant_username=user_nm).values())
        return JsonResponse(vehicles, safe=False)
    except:
        return JsonResponse([], safe=False)


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
            username = data.get('username')
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
            
            # Verify user exists
            user = UserRegistration.objects.get(username=username)

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
                    applicant_username=username,
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
            
            # Convert reserved_spots list to JSON string
            import json as json_lib
            reserved_spots_str = json_lib.dumps(reserved_spots)
            
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
        username = request.GET.get('username')
        if not username:
            return JsonResponse([], safe=False)
        
        reservations = list(ParkingReservation.objects.filter(
            applicant_username=username
        ).values().order_by('-created_at'))
        
        # Convert reserved_spots from JSON string to list
        for res in reservations:
            try:
                res['reserved_spots'] = json.loads(res['reserved_spots'])
            except:
                res['reserved_spots'] = []
        
        return JsonResponse(reservations, safe=False)
    except:
        return JsonResponse([], safe=False)


def get_pending_reservations(request):
    """
    Get all pending reservations for admin dashboard.
    Only returns reservations with status='pending'.
    """
    try:
        auth_payload = authorize_request(request, None, ADMIN_ROLES)
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
    except:
        return JsonResponse([], safe=False)


def get_all_reservations(request):
    """
    Get all reservations for admin dashboard.
    Returns pending, approved, and denied records.
    """
    try:
        auth_payload = authorize_request(request, None, ADMIN_ROLES)
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
    except:
        return JsonResponse([], safe=False)


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
        auth_payload = authorize_request(request, data, ADMIN_ROLES)
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
