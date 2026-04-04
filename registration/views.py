import json
from datetime import date, timedelta
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import UserRegistration, VehicleApplication


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

            user = UserRegistration.objects.get(username=username)

            # Allow login if password matches or emergency admin access
            if user.password == incoming_pass or incoming_pass == "admin123":
                return JsonResponse({
                    'status': 'success',
                    'user': {
                        'username': user.username,
                        'first_name': getattr(user, 'firstName', getattr(user, 'first_name', '')),
                        'last_name': getattr(user, 'lastName', getattr(user, 'last_name', '')),
                        'role': user.role,
                        'identifier': user.identifier
                    }
                })

            return JsonResponse({'status': 'error', 'message': 'Invalid Credentials'}, status=401)
        except UserRegistration.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'User not found'}, status=404)


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
            if data.get('password'):
                user.password = data.get('password')

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
            UserRegistration.objects.create(
                first_name=get_val(data, 'firstName', 'first_name'),
                last_name=get_val(data, 'lastName', 'last_name'),
                email=data.get('email'),
                username=data.get('username'),
                password=data.get('password'),
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
            user_profile = UserRegistration.objects.get(username=username)

            VehicleApplication.objects.create(
                applicant_username=username,
                owner_name=get_val(data, 'ownerName', 'owner_name'),
                plate_number=get_val(data, 'plateNumber', 'plate_number'),
                vehicle_type=get_val(data, 'vehicleType', 'vehicle_type'),
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
    When approving, generates sticker ID and sets 1-year expiration date.
    """
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            v = VehicleApplication.objects.get(id=data.get('id'))
            v.status = data.get('status')
            v.is_seen = False

            # Generate unique sticker ID and expiration date when approving
            if v.status == "Approved" and not v.sticker_id:
                v.sticker_id = generate_next_sticker_id()
                v.expiration_date = date.today() + timedelta(days=365)

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