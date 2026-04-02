import json
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import UserRegistration, VehicleApplication

# --- HELPER TO PREVENT 500 ERRORS ---
def get_val(data, key_camel, key_snake):
    """Checks for both camelCase (React) and snake_case (Django) keys"""
    return data.get(key_camel) or data.get(key_snake)

# registration/views.py

@csrf_exempt
def login_user(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            username = data.get('username')
            incoming_pass = data.get('password') 
            
            user = UserRegistration.objects.get(username=username)

            # SUCCESS: If the password matches OR if it's a demo emergency
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
            print(f"REGISTRATION ERROR: {e}")
            return JsonResponse({'status': 'error', 'message': str(e)}, status=400)
    return JsonResponse({'status': 'error'}, status=405)

@csrf_exempt
def submit_vehicle(request):
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
            print(f"SUBMISSION CRASH: {e}") 
            return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

@csrf_exempt
def update_status(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            v = VehicleApplication.objects.get(id=data.get('id'))
            v.status = data.get('status')
            v.is_seen = False  
            
            if v.status == "Approved" and not v.sticker_id:
                count = VehicleApplication.objects.filter(status="Approved").count() + 1
                v.sticker_id = f"UA-{str(count).zfill(3)}"
            
            v.save()
            return JsonResponse({'status': 'success'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

@csrf_exempt
def mark_notifications_read(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            user_nm = data.get('username')
            VehicleApplication.objects.filter(applicant_username=user_nm).update(is_seen=True)
            return JsonResponse({'status': 'success'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

def get_admin_records(request):
    try:
        vehicles = list(VehicleApplication.objects.all().values())
        return JsonResponse(vehicles, safe=False)
    except:
        return JsonResponse([], safe=False)

def get_user_records(request):
    try:
        user_nm = request.GET.get('username')
        if not user_nm: return JsonResponse([], safe=False)
        vehicles = list(VehicleApplication.objects.filter(applicant_username=user_nm).values())
        return JsonResponse(vehicles, safe=False)
    except:
        return JsonResponse([], safe=False)