from django.urls import path
from . import views

urlpatterns = [
    # Since your main urls.py already has path('api/', include('registration.urls')),
    # These will automatically become /api/register/, /api/login/, etc.
    path('register/', views.register_user, name='register'),
    path('login/', views.login_user, name='login'), 
    path('admin-records/', views.get_admin_records),
    path('user-records/', views.get_user_records),
    path('update-status/', views.update_status),
    path('submit-vehicle/', views.submit_vehicle),
    path('mark-notifications-read/', views.mark_notifications_read),
    path('update-profile/', views.update_profile),
]