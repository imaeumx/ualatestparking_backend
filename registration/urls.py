from django.urls import path
from . import views

urlpatterns = [
    # API endpoints for the UA Parking Management System
    # All routes are prefixed with '/api/' from main urls.py

    # Authentication endpoints
    path('register/', views.register_user, name='register'),  # User registration
    path('login/', views.login_user, name='login'),  # User authentication

    # Application management
    path('submit-vehicle/', views.submit_vehicle),  # Submit parking application
    path('update-status/', views.update_status),  # Admin: approve/reject applications

    # Data retrieval
    path('admin-records/', views.get_admin_records),  # Admin: get all applications
    path('user-records/', views.get_user_records),  # User: get own applications

    # User actions
    path('update-profile/', views.update_profile),  # Update user profile/settings
    path('mark-notifications-read/', views.mark_notifications_read),  # Mark notifications as read
]