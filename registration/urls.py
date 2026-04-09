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

    # Parking Reservations (with admin approval workflow)
    path('submit-reservation/', views.submit_reservation),  # User: submit multi-spot reservation
    path('user-reservations/', views.get_user_reservations),  # User: get own reservations
    path('approved-reservations-map/', views.get_approved_reservations_map),  # Authenticated: get approved reservations for map sync
    path('pending-reservations/', views.get_pending_reservations),  # Admin: get pending reservations
    path('all-reservations/', views.get_all_reservations),  # Admin: get all reservations
    path('approve-reservation/', views.approve_reservation),  # Admin: approve reservation
    path('deny-reservation/', views.deny_reservation),  # Admin: deny reservation
    path('update-reservation-admin/', views.update_reservation_admin),  # Admin: edit reservation status/notes
    path('create-personnel-account/', views.create_personnel_account),  # Root admin: create admin/guard
]