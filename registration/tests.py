import json
from datetime import timedelta, date

from django.test import TestCase
from django.utils import timezone

from .models import UserRegistration, VehicleApplication, ParkingReservation
from .views import (
	issue_auth_token,
	get_current_semester_range,
	is_sticker_valid_for_current_semester,
	passwords_match,
)


class RegistrationApiTests(TestCase):
	def setUp(self):
		self.student = UserRegistration.objects.create(
			first_name='Stud',
			last_name='Ent',
			email='student@example.com',
			username='student1',
			password='PassWord1',
			identifier='2024-0001 | College - BSIT',
			role='student',
		)
		self.other_student = UserRegistration.objects.create(
			first_name='Other',
			last_name='User',
			email='other@example.com',
			username='student2',
			password='PassWord1',
			identifier='2024-0002 | College - BSCS',
			role='student',
		)
		self.admin = UserRegistration.objects.create(
			first_name='Ad',
			last_name='Min',
			email='admin@example.com',
			username='admin1',
			password='PassWord1',
			identifier='Personnel Account',
			role='admin',
		)

		self.student_token = issue_auth_token(self.student.username, self.student.role)
		self.other_student_token = issue_auth_token(self.other_student.username, self.other_student.role)
		self.admin_token = issue_auth_token(self.admin.username, self.admin.role)
		self.root_token = issue_auth_token('rootadmin', 'root_admin')

	def test_login_user_success(self):
		response = self.client.post(
			'/api/login/',
			data=json.dumps({'username': 'student1', 'password': 'PassWord1'}),
			content_type='application/json',
		)

		self.assertEqual(response.status_code, 200)
		payload = response.json()
		self.assertEqual(payload['status'], 'success')
		self.assertEqual(payload['user']['username'], 'student1')
		self.assertTrue(payload['user']['auth_token'])

	def test_login_user_is_case_insensitive(self):
		response = self.client.post(
			'/api/login/',
			data=json.dumps({'username': 'STUDENT1', 'password': 'PassWord1'}),
			content_type='application/json',
		)

		self.assertEqual(response.status_code, 200)
		payload = response.json()
		self.assertEqual(payload['status'], 'success')
		self.assertEqual(payload['user']['username'], 'student1')

	def test_create_personnel_account_requires_root_admin(self):
		response = self.client.post(
			'/api/create-personnel-account/',
			data=json.dumps({
				'auth_token': self.admin_token,
				'role': 'guard',
				'username': 'guard1',
				'password': 'PassWord1',
				'first_name': 'Gu',
				'last_name': 'Ard',
				'email': 'guard@example.com',
			}),
			content_type='application/json',
		)

		self.assertEqual(response.status_code, 403)
		self.assertFalse(UserRegistration.objects.filter(username='guard1').exists())

	def test_create_personnel_account_root_admin_success(self):
		response = self.client.post(
			'/api/create-personnel-account/',
			data=json.dumps({
				'auth_token': self.root_token,
				'role': 'guard',
				'username': 'guard1',
				'password': 'PassWord1',
				'first_name': 'Gu',
				'last_name': 'Ard',
				'email': 'guard@example.com',
			}),
			content_type='application/json',
		)

		self.assertEqual(response.status_code, 200)
		self.assertTrue(UserRegistration.objects.filter(username='guard1', role='guard').exists())

	def test_submit_reservation_blocks_conflicting_approved_spots(self):
		VehicleApplication.objects.create(
			applicant_username=self.student.username,
			owner_name='owner-a',
			plate_number='plate-a',
			vehicle_type='4-Wheels',
			status='Approved',
			sticker_id='UA-001',
			expiration_date=date.today(),
		)
		VehicleApplication.objects.create(
			applicant_username=self.other_student.username,
			owner_name='owner-b',
			plate_number='plate-b',
			vehicle_type='4-Wheels',
			status='Approved',
			sticker_id='UA-002',
			expiration_date=date.today(),
		)
		ParkingReservation.objects.create(
			applicant_username=self.other_student.username,
			sticker_id='UA-002',
			reserved_spots=json.dumps([5, 6]),
			reservation_reason='Other user approved reservation',
			reserved_for_datetime=timezone.now() + timedelta(days=1),
			status='approved',
		)

		response = self.client.post(
			'/api/submit-reservation/',
			data=json.dumps({
				'username': self.student.username,
				'auth_token': self.student_token,
				'sticker_id': 'UA-001',
				'reservation_category': 'single',
				'reserved_spots': [6, 7],
				'reservation_reason': 'Need parking tomorrow',
				'reserved_for_datetime': (timezone.now() + timedelta(days=1)).isoformat(),
			}),
			content_type='application/json',
		)

		self.assertEqual(response.status_code, 409)
		payload = response.json()
		self.assertEqual(payload['status'], 'error')
		self.assertIn(6, payload['conflict_spots'])

	def test_submit_reservation_rejects_non_list_spots(self):
		response = self.client.post(
			'/api/submit-reservation/',
			data=json.dumps({
				'username': self.student.username,
				'auth_token': self.student_token,
				'sticker_id': 'UA-001',
				'reservation_category': 'single',
				'reserved_spots': '1,2,3',
				'reservation_reason': 'Bad spots payload',
				'reserved_for_datetime': (timezone.now() + timedelta(days=1)).isoformat(),
			}),
			content_type='application/json',
		)

		self.assertEqual(response.status_code, 400)
		self.assertIn('must be a list', response.json()['message'])

	def test_get_approved_reservations_map_requires_auth(self):
		response = self.client.get('/api/approved-reservations-map/')
		self.assertEqual(response.status_code, 403)

	def test_get_approved_reservations_map_parses_reserved_spots(self):
		ParkingReservation.objects.create(
			applicant_username=self.student.username,
			sticker_id='UA-001',
			reserved_spots=json.dumps([10, 11]),
			reservation_reason='Approved mapping payload',
			reserved_for_datetime=timezone.now() + timedelta(days=1),
			status='approved',
		)

		response = self.client.get(
			'/api/approved-reservations-map/',
			data={'auth_token': self.student_token},
		)

		self.assertEqual(response.status_code, 200)
		payload = response.json()
		self.assertTrue(len(payload) >= 1)
		self.assertIsInstance(payload[0]['reserved_spots'], list)

	def test_update_reservation_admin_requires_personnel_role(self):
		reservation = ParkingReservation.objects.create(
			applicant_username=self.student.username,
			sticker_id='UA-001',
			reserved_spots=json.dumps([12]),
			reservation_reason='Role check',
			reserved_for_datetime=timezone.now() + timedelta(days=1),
			status='pending',
		)

		response = self.client.post(
			'/api/update-reservation-admin/',
			data=json.dumps({
				'reservation_id': reservation.id,
				'status': 'approved',
				'admin_notes': 'Attempt from student',
				'auth_token': self.student_token,
			}),
			content_type='application/json',
		)

		self.assertEqual(response.status_code, 403)

	def test_update_reservation_admin_sets_approved_metadata(self):
		reservation = ParkingReservation.objects.create(
			applicant_username=self.student.username,
			sticker_id='UA-001',
			reserved_spots=json.dumps([13]),
			reservation_reason='Approve me',
			reserved_for_datetime=timezone.now() + timedelta(days=1),
			status='pending',
		)

		response = self.client.post(
			'/api/update-reservation-admin/',
			data=json.dumps({
				'reservation_id': reservation.id,
				'status': 'approved',
				'admin_notes': 'Approved by admin',
				'auth_token': self.admin_token,
			}),
			content_type='application/json',
		)

		self.assertEqual(response.status_code, 200)
		reservation.refresh_from_db()
		self.assertEqual(reservation.status, 'approved')
		self.assertIsNotNone(reservation.approved_at)
		self.assertEqual(reservation.approved_by_username, self.admin.username)

	def test_update_status_requires_admin_role(self):
		application = VehicleApplication.objects.create(
			applicant_username=self.student.username,
			owner_name='owner-c',
			plate_number='plate-c',
			vehicle_type='4-Wheels',
			status='Pending',
		)

		response = self.client.post(
			'/api/update-status/',
			data=json.dumps({
				'id': application.id,
				'status': 'Approved',
				'admin_notes': 'Attempt by student',
				'auth_token': self.student_token,
			}),
			content_type='application/json',
		)

		self.assertEqual(response.status_code, 403)

	def test_update_status_approve_sets_sticker_expiration_and_notes(self):
		application = VehicleApplication.objects.create(
			applicant_username=self.student.username,
			owner_name='owner-d',
			plate_number='plate-d',
			vehicle_type='4-Wheels',
			status='Pending',
		)

		response = self.client.post(
			'/api/update-status/',
			data=json.dumps({
				'id': application.id,
				'status': 'Approved',
				'admin_notes': 'Looks good',
				'auth_token': self.admin_token,
			}),
			content_type='application/json',
		)

		self.assertEqual(response.status_code, 200)
		application.refresh_from_db()
		self.assertEqual(application.status, 'Approved')
		self.assertEqual(application.admin_notes, 'Looks good')
		self.assertTrue(application.sticker_id)
		self.assertIsNotNone(application.expiration_date)

	def test_update_profile_rejects_password_change_without_old_password(self):
		response = self.client.post(
			'/api/update-profile/',
			data=json.dumps({
				'username': self.student.username,
				'identifier': self.student.identifier,
				'password': 'NewPassWord1',
				'auth_token': self.student_token,
			}),
			content_type='application/json',
		)

		self.assertEqual(response.status_code, 400)
		self.assertIn('Old password is required', response.json()['message'])

	def test_update_profile_changes_password_with_valid_old_password(self):
		response = self.client.post(
			'/api/update-profile/',
			data=json.dumps({
				'username': self.student.username,
				'identifier': self.student.identifier,
				'oldPassword': 'PassWord1',
				'password': 'NewPassWord1',
				'auth_token': self.student_token,
			}),
			content_type='application/json',
		)

		self.assertEqual(response.status_code, 200)
		self.student.refresh_from_db()
		self.assertTrue(passwords_match(self.student.password, 'NewPassWord1'))
		self.assertFalse(passwords_match(self.student.password, 'PassWord1'))

	def test_update_profile_allows_admin_to_update_other_user_identifier(self):
		new_identifier = '2024-0001 | College - BSCS'
		response = self.client.post(
			'/api/update-profile/',
			data=json.dumps({
				'username': self.student.username,
				'identifier': new_identifier,
				'auth_token': self.admin_token,
			}),
			content_type='application/json',
		)

		self.assertEqual(response.status_code, 200)
		self.student.refresh_from_db()
		self.assertEqual(self.student.identifier, new_identifier)

	def test_semester_helper_and_validity_checks(self):
		start_sem1, end_sem1 = get_current_semester_range(date(2026, 9, 10))
		self.assertEqual(start_sem1, date(2026, 8, 1))
		self.assertEqual(end_sem1, date(2026, 12, 31))

		start_sem2, end_sem2 = get_current_semester_range(date(2026, 2, 10))
		self.assertEqual(start_sem2, date(2026, 1, 1))
		self.assertEqual(end_sem2, date(2026, 5, 31))

		sticker_obj = VehicleApplication(
			applicant_username=self.student.username,
			owner_name='owner-e',
			plate_number='plate-e',
			vehicle_type='4-Wheels',
			status='Approved',
			expiration_date=date(2026, 12, 31),
		)
		self.assertTrue(is_sticker_valid_for_current_semester(sticker_obj, today=date(2026, 9, 15)))
		self.assertFalse(is_sticker_valid_for_current_semester(sticker_obj, today=date(2026, 3, 15)))
