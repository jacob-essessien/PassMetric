import pytest


NEW_PASSWORD = 'AnotherStr0ngP@ssword!2025'


class TestChangeMasterPasswordHappyPath:

    def test_change_with_correct_current_password_succeeds(self, client, logged_in_user, post_json):
        resp = post_json(client, '/api/auth/change-password', {
            'current_password': logged_in_user['password'],
            'new_password': NEW_PASSWORD,
        })
        assert resp.status_code == 200
        assert 'updated' in resp.get_json()['message'].lower()

    def test_vault_entries_survive_master_password_change(self, client, logged_in_user, post_json):
        original_password = 'CorrectHorseBattery!2024'
        post_json(client, '/api/vault/entries', {
            'website': 'github.com',
            'username': 'octocat',
            'password': original_password,
        })


        resp = post_json(client, '/api/auth/change-password', {
            'current_password': logged_in_user['password'],
            'new_password': NEW_PASSWORD,
        })
        assert resp.status_code == 200

        listing = client.get('/api/vault/entries').get_json()['entries']
        assert len(listing) == 1
        assert listing[0]['password'] == original_password

    def test_new_password_works_for_login_after_change(self, client, logged_in_user, post_json):
        original = 'StoredSecret!42'
        post_json(client, '/api/vault/entries', {
            'website': 'a.com', 'username': 'u', 'password': original,
        })

        post_json(client, '/api/auth/change-password', {
            'current_password': logged_in_user['password'],
            'new_password': NEW_PASSWORD,
        })

        post_json(client, '/api/auth/logout', {})

        # Log in with new password
        resp = post_json(client, '/api/auth/login', {
            'email': logged_in_user['email'],
            'master_password': NEW_PASSWORD,
        })
        assert resp.status_code == 200

        # Entry still decrypts 
        listing = client.get('/api/vault/entries').get_json()['entries']
        assert listing[0]['password'] == original

    def test_old_password_rejected_after_change(self, client, logged_in_user, post_json):
        post_json(client, '/api/auth/change-password', {
            'current_password': logged_in_user['password'],
            'new_password': NEW_PASSWORD,
        })
        post_json(client, '/api/auth/logout', {})

        # Old password should now fail
        resp = post_json(client, '/api/auth/login', {
            'email': logged_in_user['email'],
            'master_password': logged_in_user['password'],
        })
        assert resp.status_code == 401


class TestChangeMasterPasswordGuards:

    def test_wrong_current_password_rejected(self, client, logged_in_user, post_json):
        resp = post_json(client, '/api/auth/change-password', {
            'current_password': 'totally-wrong',
            'new_password': NEW_PASSWORD,
        })
        assert resp.status_code == 401

    def test_missing_fields_rejected(self, client, logged_in_user, post_json):
        resp = post_json(client, '/api/auth/change-password', {
            'current_password': logged_in_user['password'],
        })
        assert resp.status_code == 400

    def test_weak_new_password_is_rejected(self, client, logged_in_user, post_json):
        resp = post_json(client, '/api/auth/change-password', {
            'current_password': logged_in_user['password'],
            'new_password': 'qx9z',
        })
        assert resp.status_code == 400
        body = resp.get_json()
        assert body.get('requires_confirmation') is not True

    def test_change_blocked_when_vault_locked(self, client, logged_in_user, post_json):
        # Lock the vault - 403
        post_json(client, '/api/auth/lock', {})
        resp = post_json(client, '/api/auth/change-password', {
            'current_password': logged_in_user['password'],
            'new_password': NEW_PASSWORD,
        })
        assert resp.status_code == 403

    def test_change_requires_login(self, client, post_json):
        # No login at all - 401
        resp = post_json(client, '/api/auth/change-password', {
            'current_password': 'x', 'new_password': 'y',
        })
        assert resp.status_code == 401
