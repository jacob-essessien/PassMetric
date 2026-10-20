import json
import pytest


class TestVaultRoundTrip:

    def test_add_entry_returns_201_and_id(self, client, logged_in_user, post_json):
        resp = post_json(client, '/api/vault/entries', {
            'website': 'github.com',
            'username': 'octocat',
            'password': 'mypassword123',
        })
        assert resp.status_code == 201
        assert 'entry_id' in resp.get_json()

    def test_plaintext_round_trip_through_api(self, client, logged_in_user, post_json):
        # Add an entry with a known plaintext password
        original_password = 'CorrectHorseBatteryStaple!42'
        resp = post_json(client, '/api/vault/entries', {
            'website': 'example.com',
            'username': 'alice',
            'password': original_password,
        })
        entry_id = resp.get_json()['entry_id']

        # Fetch it back through the listing endpoint
        listing = client.get('/api/vault/entries').get_json()
        entries = listing['entries']
        assert len(entries) == 1
        assert entries[0]['entry_id'] == entry_id
        assert entries[0]['password'] == original_password

    def test_password_is_not_stored_as_plaintext(self, client, logged_in_user, post_json):
        post_json(client, '/api/vault/entries', {
            'website': 'a.com', 'username': 'u', 'password': 'mySecretValue',
        })
        import app as app_module
        from models import VaultEntry
        with app_module.app.app_context():
            row = VaultEntry.query.first()
            assert 'mySecretValue' not in row.encrypted_password
            # also verify the DB column holds JSON nonce+ciphertext, not plaintext
            blob = json.loads(row.encrypted_password)
            assert 'nonce' in blob
            assert 'ciphertext' in blob


class TestVaultUpdateAndDelete:

    def _add(self, client, post_json, password='p1'):
        resp = post_json(client, '/api/vault/entries', {
            'website': 'site.com', 'username': 'u', 'password': password,
        })
        return resp.get_json()['entry_id']

    def test_update_password_changes_plaintext(self, client, logged_in_user, post_json, put_json):
        entry_id = self._add(client, post_json, password='oldpass')
        resp = put_json(client, f'/api/vault/entries/{entry_id}', {'password': 'newpass'})
        assert resp.status_code == 200

        listing = client.get('/api/vault/entries').get_json()['entries']
        assert listing[0]['password'] == 'newpass'

    def test_update_metadata_does_not_change_password_age(self, client, logged_in_user, post_json, put_json):
        entry_id = self._add(client, post_json, password='same')

        listing_before = client.get('/api/vault/entries').get_json()['entries']
        age_before = listing_before[0]['password_changed_at']

        put_json(client, f'/api/vault/entries/{entry_id}', {'website': 'newsite.com'})

        listing_after = client.get('/api/vault/entries').get_json()['entries']
        assert listing_after[0]['password_changed_at'] == age_before

    def test_delete_entry(self, client, logged_in_user, post_json):
        entry_id = self._add(client, post_json)
        resp = client.delete(f'/api/vault/entries/{entry_id}')
        assert resp.status_code == 200

        listing = client.get('/api/vault/entries').get_json()['entries']
        assert listing == []

    def test_delete_unknown_entry_returns_404(self, client, logged_in_user):
        resp = client.delete('/api/vault/entries/does-not-exist')
        assert resp.status_code == 404


class TestVaultGuards:

    def test_add_entry_missing_fields_rejected(self, client, logged_in_user, post_json):
        resp = post_json(client, '/api/vault/entries', {'website': 'x'})
        assert resp.status_code == 400

    def test_unverified_user_blocked_from_adding(self, client, registered_user, post_json):
        login = post_json(client, '/api/auth/login', {
            'email': registered_user['email'],
            'master_password': registered_user['password'],
        })
        assert login.status_code == 403
        assert login.get_json()['requires_verification'] is True

        resp = post_json(client, '/api/vault/entries', {
            'website': 'a.com', 'username': 'u', 'password': 'p',
        })
        assert resp.status_code == 401

    def test_locked_vault_blocks_listing(self, client, logged_in_user, post_json):
        post_json(client, '/api/auth/lock', {})
        resp = client.get('/api/vault/entries')
        assert resp.status_code == 403


class TestVaultSearch:

    def test_search_matches_substring(self, client, logged_in_user, post_json):
        post_json(client, '/api/vault/entries',
                  {'website': 'github.com', 'username': 'octocat', 'password': 'p1'})
        post_json(client, '/api/vault/entries',
                  {'website': 'gitlab.com', 'username': 'alice', 'password': 'p2'})
        post_json(client, '/api/vault/entries',
                  {'website': 'example.com', 'username': 'bob', 'password': 'p3'})

        resp = client.get('/api/vault/search?q=git')
        results = resp.get_json()['entries']
        assert len(results) == 2

    def test_clear_vault_removes_all_entries(self, client, logged_in_user, post_json):
        post_json(client, '/api/vault/entries',
                  {'website': 'a.com', 'username': 'u', 'password': 'p'})
        post_json(client, '/api/vault/entries',
                  {'website': 'b.com', 'username': 'u', 'password': 'p'})

        resp = post_json(client, '/api/vault/clear', {
            'master_password': logged_in_user['password'],
        })
        assert resp.status_code == 200
        assert client.get('/api/vault/entries').get_json()['entries'] == []

    def test_clear_vault_requires_master_password(self, client, logged_in_user, post_json):
        post_json(client, '/api/vault/entries', {
            'website': 'a.com', 'username': 'u', 'password': 'p',
        })
        resp = post_json(client, '/api/vault/clear', {})
        assert resp.status_code == 401
        assert len(client.get('/api/vault/entries').get_json()['entries']) == 1
