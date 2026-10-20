import pytest

MIXED_PASSWORDS = [
    ('abc',                             'very weak'),
    ('password',                        'common / weak'),
    ('Hello123',                        'medium'),
    ('Tr0ub4dor&3',                     'strong-ish'),
    ('X9!kL@mN#pQ$rS%tU&vW*7zA',       'very strong'),
]


class TestAnalyzeEndpoint:

    def test_analyze_strong_password(self, client, post_json):
        resp = post_json(client, '/api/analyze',
                         {'password': 'X9!kL@mN#pQ$rS%tU&vW*7zA'})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['rule_based']['score'] >= 60
        assert data['rule_based']['strength'] in ('STRONG', 'VERY_STRONG')

    def test_analyze_weak_password(self, client, post_json):
        resp = post_json(client, '/api/analyze', {'password': 'abc'})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['rule_based']['score'] < 30

    def test_analyze_missing_password_rejected(self, client, post_json):
        resp = post_json(client, '/api/analyze', {})
        assert resp.status_code == 400


class TestPrecheckPassword:

    def test_precheck_weak_flagged(self, client, post_json):
        resp = post_json(client, '/api/auth/precheck-password', {'password': 'abc'})
        assert resp.status_code == 200
        body = resp.get_json()
        assert body['is_weak'] is True
        assert body['needs_warning'] is True

    def test_precheck_strong_passes(self, client, post_json):
        resp = post_json(client, '/api/auth/precheck-password',
                         {'password': 'X9!kL@mN#pQ$rS%tU&vW*7zA'})
        assert resp.status_code == 200
        body = resp.get_json()
        assert body['is_weak'] is False


class TestGenerateEndpoints:

    def test_generate_password_default_length(self, client, post_json):
        resp = post_json(client, '/api/generate', {'requirements': {}})
        assert resp.status_code == 200
        assert len(resp.get_json()['password']) >= 12

    def test_generate_password_custom_length(self, client, post_json):
        resp = post_json(client, '/api/generate', {'requirements': {'length': 24}})
        assert resp.status_code == 200
        assert len(resp.get_json()['password']) == 24

    def test_generate_passphrase(self, client, logged_in_user, post_json):
        # Passphrase generation requires login because it returns analysis too
        resp = post_json(client, '/api/tools/generate-passphrase',
                         {'word_count': 4, 'separator': '-', 'add_number': False})
        assert resp.status_code == 200
        body = resp.get_json()
        assert 'passphrase' in body
        assert body['passphrase'].count('-') == 3
        assert 'analysis' in body


class TestHealthAudit:

    def test_audit_empty_vault(self, client, logged_in_user):
        # Vault has no entries, audit should return all zero counts
        resp = client.get('/api/tools/health-audit')
        assert resp.status_code == 200
        body = resp.get_json()
        assert body['total'] == 0
        assert body['weak_count'] == 0
        assert body['breached_count'] == 0
        assert body['average_score'] == 0

    def test_audit_with_mixed_strength_entries(self, client, logged_in_user, post_json):
        for idx, (pw, _label) in enumerate(MIXED_PASSWORDS):
            post_json(client, '/api/vault/entries', {
                'website': f'site{idx}.com',
                'username': f'user{idx}',
                'password': pw,
            })

        resp = client.get('/api/tools/health-audit')
        assert resp.status_code == 200
        body = resp.get_json()

        assert body['total'] == 5

        assert body['weak_count'] >= 2

        assert 0 <= body['average_score'] <= 100

        for entry in body['entries']:
            assert 0 <= entry['score'] <= 100
            assert entry['strength'] in (
                'VERY_WEAK', 'WEAK', 'MEDIUM', 'STRONG', 'VERY_STRONG'
            )

    def test_audit_blocked_when_vault_locked(self, client, logged_in_user, post_json):
        post_json(client, '/api/auth/lock', {})
        resp = client.get('/api/tools/health-audit')
        assert resp.status_code == 403
