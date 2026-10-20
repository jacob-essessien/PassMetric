import string
import pytest
from passGen import PasswordGenerator, PasswordRequirements


class TestPasswordRequirements:

    def test_default_requirements_are_valid(self):
        req = PasswordRequirements()
        ok, err = req.validate()
        assert ok is True
        assert err is None

    def test_too_short_length_invalid(self):
        req = PasswordRequirements(length=2)
        ok, err = req.validate()
        assert ok is False
        assert "at least 4" in err

    def test_excessive_length_invalid(self):
        req = PasswordRequirements(length=129)
        ok, err = req.validate()
        assert ok is False
        assert "128" in err

    def test_no_character_types_invalid(self):
        req = PasswordRequirements(
            include_uppercase=False, include_lowercase=False,
            include_digits=False, include_symbols=False
        )
        ok, err = req.validate()
        assert ok is False
        assert "character type" in err

    def test_length_below_required_types_invalid(self):
        # length=3 but requires 4 types and require_all_types=True
        req = PasswordRequirements(length=3, require_all_types=True)
        ok, err = req.validate()
        assert ok is False


class TestPasswordGeneration:

    @pytest.fixture
    def gen(self):
        generator = PasswordGenerator()
        generator.wordlist = ['alpha', 'bravo', 'charlie', 'delta']
        return generator

    def test_default_password_length(self, gen):
        password = gen.generate_password()
        assert len(password) == 16

    def test_custom_length(self, gen):
        password = gen.generate_password(PasswordRequirements(length=24))
        assert len(password) == 24

    def test_password_contains_required_types(self, gen):
        req = PasswordRequirements(length=16, require_all_types=True)
        password = gen.generate_password(req)
        assert any(c.islower() for c in password)
        assert any(c.isupper() for c in password)
        assert any(c.isdigit() for c in password)
        assert any(c in string.punctuation for c in password)

    def test_only_lowercase(self, gen):
        req = PasswordRequirements(
            length=12, include_uppercase=False,
            include_digits=False, include_symbols=False
        )
        password = gen.generate_password(req)
        assert all(c.islower() for c in password)

    def test_exclude_similar_characters(self, gen):
        req = PasswordRequirements(length=20, exclude_similar=True)
        password = gen.generate_password(req)
        for c in password:
            assert c not in 'l1I0O'

    def test_invalid_requirements_raises_value_error(self, gen):
        with pytest.raises(ValueError):
            gen.generate_password(PasswordRequirements(length=2))

    

class TestPasswordUniqueness:
    @pytest.fixture
    def gen(self):
        generator = PasswordGenerator()
        generator.wordlist = ['alpha', 'bravo', 'charlie', 'delta']
        return generator

    def test_passwords_are_unique(self, gen):
        # Two random passwords should almost never match
        p1 = gen.generate_password()
        p2 = gen.generate_password()
        assert p1 != p2

    def test_no_duplicates_in_large_batch(self, gen):
        # 100 generations of a 16-char full-alphabet password must produce zero duplicates.
        seen = set()
        for _ in range(100):
            p = gen.generate_password(PasswordRequirements(length=16, require_all_types=True))
            assert p not in seen
            seen.add(p)
        

class TestPassphraseGeneration:

    @pytest.fixture
    def gen(self):
        generator = PasswordGenerator()
        generator.wordlist = ['alpha', 'bravo', 'charlie', 'delta']
        return generator

    def test_passphrase_default_word_count(self, gen):
        phrase = gen.generate_passphrase()
        # 4 words separated by '-' plus a number suffix by default
        assert phrase.count('-') == 3

    def test_passphrase_custom_separator(self, gen):
        phrase = gen.generate_passphrase(word_count=3, separator='_', add_number=False)
        assert phrase.count('_') == 2

    def test_passphrase_capitalize(self, gen):
        phrase = gen.generate_passphrase(word_count=3, capitalize=True, add_number=False)
        words = phrase.split('-')
        for w in words:
            assert w[0].isupper()

    def test_passphrase_with_number(self, gen):
        phrase = gen.generate_passphrase(word_count=2, add_number=True)
        # Last characters should be digits
        assert phrase[-1].isdigit()


