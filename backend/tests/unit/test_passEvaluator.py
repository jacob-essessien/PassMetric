import pytest
from passevaluator import PasswordEvaluator, StrengthLevel, EvaluationResult


@pytest.fixture
def evaluator():
    return PasswordEvaluator()


class TestEntropyCalculation:

    def test_empty_password_entropy_is_zero(self, evaluator):
        assert evaluator.calculate_entropy("") == 0.0

    def test_lowercase_only_entropy(self, evaluator):
        # 8 lowercase chars: log2(26) * 8 ≈ 37.6
        entropy = evaluator.calculate_entropy("abcdefgh")
        assert 37.0 < entropy < 38.0

    def test_full_charset_higher_entropy(self, evaluator):
        # Mixed-type pass should have higher entropy than all-lowercase
        low = evaluator.calculate_entropy("aaaaaaaa")
        mixed = evaluator.calculate_entropy("Aa1!Aa1!")
        assert mixed > low


class TestEvaluatePassword:

    def test_empty_password_is_very_weak(self, evaluator):
        result = evaluator.evaluate_password("")
        assert result.strength_level == StrengthLevel.VERY_WEAK
        assert result.score == 0
        assert "empty" in result.issues[0].lower()

    def test_common_password_flagged(self, evaluator):
        result = evaluator.evaluate_password("password")
        # Should appear in issues since it is in COMMON_PASSWORDS
        assert any("common" in i.lower() for i in result.issues)

    def test_strong_password_scores_high(self, evaluator):
        result = evaluator.evaluate_password("X9!kL@mN#pQ$rS%tU&vW*7zA")
        assert result.score >= 60
        assert result.strength_level in (StrengthLevel.STRONG, StrengthLevel.VERY_STRONG)

    def test_short_password_flagged(self, evaluator):
        result = evaluator.evaluate_password("abc")
        assert any("short" in i.lower() for i in result.issues)

    def test_returns_evaluation_result(self, evaluator):
        result = evaluator.evaluate_password("Hello123!")
        assert isinstance(result, EvaluationResult)
        assert hasattr(result, 'score')
        assert hasattr(result, 'entropy_bits')
        assert hasattr(result, 'recommendations')

    def test_score_in_valid_range(self, evaluator):
        for pwd in ["abc", "password", "Hello123!", "X9!kL@mN#pQ$rS%tU&vW*7zA"]:
            result = evaluator.evaluate_password(pwd)
            assert 0 <= result.score <= 100


class TestPatternDetection:

    def test_sequence_warning(self, evaluator):
        result = evaluator.evaluate_password("abcd1234XY!")
        # Should flag sequential characters somewhere in warnings
        assert any("sequential" in w.lower() for w in result.warnings)

    def test_keyboard_pattern_warning(self, evaluator):
        result = evaluator.evaluate_password("qwerty123A!")
        assert any("keyboard" in w.lower() for w in result.warnings)

    def test_year_warning(self, evaluator):
        result = evaluator.evaluate_password("Summer2024!")
        assert any("year" in w.lower() for w in result.warnings)

    def test_repeated_pattern_issue(self, evaluator):
        result = evaluator.evaluate_password("abcabcabc")
        assert any("pattern" in i.lower() or "repeated" in i.lower() for i in result.issues)

    def test_all_same_character_issue(self, evaluator):
        result = evaluator.evaluate_password("aaaaaaaa")
        assert any("one repeated character" in i.lower() for i in result.issues)


class TestComposition:

    def test_missing_uppercase_warned(self, evaluator):
        result = evaluator.evaluate_password("hello123!")
        assert any("uppercase" in w.lower() for w in result.warnings)

    def test_missing_digit_warned(self, evaluator):
        result = evaluator.evaluate_password("HelloWorld!")
        assert any("digit" in w.lower() for w in result.warnings)