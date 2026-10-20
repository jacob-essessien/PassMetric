import os
import numpy as np
import pytest
from mlclassifier import PasswordMLClassifier


@pytest.fixture
def classifier():
    return PasswordMLClassifier()


class TestFeatureExtraction:

    def test_feature_vector_shape(self, classifier):
        features = classifier._extract_features("Hello123!")
        assert features.shape == (1, 12)

    def test_features_for_all_lowercase(self, classifier):
        features = classifier._extract_features("hello").flatten()
        # has_lower=1, has_upper=0, has_digit=0, has_symbol=0
        assert features[0] == 1
        assert features[1] == 0
        assert features[2] == 0
        assert features[3] == 0

    def test_features_for_full_charset(self, classifier):
        features = classifier._extract_features("Hello123!").flatten()
        assert features[0] == 1  # lowercase
        assert features[1] == 1  # uppercase
        assert features[2] == 1  # digits
        assert features[3] == 1  # symbols
        assert features[11] == 4  # types_count

    def test_features_detect_year(self, classifier):
        features = classifier._extract_features("Summer2024").flatten()
        assert features[9] == 1  # has_years

    def test_features_detect_common_word(self, classifier):
        features = classifier._extract_features("password123").flatten()
        assert features[6] == 1  # has_common_words


class TestAutoLabel:

    def test_short_password_is_weak(self, classifier):
        # length < 8 -> WEAK (0)
        assert classifier._auto_label_password("abc") == 0

    def test_common_word_is_weak(self, classifier):
        assert classifier._auto_label_password("password123") == 0

    def test_strong_password_is_strong(self, classifier):
        # 16-char, 4 types, no patterns -> STRONG (2)
        label = classifier._auto_label_password("X9!kL@mN#pQ$rS%t")
        assert label == 2


class TestPredictionWithoutTraining:

    def test_predict_raises_if_not_trained(self, classifier):
        with pytest.raises(RuntimeError):
            classifier.predict("Hello123!")

    def test_save_raises_if_not_trained(self, classifier, tmp_path):
        with pytest.raises(RuntimeError):
            classifier.save_model(str(tmp_path / "m.pkl"))


class TestTrainPredictSaveLoad:

    def test_train_with_rockyou(self, classifier):
        rockyou = os.path.join(os.path.dirname(__file__), '..', '..', 'rockyou.txt')
        if not os.path.exists(rockyou):
            pytest.skip("rockyou.txt not present at backend/rockyou.txt")
        X, y = classifier.generate_training_data(n_samples=300)
        classifier.train(X_train=X, y_train=y)
        assert classifier.is_trained is True
        label, confidence = classifier.predict("Hello123!")
        assert label in ("WEAK", "MEDIUM", "STRONG")
        assert 0.0 <= confidence <= 1.0

    def test_predict_returns_label_and_confidence(self, classifier):
        rng = np.random.RandomState(42)
        X = rng.rand(60, 12)
        y = np.array([0] * 20 + [1] * 20 + [2] * 20)
        classifier.train(X_train=X, y_train=y)
        label, confidence = classifier.predict("Hello123!")
        assert label in ("WEAK", "MEDIUM", "STRONG")
        assert 0.0 <= confidence <= 1.0

    def test_save_and_load_round_trip(self, classifier, tmp_path):
        rng = np.random.RandomState(42)
        X = rng.rand(60, 12)
        y = np.array([0] * 20 + [1] * 20 + [2] * 20)
        classifier.train(X_train=X, y_train=y)

        model_file = str(tmp_path / "test_model.pkl")
        classifier.save_model(model_file)
        assert os.path.exists(model_file)

        new_classifier = PasswordMLClassifier()
        new_classifier.load_model(model_file)
        assert new_classifier.is_trained is True
        # Should be able to predict after loading
        label, _ = new_classifier.predict("Hello123!")
        assert label in ("WEAK", "MEDIUM", "STRONG")

    def test_load_missing_model_raises(self, classifier, tmp_path):
        with pytest.raises(FileNotFoundError):
            classifier.load_model(str(tmp_path / "does_not_exist.pkl"))