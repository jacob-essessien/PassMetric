import os
import re
import math
import random
import secrets
import string
import pickle
from typing import Tuple

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix


# Common-word/sequence lists used by both the feature extractor and the
# auto-labeller. Kept up here so the two stay in sync if I add to them.
COMMON_WORDS = [
    'password', 'welcome', 'admin', 'user', 'test', 'login',
    'love', 'summer', 'monkey', 'dragon', 'master', 'letmein',
    'qwerty', 'abc123', 'princess', 'sunshine', 'shadow', 'football',
]
SEQUENCES = ['abc', '123', 'qwe', '234', 'bcd']
YEAR_RE = re.compile(r'(19\d{2}|20\d{2})')
TRIPLE_REPEAT_RE = re.compile(r'(.)\1{2,}')


class PasswordMLClassifier:

    LABELS = {0: 'WEAK', 1: 'MEDIUM', 2: 'STRONG'}

    FEATURE_NAMES = [
        'has_lowercase', 
        'has_uppercase',
        'has_digits',
        'has_symbols',
        'unique_ratio',
        'entropy', 
        'has_common_words',
        'has_sequences', 
        'has_patterns',
        'has_years',
        'has_repeats',
        'types_count',
    ]

    def __init__(self):
        # class_weight='balanced' because rockyou skews heavily to weak/medium
        # and we still want the strong class to be predicted at all
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            class_weight='balanced',
        )
        self.is_trained = False
        self.feature_names = self.FEATURE_NAMES
        self.label_mapping = self.LABELS



    def _extract_features(self, password: str) -> np.ndarray:
        has_lower  = any(c.islower() for c in password)
        has_upper  = any(c.isupper() for c in password)
        has_digit  = any(c.isdigit() for c in password)
        has_symbol = any(c in string.punctuation for c in password)

        n = len(password)
        unique_ratio = len(set(password)) / n if n else 0

        charset_size = (26 if has_lower else 0) + (26 if has_upper else 0) \
                     + (10 if has_digit else 0) + (32 if has_symbol else 0)
        entropy = n * math.log2(charset_size) if charset_size and n else 0

        pw_lower = password.lower()
        has_common = any(w in pw_lower for w in COMMON_WORDS)
        has_seq    = any(s in pw_lower for s in SEQUENCES)

        # repeating block ('abcabc', 'foofoofoo')
        has_pattern = False
        if n >= 4:
            for i in range(2, n // 2 + 1):
                if password[:i] * (n // i) == password:
                    has_pattern = True
                    break

        has_year = bool(YEAR_RE.search(password))

        # consecutive repeated chars: 'aa', 'oo' etc
        has_repeats = any(password[i] == password[i-1] for i in range(1, n))

        types_count = sum([has_lower, has_upper, has_digit, has_symbol])

        feats = [
            int(has_lower), int(has_upper), int(has_digit), int(has_symbol),
            unique_ratio, entropy,
            int(has_common), int(has_seq), int(has_pattern),
            int(has_year), int(has_repeats),
            types_count,
        ]
        return np.array(feats).reshape(1, -1)


    def generate_training_data(self, n_samples: int = 1000) -> Tuple[np.ndarray, np.ndarray]:
        rockyou_path = os.path.join(os.path.dirname(__file__), 'rockyou.txt')
        if not os.path.exists(rockyou_path):
            raise FileNotFoundError("RockYou dataset not found")

        # 40/30/30 split rockyou doesn't really contain "strong" passwords
        # so we have to create that class ourselves
        weak_target   = int(n_samples * 0.4)
        medium_target = int(n_samples * 0.3)
        strong_target = n_samples - weak_target - medium_target

        feats, labels = [], []
        weak_count = medium_count = 0

        with open(rockyou_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if weak_count >= weak_target and medium_count >= medium_target:
                    break
                pw = line.strip()
                if not pw:
                    continue
                label = self._auto_label_password(pw)
                if label == 0 and weak_count < weak_target:
                    feats.append(self._extract_features(pw).flatten())
                    labels.append(0)
                    weak_count += 1
                elif label == 1 and medium_count < medium_target:
                    feats.append(self._extract_features(pw).flatten())
                    labels.append(1)
                    medium_count += 1

        print(f"From RockYou: {weak_count} weak, {medium_count} medium")

        # synthesise strong passwords
        charset = string.ascii_letters + string.digits + string.punctuation
        for _ in range(strong_target):
            length = random.randint(12, 20)
            strong = ''.join(secrets.choice(charset) for _ in range(length))
            feats.append(self._extract_features(strong).flatten())
            labels.append(2)
        print(f"Synthesised {strong_target} strong")

        # shuffle so the random forest doesn't learn the ordering
        combined = list(zip(feats, labels))
        random.shuffle(combined)
        feats, labels = zip(*combined)

        total = len(labels)
        print(f"Total {total}: "
              f"weak {labels.count(0)}, "
              f"medium {labels.count(1)}, "
              f"strong {labels.count(2)}")

        return np.array(feats), np.array(labels)

    def _auto_label_password(self, password: str) -> int:
        n = len(password)
        has_lower  = any(c.islower() for c in password)
        has_upper  = any(c.isupper() for c in password)
        has_digit  = any(c.isdigit() for c in password)
        has_symbol = any(c in string.punctuation for c in password)
        types_count = sum([has_lower, has_upper, has_digit, has_symbol])

        charset_size = (26 if has_lower else 0) + (26 if has_upper else 0) \
                     + (10 if has_digit else 0) + (32 if has_symbol else 0)
        entropy = n * math.log2(charset_size) if charset_size else 0

        pw_lower = password.lower()
        has_common = any(w in pw_lower for w in COMMON_WORDS)
        has_seq    = any(s in pw_lower for s in SEQUENCES)
        has_year   = bool(YEAR_RE.search(password))
        has_run    = bool(TRIPLE_REPEAT_RE.search(password))

        if n < 8 or types_count <= 1 or entropy < 40 or has_common or has_run:
            return 0
        if (n >= 12 and types_count >= 3 and entropy >= 80
                and not has_seq and not has_year and not has_common):
            return 2
        return 1


    def train(self, X_train=None, y_train=None):
        if X_train is None or y_train is None:
            X_train, y_train = self.generate_training_data(n_samples=10000)

        X_tr, X_val, y_tr, y_val = train_test_split(
            X_train, y_train, test_size=0.2, random_state=42, stratify=y_train,
        )

        print(f"Training on {len(X_tr)} samples")
        self.model.fit(X_tr, y_tr)
        self.is_trained = True

        y_pred = self.model.predict(X_val)
        print(classification_report(y_val, y_pred, target_names=['WEAK', 'MEDIUM', 'STRONG']))
        print(confusion_matrix(y_val, y_pred))

    def predict(self, password: str) -> Tuple[str, float]:
        if not self.is_trained:
            raise RuntimeError("Model must be trained before prediction")
        features = self._extract_features(password)
        prediction = self.model.predict(features)[0]
        proba = self.model.predict_proba(features)[0]
        return self.LABELS[prediction], float(proba[prediction])


    def save_model(self, filepath: str = "password_ml_model.pkl"):
        if not self.is_trained:
            raise RuntimeError("Cannot save untrained model")
        with open(filepath, 'wb') as f:
            pickle.dump(self.model, f)
        print(f"Saved to {filepath}")

    def load_model(self, filepath: str = "password_ml_model.pkl"):
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Model file not found: {filepath}")
        with open(filepath, 'rb') as f:
            self.model = pickle.load(f)
        self.is_trained = True




