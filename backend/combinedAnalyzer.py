from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
import random

from passGen import PasswordGenerator, PasswordRequirements
from passevaluator import PasswordEvaluator, EvaluationResult, StrengthLevel
from mlclassifier import PasswordMLClassifier


@dataclass
class CombinedAnalysis:

    password_length: int
    rule_based: Dict
    ml_based: Optional[Dict]
    combined_strength: str
    details: Dict
    summary: str


class CombinedPasswordAnalyzer:
    
    def __init__(self, model_path: str = 'password_ml_model.pkl'):
        self.evaluator = PasswordEvaluator()
        self.generator = PasswordGenerator()
        self.ml_classifier = PasswordMLClassifier()
        
        self._model_path = model_path
        self._auto_load_ml_model()

    #loads the ML model if it exists, or train a new one using the RockYou dataset
    def _auto_load_ml_model(self):
        import os
        if os.path.exists(self._model_path):
            try:
                self.ml_classifier.load_model(self._model_path)
                print(f"[ML] Model loaded from {self._model_path}")
                return
            except Exception as e:
                print(f"[ML] Failed to load model: {e}")

        rockyou_path = os.path.join(os.path.dirname(__file__), 'rockyou.txt')
        if os.path.exists(rockyou_path):
            print("[ML] No saved model found. Training from RockYou dataset...")
            try:
                self.ml_classifier.train()
                self.ml_classifier.save_model(self._model_path)
                print(f"[ML] Model trained and saved to {self._model_path}")
            except Exception as e:
                print(f"[ML] Training failed: {e}. ML predictions unavailable.")
        else:
            print("[ML] No model or dataset found. ML predictions unavailable.")
    

    def analyze_password(self, password: str, include_ml: bool = None) -> Dict:
        if include_ml is None:
            include_ml = self.ml_classifier.is_trained
            
        # Rule-based evaluation 
        rule_result = self.evaluator.evaluate_password(password)
        
        ml_prediction = None
        ml_confidence = None
        if include_ml and self.ml_classifier.is_trained:
            try:
                ml_prediction, ml_confidence = self.ml_classifier.predict(password)
            except Exception as e:
                print(f"Warning: ML prediction failed: {e}")
        
        combined_strength = self._determine_combined_strength(rule_result, ml_prediction)
        
        analysis = {
            'password_length': len(password),
            
            'rule_based': {
                'strength': rule_result.strength_level.name,
                'score': rule_result.score,
                'entropy_bits': rule_result.entropy_bits,
                'character_diversity': rule_result.character_diversity,
                'issues': rule_result.issues,
                'warnings': rule_result.warnings,
                'recommendations': rule_result.recommendations
            },
            
            'ml_based': {
                'prediction': ml_prediction,
                'confidence': ml_confidence
            } if ml_prediction else None,
            
            'combined_strength': combined_strength,
            
            'details': rule_result.details,
            
            'summary': self._generate_summary(
                len(password),
                rule_result.strength_level.name,
                rule_result.score,
                rule_result.entropy_bits,
                ml_prediction,
                combined_strength
            )
        }
        
        return analysis
    
    def _determine_combined_strength(self, rule_result: EvaluationResult, ml_prediction: Optional[str]) -> str:

        strength_values = {
            'VERY_WEAK': 0,
            'WEAK': 1,
            'MEDIUM': 2,
            'STRONG': 3,
            'VERY_STRONG': 4
        }
        rule_strength = rule_result.strength_level.name
        rule_value = strength_values.get(rule_strength, 0)
        
        # If no ML prediction, use rule-based only
        if ml_prediction is None:
            return rule_strength
        
        # Map ML prediction to strength values
        ml_strength_map = {
            'WEAK': 1,      
            'MEDIUM': 2,    
            'STRONG': 3     
        }
        ml_value = ml_strength_map.get(ml_prediction, 0)
        # Take the minimum 
        combined_value = min(rule_value, ml_value)  
        # Map back to strength name
        value_to_strength = {v: k for k, v in strength_values.items()}
        return value_to_strength.get(combined_value, 'VERY_WEAK')
    
    def _generate_summary(self, length: int, rule_strength: str, score: float,
                         entropy: float, ml_prediction: Optional[str],
                         combined_strength: str) -> str:
        summary_parts = [
            f"Password Strength: {combined_strength.replace('_', ' ').title()}",
            f"Score: {score:.1f}/100",
            f"Entropy: {entropy:.1f} bits",
            f"Length: {length} chars"
        ]
        
        if ml_prediction:
            summary_parts.append(f"ML Prediction: {ml_prediction}")
        
        return " | ".join(summary_parts)
    
    def generate_secure_password(self, 
                                requirements: Optional[PasswordRequirements] = None) -> str:

        return self.generator.generate_password(requirements)
    
    def generate_passphrase(self, word_count: int = 4, separator: str = "-",
                           capitalize: bool = True, add_number: bool = True) -> str:

        return self.generator.generate_passphrase(word_count, separator, capitalize, add_number)
    
    
    
    

