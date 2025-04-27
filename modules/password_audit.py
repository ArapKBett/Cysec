import math
import re
from collections import Counter
from pathlib import Path

class PasswordAuditor:
    def __init__(self):
        self.common_passwords = set()
        with open(Path(__file__).parent.parent / 'static' / 'common_passwords.txt', 'r') as f:
            self.common_passwords.update(line.strip() for line in f)

    def _calculate_entropy(self, password):
        char_counts = Counter(password)
        length = len(password)
        entropy = 0.0
        
        for count in char_counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        
        return entropy * length

    def _check_complexity(self, password):
        checks = {
            'length': len(password) >= 12,
            'lower': bool(re.search(r'[a-z]', password)),
            'upper': bool(re.search(r'[A-Z]', password)),
            'digit': bool(re.search(r'\d', password)),
            'special': bool(re.search(r'[^A-Za-z0-9]', password))
        }
        return checks

    def analyze(self, password):
        if not password:
            return {'error': 'No password provided'}
            
        result = {
            'common': password in self.common_passwords,
            'entropy': self._calculate_entropy(password),
            'complexity': self._check_complexity(password),
            'length': len(password)
        }
        
        result['strength'] = self._determine_strength(result)
        return result

    def _determine_strength(self, analysis):
        if analysis['common']:
            return 0
        score = 0
        score += analysis['complexity']['length'] * 2
        score += sum(1 for check in analysis['complexity'].values() if check) * 10
        score += min(analysis['entropy'] / 4, 30)
        return min(int(score), 100)
