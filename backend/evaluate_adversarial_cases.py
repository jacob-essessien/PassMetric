import csv
from combinedAnalyzer import CombinedPasswordAnalyzer

# Adversarial cases matching Table 8.4
CASES = [
    "password123",
    "Pa$$word2024!",
    "Tr0ub4dor&3",
    "K$9mR!vLq2#wP7nX"
]

def main():
    analyzer = CombinedPasswordAnalyzer()
    rows = []

    print("Evaluating adversarial cases...")

    for password in CASES:
        result = analyzer.analyze_password(password)
        
        # Extract only the required fields
        rows.append({
            "Password": password,
            "Entropy (bits)": f"{result['rule_based']['entropy_bits']:.1f}",
            "Rule-based": result['rule_based']['strength'],
            "ML": result.get("ml_based", {}).get("prediction", "n/a"),
            "Combined": result["combined_strength"]
        })

    #CSV Output
    fieldnames = ["Password", "Entropy (bits)", "Rule-based", "ML", "Combined"]
    
    with open("adversarial_cases.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    
    #  Markdown Output
    with open("adversarial_cases.md", "w") as f:
        f.write("| Password | Entropy (bits) | Rule-based | ML | Combined |\n")
        f.write("|----------|----------------|------------|----|----------|\n")
        for r in rows:
            f.write(f"| {r['Password']} | {r['Entropy (bits)']} | {r['Rule-based']} | {r['ML']} | {r['Combined']} |\n")

    print("Generated adversarial_cases.csv and adversarial_cases.md")

if __name__ == "__main__":
    main()