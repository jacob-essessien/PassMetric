import os
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from mlclassifier import PasswordMLClassifier

MODEL_PATH = "password_ml_model.pkl"

def main():
    clf = PasswordMLClassifier()

    if not os.path.exists(MODEL_PATH):
        print(f"No saved model at {MODEL_PATH}; training a fresh one.")
        clf.train()
    else:
        clf.load_model(MODEL_PATH)
        print(f"Loaded model from {MODEL_PATH}")

    feature_names = clf.FEATURE_NAMES
    
    #Gini importance
    gini = clf.model.feature_importances_

    # Sort by importance descending
    order = np.argsort(gini)[::-1]


    #  Markdown Output
    with open("feature_importance_summary.md", "w") as f:
        f.write("| Rank | Feature | Importance |\n")
        f.write("|------|---------|------------|\n")
        for rank, i in enumerate(order, start=1):
            f.write(f"| {rank} | `{feature_names[i]}` | {gini[i]:.3f} |\n")
    print("Generated feature_importance_summary.md")

    # bar chart 
    order_rev = order[::-1]
    
    fig, ax = plt.subplots(figsize=(8, 5))
    y_pos = np.arange(len(feature_names))
    
    bars = ax.barh(y_pos, gini[order_rev], color="#3b5b92")
    

    for i, v in enumerate(gini[order_rev]):
        ax.text(v + 0.005, i, f"{v:.3f}", va='center', fontsize=8)

    ax.set_yticks(y_pos)
    ax.set_yticklabels([feature_names[i] for i in order_rev])
    ax.set_xlabel("Feature Importance (Mean Decrease in Impurity)")
    ax.set_title("Random Forest Feature Importances")
    
    plt.tight_layout()
    plt.savefig("feature_importance.png", dpi=150)
    print("Generated feature_importance.png")



if __name__ == "__main__":
    main()