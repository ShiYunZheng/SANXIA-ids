from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score


def metrics(true_labels, predicted_labels):
    return {
        "accuracy": accuracy_score(true_labels, predicted_labels),
        "precision": precision_score(true_labels, predicted_labels, average="weighted", zero_division=0.0),
        "recall": recall_score(true_labels, predicted_labels, average="weighted", zero_division=0.0),
        "f1": f1_score(true_labels, predicted_labels, average="weighted", zero_division=0.0),
    }