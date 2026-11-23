import torch
import torch.nn as nn

class NonIIDAnomalyDetector(nn.Module):
    """Neural network model tailored for anomaly detection under non-IID traffic distributions."""
    def __init__(self, input_dim=5):
        super(NonIIDAnomalyDetector, self).__init__()
        self.network = nn.Sequential(
            nn.Linear(input_dim, 32),
            nn.ReLU(),
            nn.Linear(32, 16),
            nn.ReLU(),
            nn.Linear(16, 1),
            nn.Sigmoid()
        )

    def forward(self, x):
        return self.network(x)

def evaluate_traffic(feature_vector: list[float], model: nn.Module) -> float:
    """Evaluates network telemetry vector and outputs an anomaly confidence score."""
    model.eval()
    with torch.no_grad():
        tensor_input = torch.tensor([feature_vector], dtype=torch.float32)
        score = model(tensor_input).item()
    return score