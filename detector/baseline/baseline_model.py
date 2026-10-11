from typing import Dict, List
import statistics
from detector.features.feature_extractor import ExtractedFeatures

class BaselineModel:
    """
    Maintains empirical behavioral baselines for the medical AI agent.
    Documents normal statistical bounds based on calibration runs.
    """
    def __init__(self):
        self.sample_count = 0
        self.metrics = {
            "auth_denial": [],
            "prompt_suspicion": [],
            "unexpected_exec": [],
            "unexpected_file": [],
            "unexpected_net": []
        }

    def train_on_sample(self, features: ExtractedFeatures):
        self.sample_count += 1
        self.metrics["auth_denial"].append(features.auth_denial)
        self.metrics["prompt_suspicion"].append(features.prompt_suspicion)
        self.metrics["unexpected_exec"].append(features.unexpected_exec)
        self.metrics["unexpected_file"].append(features.unexpected_file)
        self.metrics["unexpected_net"].append(features.unexpected_net)

    def get_baseline_summary(self) -> Dict[str, Dict[str, float]]:
        summary = {}
        for k, v in self.metrics.items():
            if len(v) > 0:
                mean_val = statistics.mean(v)
                stdev_val = statistics.stdev(v) if len(v) > 1 else 0.0
            else:
                mean_val = 0.0
                stdev_val = 0.0
            summary[k] = {"mean": round(mean_val, 4), "stdev": round(stdev_val, 4)}
        return summary

    def get_deviation(self, features: ExtractedFeatures) -> float:
        """
        Calculates simple Euclidean distance from baseline mean.
        """
        summary = self.get_baseline_summary()
        sq_dist = 0.0
        feature_dict = features.model_dump()
        for k, stats in summary.items():
            val = feature_dict.get(k, 0.0)
            diff = val - stats["mean"]
            sq_dist += diff * diff
        return round(sq_dist ** 0.5, 4)
