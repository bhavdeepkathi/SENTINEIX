import pandas as pd
import numpy as np
from pathlib import Path

# Generate synthetic dataset for training
# Features: hour, failed_logins, success_logins, privileged_cmds, data_mb, unique_ips, user_id_encoded
np.random.seed(42)
n_samples = 5000

data = {
    "hour": np.random.randint(0, 24, n_samples),
    "failed_logins": np.random.poisson(1, n_samples),
    "success_logins": np.random.poisson(2, n_samples),
    "privileged_cmds": np.random.poisson(0.5, n_samples),
    "data_mb": np.random.exponential(10, n_samples).astype(int),
    "unique_ips": np.random.randint(1, 5, n_samples),
    "user_id": np.random.randint(1, 100, n_samples),
}

df = pd.DataFrame(data)

# Create labels: 0 = benign, 1 = malicious
# Simple rule for labeling: high failed_logins + privileged_cmds + high data_mb
malicious = (
    (df["failed_logins"] >= 3) &
    (df["privileged_cmds"] >= 1) &
    (df["data_mb"] > 50)
).astype(int)

# Add some noise
flip = np.random.rand(n_samples) < 0.02
malicious = np.where(flip, 1 - malicious, malicious)

df["label"] = malicious

# Save
out_dir = Path(__file__).parent / "datasets"
out_dir.mkdir(exist_ok=True)
df.to_csv(out_dir / "synthetic_logs.csv", index=False)
print(f"Generated {len(df)} samples, malicious ratio: {malicious.mean():.3f}")
print(f"Saved to {out_dir / 'synthetic_logs.csv'}")