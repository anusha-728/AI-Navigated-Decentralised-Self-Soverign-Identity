import requests
import time
from ssi_auth.crypto_utils import generate_keypair, sign_nonce

BASE_URL = "http://127.0.0.1:8000"

def run_integration_test():
    print("--- Starting End-to-End Framework Integration Test ---")
    
    # 1. Generate SSI Keys for Test Node
    node_keys = generate_keypair()
    node_id = "edge-node-01"
    
    # 2. Register Node
    reg_res = requests.post(f"{BASE_URL}/api/ssi/register", json={
        "node_id": node_id,
        "public_key_b64": node_keys["public_key"]
    })
    print("Registration Response:", reg_res.json())
    assert reg_res.status_code == 200
    
    # 3. Request Challenge Nonce
    chal_res = requests.post(f"{BASE_URL}/api/ssi/challenge", json={"node_id": node_id})
    nonce = chal_res.json()["nonce"]
    print(f"Received Nonce Challenge: {nonce}")
    
    # 4. Sign Nonce with Private Key (SSI Auth)
    signature = sign_nonce(node_keys["private_key"], nonce)
    
    # 5. Send Simulated Threat Telemetry (AI + Vulnerability Engine Test)
    start_time = time.time()
    telemetry_res = requests.post(f"{BASE_URL}/api/threat/analyze", json={
        "node_id": node_id,
        "nonce": nonce,
        "signature_b64": signature,
        "feature_vector": [0.85, 0.92, 0.78, 0.90, 0.88] # High anomaly vector
    })
    latency = (time.time() - start_time) * 1000
    
    print("Analysis Response:", telemetry_res.json())
    print(f"End-to-End Processing Latency: {latency:.2f} ms")
    assert telemetry_res.status_code == 200
    print("--- Integration Test Passed Successfully! ---")

if __name__ == "__main__":
    run_integration_test()