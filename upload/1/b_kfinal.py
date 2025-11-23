
import joblib
import pandas as pd
import numpy as np
from datetime import datetime
import hashlib
import json
import warnings
warnings.filterwarnings('ignore')

MODEL_PATH = "xgboost_zero_fn.pkl"



class Block:
    """A single block in the blockchain containing intrusion data"""
    def __init__(self, index, timestamp, data, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()
    
    def calculate_hash(self):
        """Calculate SHA-256 hash of the block contents"""
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash
        }, sort_keys=True, default=str)
        
        return hashlib.sha256(block_string.encode()).hexdigest()
    
    def to_dict(self):
        """Convert block to dictionary for export"""
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "hash": self.hash
        }


class ThreatLogBlockchain:
    """Blockchain to store immutable threat logs"""
    def __init__(self):
        self.chain = []
        self.create_genesis_block()
    
    def create_genesis_block(self):
        """Create the first block in the chain"""
        genesis_block = Block(
            index=0,
            timestamp=str(datetime.now()),
            data={
                "message": "Threat Log Blockchain Initialized",
                "system": "Network Intrusion Detection System"
            },
            previous_hash="0"
        )
        self.chain.append(genesis_block)
    
    def get_latest_block(self):
        return self.chain[-1]
    
    def add_intrusion_block(self, intrusion_data):
        """Add a new intrusion detection to the blockchain"""
        previous_block = self.get_latest_block()
        
        intrusion_data['blockchain_timestamp'] = str(datetime.now())
        intrusion_data['block_index'] = len(self.chain)
        
        new_block = Block(
            index=len(self.chain),
            timestamp=str(datetime.now()),
            data=intrusion_data,
            previous_hash=previous_block.hash
        )
        
        self.chain.append(new_block)
        return new_block
    
    def is_chain_valid(self):
        """Verify the integrity of the blockchain"""
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            
            if current_block.hash != current_block.calculate_hash():
                return False
            
            if current_block.previous_hash != previous_block.hash:
                return False
        
        return True
    
    def get_threat_count(self):
        return len(self.chain) - 1
    
    def get_severity_distribution(self):
        """Get distribution of threat severities"""
        severity_counts = {'LOW RISK': 0, 'MEDIUM RISK': 0, 'HIGH RISK': 0}
        
        for block in self.chain[1:]:
            severity = block.data.get('severity_name', 'Unknown')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        return severity_counts
    
    def export_to_json(self, filename=None):
        """Export blockchain to JSON file"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"blockchain_threat_log_{timestamp}.json"
        
        chain_data = {
            "blockchain_info": {
                "total_blocks": len(self.chain),
                "total_intrusions": self.get_threat_count(),
                "export_timestamp": str(datetime.now()),
                "is_valid": self.is_chain_valid()
            },
            "blocks": [block.to_dict() for block in self.chain]
        }
        
        with open(filename, 'w') as f:
            json.dump(chain_data, f, indent=2, default=str)
        
        return filename




SEVERITY_LEVELS = {
    0: {
        'name': 'NORMAL',
        'color': '[GREEN]',
        'priority': 'None',
        'description': 'Normal traffic, no threat detected'
    },
    1: {
        'name': 'LOW RISK',
        'color': '[YELLOW]',
        'priority': 'Low',
        'description': 'Suspicious activity detected, monitor'
    },
    2: {
        'name': 'MEDIUM RISK',
        'color': '[ORANGE]',
        'priority': 'Medium',
        'description': 'Likely intrusion, requires attention'
    },
    3: {
        'name': 'HIGH RISK',
        'color': '[RED]',
        'priority': 'High',
        'description': 'Confirmed intrusion, immediate action needed'
    }
}

def determine_severity_from_features(is_intrusion, network_features, prob=None, zero_fn_threshold=None):
    """
    Determine severity level based on feature values AND probability
    Returns: 0 (normal), 1 (low), 2 (medium), 3 (high)
    """
    if not is_intrusion:
        return 0
    
    # Extract features with defaults
    src_bytes = network_features.get('src_bytes', 0)
    dst_bytes = network_features.get('dst_bytes', 0)
    count = network_features.get('count', 0)
    serror_rate = network_features.get('serror_rate', 0)
    failed_logins = network_features.get('num_failed_logins', 0)
    dst_host_count = network_features.get('dst_host_count', 0)
    srv_count = network_features.get('srv_count', 0)
    duration = network_features.get('duration', 0)
    
    # Initialize severity score
    severity_score = 0
    
    # Check HIGH RISK indicators (score +3)
    if src_bytes > 100000:  # Very large data transfer
        severity_score += 3
    if count > 300:  # Many connections
        severity_score += 3
    if failed_logins > 5:  # Multiple failed logins
        severity_score += 3
    if serror_rate > 0.5:  # High error rate
        severity_score += 3
    if dst_host_count > 100:  # Scanning many hosts
        severity_score += 3
    
    # Check MEDIUM RISK indicators (score +2)
    if 50000 < src_bytes <= 100000:
        severity_score += 2
    if 100 < count <= 300:
        severity_score += 2
    if 3 < failed_logins <= 5:
        severity_score += 2
    if 0.3 < serror_rate <= 0.5:
        severity_score += 2
    if 50 < dst_host_count <= 100:
        severity_score += 2
    if srv_count > 20:
        severity_score += 2
    
    # Check LOW RISK indicators (score +1)
    if 10000 < src_bytes <= 50000:
        severity_score += 1
    if 20 < count <= 100:
        severity_score += 1
    if 1 < failed_logins <= 3:
        severity_score += 1
    if 0.1 < serror_rate <= 0.3:
        severity_score += 1
    if duration > 1000:
        severity_score += 1
    
    # Use probability as additional factor
    if prob is not None:
        if prob >= 0.9:  # Very high confidence
            severity_score += 3
        elif prob >= 0.7:  # High confidence
            severity_score += 2
        elif prob >= 0.5:  # Medium confidence
            severity_score += 1
    
    # Determine final severity level based on score
    if severity_score >= 8:
        severity = 3  # HIGH RISK
    elif severity_score >= 4:
        severity = 2  # MEDIUM RISK
    else:
        severity = 1  # LOW RISK
    
    return severity


def get_action_recommendations(severity, prob, network_features):
    """Generate specific action recommendations based on severity and features"""
    actions = {
        'severity': severity,
        'severity_name': SEVERITY_LEVELS[severity]['name'],
        'immediate_actions': [],
        'monitoring_actions': [],
        'logging_actions': [],
        'explanation': '',
        'action_summary': ''
    }
    
    if severity == 0:
        actions['immediate_actions'] = ['Allow this traffic to pass through normally']
        actions['logging_actions'] = ['Keep basic logs for record-keeping purposes']
        actions['explanation'] = 'This appears to be normal, legitimate network traffic.'
        actions['action_summary'] = 'Normal traffic - no action required.'
    
    elif severity == 1:
        actions['immediate_actions'] = [
            'Allow the traffic but keep a close watch on it',
            'Turn on detailed packet inspection'
        ]
        actions['monitoring_actions'] = [
            'Watch connection frequency over next 5 minutes',
            'Look for unusual patterns',
            'Track data volume'
        ]
        actions['logging_actions'] = [
            'Save complete connection details',
            'Store packet headers for analysis'
        ]
        actions['explanation'] = f'This traffic looks somewhat suspicious (we are {prob:.1%} confident it might be an intrusion).'
        actions['action_summary'] = f'LOW RISK: Monitor activity closely. Review logs and watch for patterns. Confidence: {prob:.1%}.'
    
    elif severity == 2:
        actions['immediate_actions'] = [
            'Mark this traffic for immediate security review',
            'Slow down or limit data from this source',
            'Activate intrusion detection systems'
        ]
        actions['monitoring_actions'] = [
            'Monitor this source IP in real-time',
            'Check security logs for previous activity',
            'Look up IP reputation online',
            'Review past 24 hours of traffic from this source'
        ]
        actions['logging_actions'] = [
            'Capture and save all packets',
            'Add to security database',
            'Create permanent audit log'
        ]
        actions['explanation'] = f'This is likely a real intrusion attempt ({prob:.1%} confident). Requires prompt attention.'
        actions['action_summary'] = f'MEDIUM RISK: Review immediately and monitor source. Likely intrusion with {prob:.1%} confidence. Check logs for similar activity.'
        
        if network_features.get('src_bytes', 0) > 10000:
            actions['monitoring_actions'].append('High outbound data - possible data theft')
            actions['action_summary'] += ' Large data transfer detected.'
        if network_features.get('count', 0) > 100:
            actions['monitoring_actions'].append('Many connections - possible network scan')
            actions['action_summary'] += ' Multiple connections detected.'
    
    elif severity == 3:
        actions['immediate_actions'] = [
            'BLOCK this source IP immediately',
            'Add IP to firewall blacklist',
            'Drop all packets from this source',
            'Cut off active connections'
        ]
        actions['monitoring_actions'] = [
            'Check if other IPs from same network are attacking',
            'Look for signs of system compromise',
            'Check if IP is part of known botnet',
            'Review all traffic from past 24 hours',
            'Identify targeted systems'
        ]
        actions['logging_actions'] = [
            'Capture everything for forensic analysis',
            'Save evidence in secure location',
            'Create detailed logs for legal proceedings',
            'Write full incident report'
        ]
        actions['explanation'] = f'This is a serious attack in progress ({prob:.1%} confident). Block immediately!'
        actions['action_summary'] = f'HIGH RISK - CRITICAL: Block source IP immediately! Serious attack detected with {prob:.1%} confidence. Initiate incident response.'
        
        if network_features.get('num_failed_logins', 0) > 5:
            actions['immediate_actions'].append('Lock user accounts - password guessing attack')
            actions['action_summary'] += ' Password attack in progress!'
        if network_features.get('src_bytes', 0) > 50000:
            actions['immediate_actions'].append('Large data transfer - investigate data theft')
            actions['action_summary'] += ' Possible data exfiltration!'
        if network_features.get('count', 0) > 200:
            actions['immediate_actions'].append('Block port scan - probing for weaknesses')
            actions['action_summary'] += ' Active port scanning detected!'
    
    return actions


def get_feature_context(network_features):
    """Get context based on network features"""
    context = []
    
    src_bytes = network_features.get('src_bytes', 0)
    dst_bytes = network_features.get('dst_bytes', 0)
    count = network_features.get('count', 0)
    serror_rate = network_features.get('serror_rate', 0)
    failed_logins = network_features.get('num_failed_logins', 0)
    dst_host_count = network_features.get('dst_host_count', 0)
    
    if src_bytes > 100000:
        context.append('Extremely large outbound data - possible major data theft or DDoS')
    elif src_bytes > 50000:
        context.append('Significant outbound data - might indicate data theft')
    
    if dst_bytes < 100 and src_bytes > 10000:
        context.append('One-sided traffic pattern - typical of data exfiltration')
    
    if count > 300:
        context.append('Hundreds of connections - automated port scanning or DoS attack')
    elif count > 100:
        context.append('Many rapid connections - automated scanning tools detected')
    
    if serror_rate > 0.5:
        context.append('High SYN error rate - telltale sign of SYN flood attack')
    
    if failed_logins > 3:
        context.append(f'{failed_logins} failed logins - password guessing attack')
    
    if dst_host_count > 100:
        context.append('Connecting to many hosts - worm spreading or lateral movement')
    
    return context



print("=" * 100)
print("INTELLIGENT INTRUSION DETECTION & RESPONSE SYSTEM WITH BLOCKCHAIN")
print("Real-Time Row-by-Row Analysis + Immediate Suggestions + Blockchain Logging")
print("=" * 100)

# Initialize Blockchain
print("\n[*] Initializing Blockchain Threat Log System...")
blockchain = ThreatLogBlockchain()
print(f"   Genesis Block Hash: {blockchain.chain[0].hash[:40]}...")

# Load Model
print(f"\n[*] Loading model from: {MODEL_PATH}")
try:
    saved = joblib.load(MODEL_PATH)
    model = saved["model"]
    scaler = saved["scaler"]
    feature_names = saved["feature_names"]
    numeric_features = saved["numeric_features"]
    categorical_features = saved["categorical_features"]
    zero_fn_threshold = saved["zero_fn_threshold"]
    
    print("\n[+] Model loaded successfully!")
    print(f"  * Zero-FN threshold: {zero_fn_threshold:.3f}")
    print(f"  * Numeric features: {len(numeric_features)}")
    print(f"  * Categorical features: {len(categorical_features)}")
    
except FileNotFoundError:
    print(f"\n[-] Error: Model file '{MODEL_PATH}' not found!")
    exit(1)
except Exception as e:
    print(f"\n[-] Error loading model: {e}")
    exit(1)

# Get Input File
print("\n" + "=" * 100)
print("INPUT FILE")
print("=" * 100)

while True:
    csv_path = input("\n[?] Enter path to CSV file (or press Enter for 'Test_data.csv'): ").strip()
    
    if csv_path == "":
        csv_path = "Test_data.csv"
    
    try:
        print(f"\n[*] Loading data from: {csv_path}")
        df = pd.read_csv(csv_path)
        print(f"[+] Loaded {len(df)} rows and {len(df.columns)} columns")
        break
    except FileNotFoundError:
        print(f"[-] File not found: {csv_path}")
        retry = input("   Try another file? (y/n): ").strip().lower()
        if retry != 'y':
            exit(1)
    except Exception as e:
        print(f"[-] Error reading file: {e}")
        retry = input("   Try another file? (y/n): ").strip().lower()
        if retry != 'y':
            exit(1)

# Preprocessing
print("\n" + "=" * 100)
print("DATA PREPROCESSING")
print("=" * 100)

has_labels = 'class' in df.columns
if has_labels:
    print("\n[+] Found 'class' column - will evaluate predictions")
    y_true = (df['class'] != 'normal').astype(int)
    X_new = df.drop(columns=['class'])
else:
    print("\n[!] No 'class' column found - prediction only mode")
    X_new = df.copy()
    y_true = None

X_original = X_new.copy()

if 'difficulty' in X_new.columns:
    X_new = X_new.drop(columns=['difficulty'])

original_features = numeric_features + categorical_features
missing_features = [f for f in original_features if f not in X_new.columns]

if missing_features:
    print(f"\n[!] {len(missing_features)} features missing - filling with 0")

for feat in missing_features:
    if feat in numeric_features:
        X_new[feat] = 0.0
    else:
        X_new[feat] = ""

X_new = X_new[original_features]
print(f"\n[+] Preprocessed data shape: {X_new.shape}")

# Encoding
print("\n[*] Applying one-hot encoding...")
X_encoded = pd.get_dummies(X_new, columns=categorical_features, drop_first=False)

for feat in feature_names:
    if feat not in X_encoded.columns:
        X_encoded[feat] = 0

X_encoded = X_encoded[feature_names]
print(f"[+] Encoded shape: {X_encoded.shape}")

# Scaling
print("\n[*] Scaling numeric features...")
numeric_cols_in_encoded = [c for c in X_encoded.columns if c in numeric_features]
X_encoded[numeric_cols_in_encoded] = scaler.transform(X_encoded[numeric_cols_in_encoded])
print(f"[+] Scaled {len(numeric_cols_in_encoded)} numeric features")

# Make Predictions
print("\n" + "=" * 100)
print("MAKING PREDICTIONS")
print("=" * 100)

print("\n[*] Predicting probabilities for all samples...")
y_proba = model.predict_proba(X_encoded)[:, 1]
y_pred = (y_proba >= zero_fn_threshold).astype(int)
print(f"[+] Predictions complete for {len(y_pred)} samples")



print("\n" + "=" * 100)
print("[*] STARTING ROW-BY-ROW INTRUSION ANALYSIS")
print("=" * 100)

intrusion_counter = 0
normal_counter = 0
all_results = []

print(f"\n[*] Processing {len(df)} samples...\n")

for idx in range(len(df)):
    # Get prediction for this row
    is_intrusion = (y_pred[idx] == 1)
    prob = y_proba[idx]
    
    # Extract network features
    network_features = {}
    key_features = ['duration', 'protocol_type', 'service', 'flag', 
                   'src_bytes', 'dst_bytes', 'count', 'srv_count',
                   'serror_rate', 'num_failed_logins', 'dst_host_count']
    for feat in key_features:
        if feat in X_original.columns:
            network_features[feat] = X_original.iloc[idx][feat]
    
    # Calculate severity
    severity = determine_severity_from_features(
        is_intrusion=is_intrusion,
        network_features=network_features,
        prob=prob,
        zero_fn_threshold=zero_fn_threshold
    )
    
    # Process based on result
    if is_intrusion and severity > 0:
        intrusion_counter += 1
        
        # Get detailed recommendations
        actions = get_action_recommendations(severity, prob, network_features)
        feature_context = get_feature_context(network_features)
        
        # Display immediate intrusion alert
        print("=" * 100)
        print(f"[!] INTRUSION DETECTED - Row Index: {idx}")
        print("=" * 100)
        
        print(f"\n{SEVERITY_LEVELS[severity]['color']} THREAT LEVEL: {actions['severity_name']}")
        print(f"   Intrusion Confidence: {prob:.1%}")
        print(f"   Priority: {SEVERITY_LEVELS[severity]['priority']}")
        
        print(f"\n[*] ANALYSIS:")
        print(f"   {actions['explanation']}")
        
        print(f"\n[!] IMMEDIATE ACTIONS REQUIRED:")
        for i, action in enumerate(actions['immediate_actions'][:3], 1):
            print(f"   {i}. {action}")
        
        if actions['monitoring_actions']:
            print(f"\n[*] MONITORING RECOMMENDATIONS:")
            for i, action in enumerate(actions['monitoring_actions'][:3], 1):
                print(f"   {i}. {action}")
        
        if feature_context:
            print(f"\n[*] SUSPICIOUS INDICATORS:")
            for ctx in feature_context[:3]:
                print(f"   * {ctx}")
        
        # Log to blockchain
        log_entry = {
            "sample_index": int(idx),
            "intrusion_probability": float(prob),
            "severity_level": int(severity),
            "severity_name": SEVERITY_LEVELS[severity]['name'],
            "priority": SEVERITY_LEVELS[severity]['priority'],
            "action_summary": actions['action_summary'],
            "immediate_actions": actions['immediate_actions'],
            "monitoring_actions": actions['monitoring_actions'][:3],
            "network_features": {k: float(v) if isinstance(v, (int, float, np.number)) else str(v) 
                                for k, v in network_features.items()}
        }
        
        block = blockchain.add_intrusion_block(log_entry)
        print(f"\n[+] Logged to Blockchain - Block #{block.index}")
        print(f"   Block Hash: {block.hash[:50]}...")
        print()
        
    else:
        normal_counter += 1
        if idx % 100 == 0:  # Print every 100 normal samples
            print(f"[+] Row {idx}: NORMAL TRAFFIC (Confidence: {(1-prob):.1%})")
    
    # Store result with action summary
    all_results.append({
        'index': idx,
        'is_intrusion': is_intrusion,
        'probability': prob,
        'severity': severity,
        'severity_name': SEVERITY_LEVELS[severity]['name'],
        'action_summary': get_action_recommendations(severity, prob, network_features)['action_summary'] if is_intrusion else 'Normal traffic'
    })



print("\n" + "=" * 100)
print("[*] COMPLETE ANALYSIS SUMMARY")
print("=" * 100)

print(f"\n[*] DETECTION RESULTS:")
print(f"   * Total Samples Processed: {len(df)}")
print(f"   * Normal Traffic: {normal_counter} ({normal_counter/len(df)*100:.1f}%)")
print(f"   * Intrusions Detected: {intrusion_counter} ({intrusion_counter/len(df)*100:.1f}%)")

print(f"\n[*] SEVERITY BREAKDOWN:")
for level in range(4):
    count = sum(1 for r in all_results if r['severity'] == level)
    pct = count / len(all_results) * 100
    print(f"   {SEVERITY_LEVELS[level]['color']} {SEVERITY_LEVELS[level]['name']}: {count} ({pct:.1f}%)")

# Evaluation
if has_labels:
    print("\n" + "=" * 100)
    print("[*] MODEL PERFORMANCE EVALUATION")
    print("=" * 100)
    
    from sklearn.metrics import confusion_matrix, accuracy_score, roc_auc_score
    
    cm = confusion_matrix(y_true, y_pred)
    accuracy = accuracy_score(y_true, y_pred)
    auc = roc_auc_score(y_true, y_proba)
    
    print(f"\n[*] Confusion Matrix:")
    print(f"                Predicted Normal    Predicted Intrusion")
    print(f"Actual Normal        {cm[0,0]:<15} {cm[0,1]:<15}")
    print(f"Actual Intrusion     {cm[1,0]:<15} {cm[1,1]:<15}")
    
    print(f"\n[*] Metrics:")
    print(f"   * Accuracy: {accuracy:.4f}")
    print(f"   * ROC-AUC: {auc:.4f}")
    print(f"   * False Negatives: {cm[1,0]}")
    print(f"   * True Positives: {cm[1,1]}")

# Save Results
print("\n" + "=" * 100)
print("[*] SAVING RESULTS")
print("=" * 100)

results_df = df.copy()
results_df['intrusion_probability'] = y_proba
results_df['predicted_class'] = ['intrusion' if p == 1 else 'normal' for p in y_pred]
results_df['severity_level'] = [r['severity'] for r in all_results]
results_df['severity_name'] = [r['severity_name'] for r in all_results]
results_df['action_summary'] = [r['action_summary'] for r in all_results]

timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
output_file = f"predictions_with_actions_{timestamp}.csv"
results_df.to_csv(output_file, index=False)
print(f"\n[+] Predictions CSV saved: {output_file}")

# Export blockchain
blockchain_file = blockchain.export_to_json()
print(f"[+] Blockchain JSON saved: {blockchain_file}")

# Final Summary
print("\n" + "=" * 100)
print("[+] ANALYSIS COMPLETE")
print("=" * 100)

print(f"""
[*] Input File: {csv_path}
[*] Rows Processed: {len(df)}
[*] Detection Threshold: {zero_fn_threshold:.3f}

RESULTS:
  [GREEN] Normal Traffic: {normal_counter}
  [RED] Intrusions: {intrusion_counter}

BLOCKCHAIN:
  [*] Intrusions Logged: {blockchain.get_threat_count()}
  [*] Integrity: {'VALID' if blockchain.is_chain_valid() else 'COMPROMISED'}
  [*] Total Blocks: {len(blockchain.chain)}

FILES SAVED:
  * {output_file}
  * {blockchain_file}
""")

print("=" * 100)
print("[+] ALL ROWS PROCESSED - BLOCKCHAIN SECURE")
print("=" * 100)