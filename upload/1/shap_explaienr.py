
import joblib
import pandas as pd
import numpy as np
import shap
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

MODEL_PATH = "xgboost_zero_fn.pkl"

print("=" * 90)
print("ADVANCED EXPLAINABLE AI (XAI) FOR INTRUSION DETECTION")
print("SHAP + Feature Importance + Network Analysis")
print("=" * 90)


print(f"\n Loading model from: {MODEL_PATH}")
try:
    saved = joblib.load(MODEL_PATH)
    model = saved["model"]
    scaler = saved["scaler"]
    feature_names = saved["feature_names"]
    numeric_features = saved["numeric_features"]
    categorical_features = saved["categorical_features"]
    zero_fn_threshold = saved["zero_fn_threshold"]
    
    print(" Model loaded successfully!")
    print(f"  • Threshold: {zero_fn_threshold:.3f}")
    print(f"  • Total features: {len(feature_names)}")
    print(f"  • XGBoost configuration: {saved.get('model_config', {})}")
except Exception as e:
    print(f" Error loading model: {e}")
    exit(1)


print("\n" + "=" * 90)
print("LOAD DATA FOR EXPLANATION")
print("=" * 90)

while True:
    csv_path = input("\n Enter CSV file path (or Enter for 'Test_data.csv'): ").strip()
    if csv_path == "":
        csv_path = "Test_data.csv"
    
    try:
        print(f"\n Loading: {csv_path}")
        df = pd.read_csv(csv_path)
        print(f" Loaded {len(df)} rows and {len(df.columns)} columns")
        break
    except FileNotFoundError:
        print(f" File not found: {csv_path}")
        if input("Try again? (y/n): ").lower() != 'y':
            exit(1)


print("\n Preprocessing data...")

has_labels = 'class' in df.columns
if has_labels:
    y_true = (df['class'] != 'normal').astype(int)
    X_new = df.drop(columns=['class'])
else:
    X_new = df.copy()
    y_true = None

if 'difficulty' in X_new.columns:
    X_new = X_new.drop(columns=['difficulty'])

# Store original data for analysis
X_original = X_new.copy()

# Add missing features
original_features = numeric_features + categorical_features
for feat in original_features:
    if feat not in X_new.columns:
        X_new[feat] = 0.0 if feat in numeric_features else ""

X_new = X_new[original_features]

# One-hot encoding
X_encoded = pd.get_dummies(X_new, columns=categorical_features, drop_first=False)
for feat in feature_names:
    if feat not in X_encoded.columns:
        X_encoded[feat] = 0
X_encoded = X_encoded[feature_names]

# Scaling
numeric_cols = [c for c in X_encoded.columns if c in numeric_features]
X_encoded[numeric_cols] = scaler.transform(X_encoded[numeric_cols])

print(f" Preprocessed shape: {X_encoded.shape}")

print("\n Making predictions...")
y_proba = model.predict_proba(X_encoded)[:, 1]
y_pred = (y_proba >= zero_fn_threshold).astype(int)

intrusion_count = (y_pred == 1).sum()
normal_count = (y_pred == 0).sum()
print(f" Predictions complete:")
print(f"   • Intrusions detected: {intrusion_count}")
print(f"   • Normal traffic: {normal_count}")


print("\n" + "=" * 90)
print("INITIALIZING EXPLAINABLE AI COMPONENTS")
print("=" * 90)

print("\n Creating SHAP TreeExplainer (exact for XGBoost)...")
explainer = shap.TreeExplainer(model)

print(" Computing SHAP values for all samples (this may take 30-60 seconds)...")
shap_values = explainer.shap_values(X_encoded)

print(f" SHAP values computed!")
print(f"  • Shape: {shap_values.shape}")
print(f"  • Base value (expected): {explainer.expected_value:.4f}")

# Get XGBoost native feature importance
xgb_importance = model.feature_importances_
feature_importance_df = pd.DataFrame({
    'feature': feature_names,
    'xgb_importance': xgb_importance,
    'mean_abs_shap': np.abs(shap_values).mean(axis=0)
}).sort_values('mean_abs_shap', ascending=False)

print(f"\n Feature importance calculated using:")
print(f"   • XGBoost native importance (Gain)")
print(f"   • SHAP values (impact on predictions)")


NETWORK_FEATURE_CATEGORIES = {
    'Basic Flow Features': ['duration', 'protocol_type', 'service', 'flag'],
    'Traffic Volume': ['src_bytes', 'dst_bytes', 'land'],
    'Connection Metrics': ['wrong_fragment', 'urgent', 'hot', 'num_failed_logins'],
    'Time-based Features': ['count', 'srv_count', 'serror_rate', 'srv_serror_rate',
                           'rerror_rate', 'srv_rerror_rate'],
    'Host-based Features': ['dst_host_count', 'dst_host_srv_count', 
                           'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
                           'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
                           'dst_host_serror_rate', 'dst_host_srv_serror_rate',
                           'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'],
    'Content Features': ['num_compromised', 'root_shell', 'su_attempted', 
                        'num_root', 'num_file_creations', 'num_shells',
                        'num_access_files', 'is_guest_login', 'is_host_login',
                        'num_outbound_cmds']
}

def get_category(feature_name):
    """Get category for a feature"""
    for category, features in NETWORK_FEATURE_CATEGORIES.items():
        if any(feat in feature_name for feat in features):
            return category
    return 'Other/Encoded'

# Add categories to feature importance
feature_importance_df['category'] = feature_importance_df['feature'].apply(get_category)



def explain_single_sample_advanced(sample_idx):
    """Advanced explanation with network feature analysis"""
    if sample_idx < 0 or sample_idx >= len(df):
        print(f" Invalid index. Must be 0-{len(df)-1}")
        return
    
    print("\n" + "=" * 90)
    print(f"ADVANCED XAI EXPLANATION - Sample {sample_idx}")
    print("=" * 90)
    
    # Prediction info
    prob = y_proba[sample_idx]
    pred = y_pred[sample_idx]
    pred_label = " INTRUSION" if pred == 1 else " NORMAL"
    
    print(f"\n PREDICTION DETAILS:")
    print(f"  • Classification: {pred_label}")
    print(f"  • Intrusion Probability: {prob:.4f} ({prob*100:.2f}%)")
    print(f"  • Decision Threshold: {zero_fn_threshold:.3f}")
    print(f"  • Confidence Level: {' HIGH' if prob >= 0.7 else '🟡 MEDIUM' if prob >= zero_fn_threshold else '🟢 LOW'}")
    
    if has_labels:
        actual = " INTRUSION" if y_true.iloc[sample_idx] == 1 else " NORMAL"
        correct = " CORRECT" if pred == y_true.iloc[sample_idx] else " INCORRECT"
        print(f"  • Actual Label: {actual}")
        print(f"  • Prediction Status: {correct}")
    
    # SHAP explanation
    sample_shap = shap_values[sample_idx]
    base_value = explainer.expected_value
    
    print(f"\n SHAP VALUE ANALYSIS:")
    print(f"  • Base value (population average): {base_value:.4f}")
    print(f"  • Total SHAP contribution: {sample_shap.sum():.4f}")
    print(f"  • Final model output: {base_value + sample_shap.sum():.4f}")
    print(f"  • After sigmoid: {prob:.4f}")
    
    # Feature contributions
    feature_contributions = pd.DataFrame({
        'feature': feature_names,
        'shap_value': sample_shap,
        'feature_value': X_encoded.iloc[sample_idx].values,
        'abs_shap': np.abs(sample_shap)
    })
    
    # Get original values for key network features
    original_values = {}
    for feat in numeric_features:
        if feat in X_original.columns:
            original_values[feat] = X_original.iloc[sample_idx][feat]
    
    # Show network features analysis
    print(f"\n KEY NETWORK FEATURES (Original Values):")
    print("-" * 90)
    key_features = ['duration', 'src_bytes', 'dst_bytes', 'count', 'srv_count']
    for feat in key_features:
        if feat in original_values:
            # Find SHAP value for this feature
            shap_val = sample_shap[feature_names.index(feat)] if feat in feature_names else 0
            print(f"  • {feat:<20}: {original_values[feat]:<15.2f} (SHAP impact: {shap_val:+.4f})")
    
    feature_contributions['category'] = feature_contributions['feature'].apply(get_category)
    sorted_contrib = feature_contributions.sort_values('abs_shap', ascending=False)
    
    print(f"\n TOP 15 FEATURES PUSHING TOWARD INTRUSION:")
    print("-" * 90)
    print(f"{'Feature':<35} {'Category':<25} {'SHAP Value':>12} {'Feature Value':>15}")
    print("-" * 90)
    
    top_intrusion = sorted_contrib[sorted_contrib['shap_value'] > 0].head(15)
    for idx, row in top_intrusion.iterrows():
        # Get original value if available
        orig_val = ""
        base_feat = row['feature'].split('_')[0] if '_' in row['feature'] else row['feature']
        if base_feat in original_values:
            orig_val = f"{original_values[base_feat]:.2f}"
        elif row['feature'] in numeric_features:
            orig_val = f"{row['feature_value']:.2f}"
        else:
            orig_val = str(row['feature_value'])
        
        print(f"{row['feature']:<35} {row['category']:<25} {row['shap_value']:>+12.4f} {orig_val:>15}")
    
    print(f"\n🟢 TOP 15 FEATURES PUSHING TOWARD NORMAL:")
    print("-" * 90)
    print(f"{'Feature':<35} {'Category':<25} {'SHAP Value':>12} {'Feature Value':>15}")
    print("-" * 90)
    
    top_normal = sorted_contrib[sorted_contrib['shap_value'] < 0].head(15)
    for idx, row in top_normal.iterrows():
        orig_val = ""
        base_feat = row['feature'].split('_')[0] if '_' in row['feature'] else row['feature']
        if base_feat in original_values:
            orig_val = f"{original_values[base_feat]:.2f}"
        elif row['feature'] in numeric_features:
            orig_val = f"{row['feature_value']:.2f}"
        else:
            orig_val = str(row['feature_value'])
        
        print(f"{row['feature']:<35} {row['category']:<25} {row['shap_value']:>+12.4f} {orig_val:>15}")
    
    # Category-wise contribution
    print(f"\n CONTRIBUTION BY NETWORK FEATURE CATEGORY:")
    print("-" * 90)
    category_contrib = feature_contributions.groupby('category')['shap_value'].sum().sort_values(ascending=False)
    for cat, contrib in category_contrib.items():
        direction = "→ Intrusion" if contrib > 0 else "→ Normal"
        print(f"  {cat:<30} {contrib:>+10.4f}  {direction}")
    
    # Generate visualizations
    print(f"\n Generating visualizations...")
    
    # 1. Waterfall plot
    plt.figure(figsize=(12, 10))
    shap.waterfall_plot(shap.Explanation(
        values=sample_shap,
        base_values=base_value,
        data=X_encoded.iloc[sample_idx].values,
        feature_names=feature_names
    ), max_display=20, show=False)
    plt.title(f'SHAP Waterfall Plot - Sample {sample_idx}\n{pred_label} (Probability: {prob:.4f})', 
              fontsize=14, fontweight='bold')
    plot_file = f"shap_waterfall_sample_{sample_idx}.png"
    plt.tight_layout()
    plt.savefig(plot_file, dpi=150, bbox_inches='tight')
    plt.close()
    print(f" Saved: {plot_file}")
    
    # 2. Force plot
    shap.force_plot(
        base_value,
        sample_shap,
        X_encoded.iloc[sample_idx],
        feature_names=feature_names,
        matplotlib=True,
        show=False
    )
    force_file = f"shap_force_sample_{sample_idx}.png"
    plt.savefig(force_file, dpi=150, bbox_inches='tight')
    plt.close()
    print(f" Saved: {force_file}")
    
    # 3. Category contribution pie chart
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 7))
    
    # Positive contributions
    positive_contrib = category_contrib[category_contrib > 0]
    if len(positive_contrib) > 0:
        ax1.pie(positive_contrib.values, labels=positive_contrib.index, autopct='%1.1f%%',
                startangle=90, colors=plt.cm.Reds(np.linspace(0.3, 0.8, len(positive_contrib))))
        ax1.set_title('Features Pushing Toward INTRUSION', fontweight='bold', fontsize=12)
    
    # Negative contributions
    negative_contrib = category_contrib[category_contrib < 0].abs()
    if len(negative_contrib) > 0:
        ax2.pie(negative_contrib.values, labels=negative_contrib.index, autopct='%1.1f%%',
                startangle=90, colors=plt.cm.Greens(np.linspace(0.3, 0.8, len(negative_contrib))))
        ax2.set_title('Features Pushing Toward NORMAL', fontweight='bold', fontsize=12)
    
    plt.suptitle(f'Feature Category Contribution - Sample {sample_idx}', 
                 fontsize=14, fontweight='bold', y=1.02)
    category_file = f"category_contribution_sample_{sample_idx}.png"
    plt.tight_layout()
    plt.savefig(category_file, dpi=150, bbox_inches='tight')
    plt.close()
    print(f" Saved: {category_file}")

def show_global_importance_advanced():
    """Advanced global feature importance with network analysis"""
    print("\n" + "=" * 90)
    print("GLOBAL FEATURE IMPORTANCE - NETWORK PERSPECTIVE")
    print("=" * 90)
    
    print("\n TOP 30 MOST IMPORTANT FEATURES (Combined XGBoost + SHAP):")
    print("-" * 90)
    print(f"{'Rank':<6} {'Feature':<35} {'Category':<25} {'SHAP':>12} {'XGB':>12}")
    print("-" * 90)
    
    top_features = feature_importance_df.head(30)
    for rank, (idx, row) in enumerate(top_features.iterrows(), 1):
        print(f"{rank:<6} {row['feature']:<35} {row['category']:<25} "
              f"{row['mean_abs_shap']:>12.6f} {row['xgb_importance']:>12.6f}")
    
    # Category-wise importance
    print(f"\n IMPORTANCE BY NETWORK FEATURE CATEGORY:")
    print("-" * 90)
    category_importance = feature_importance_df.groupby('category').agg({
        'mean_abs_shap': 'sum',
        'xgb_importance': 'sum',
        'feature': 'count'
    }).sort_values('mean_abs_shap', ascending=False)
    category_importance.columns = ['Total_SHAP', 'Total_XGB', 'Feature_Count']
    
    print(f"{'Category':<30} {'# Features':>12} {'SHAP Score':>15} {'XGB Score':>15}")
    print("-" * 90)
    for cat, row in category_importance.iterrows():
        print(f"{cat:<30} {int(row['Feature_Count']):>12} "
              f"{row['Total_SHAP']:>15.6f} {row['Total_XGB']:>15.6f}")
    
    # Generate visualizations
    print(f"\n Generating global importance visualizations...")
    
    # 1. Top features bar plot (combined)
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(18, 10))
    
    top_25 = feature_importance_df.head(25)
    
    # SHAP importance
    ax1.barh(range(len(top_25)), top_25['mean_abs_shap'], color='steelblue')
    ax1.set_yticks(range(len(top_25)))
    ax1.set_yticklabels(top_25['feature'])
    ax1.set_xlabel('Mean Absolute SHAP Value', fontsize=11)
    ax1.set_title('SHAP Feature Importance\n(Impact on Predictions)', fontsize=12, fontweight='bold')
    ax1.invert_yaxis()
    ax1.grid(axis='x', alpha=0.3)
    
    # XGBoost importance
    ax2.barh(range(len(top_25)), top_25['xgb_importance'], color='coral')
    ax2.set_yticks(range(len(top_25)))
    ax2.set_yticklabels(top_25['feature'])
    ax2.set_xlabel('XGBoost Importance (Gain)', fontsize=11)
    ax2.set_title('XGBoost Native Importance\n(Information Gain)', fontsize=12, fontweight='bold')
    ax2.invert_yaxis()
    ax2.grid(axis='x', alpha=0.3)
    
    plt.tight_layout()
    plt.savefig('global_feature_importance_comparison.png', dpi=150, bbox_inches='tight')
    plt.close()
    print(f" Saved: global_feature_importance_comparison.png")
    
    # 2. Category importance
    plt.figure(figsize=(12, 8))
    categories = category_importance.index
    x = np.arange(len(categories))
    width = 0.35
    
    plt.barh(x - width/2, category_importance['Total_SHAP'], width, 
             label='SHAP Importance', color='steelblue', alpha=0.8)
    plt.barh(x + width/2, category_importance['Total_XGB'], width, 
             label='XGBoost Importance', color='coral', alpha=0.8)
    
    plt.yticks(x, categories)
    plt.xlabel('Importance Score', fontsize=12)
    plt.title('Feature Category Importance - Network Analysis', fontsize=14, fontweight='bold')
    plt.legend(fontsize=11)
    plt.gca().invert_yaxis()
    plt.grid(axis='x', alpha=0.3)
    plt.tight_layout()
    plt.savefig('category_importance.png', dpi=150, bbox_inches='tight')
    plt.close()
    print(f" Saved: category_importance.png")
    
    # 3. SHAP beeswarm plot
    plt.figure(figsize=(12, 10))
    shap.summary_plot(
        shap_values,
        X_encoded,
        feature_names=feature_names,
        max_display=25,
        show=False
    )
    plt.title('SHAP Summary Plot - Feature Impact Distribution', fontsize=14, fontweight='bold', pad=20)
    plt.tight_layout()
    plt.savefig('shap_beeswarm_plot.png', dpi=150, bbox_inches='tight')
    plt.close()
    print(f" Saved: shap_beeswarm_plot.png")
    
    # 4. SHAP bar plot
    plt.figure(figsize=(12, 10))
    shap.summary_plot(
        shap_values,
        X_encoded,
        feature_names=feature_names,
        plot_type="bar",
        max_display=25,
        show=False
    )
    plt.title('SHAP Bar Plot - Mean Feature Importance', fontsize=14, fontweight='bold', pad=20)
    plt.tight_layout()
    plt.savefig('shap_bar_plot.png', dpi=150, bbox_inches='tight')
    plt.close()
    print(f" Saved: shap_bar_plot.png")

def explain_intrusions_with_network_features():
    """Explain intrusions with focus on network features"""
    intrusion_indices = np.where(y_pred == 1)[0]
    
    if len(intrusion_indices) == 0:
        print("\n No intrusions detected in this dataset")
        return
    
    print("\n" + "=" * 90)
    print(f"INTRUSION ANALYSIS - NETWORK FEATURE PERSPECTIVE")
    print(f"{len(intrusion_indices)} Intrusions Detected")
    print("=" * 90)
    
    intrusion_shap = shap_values[intrusion_indices]
    
    # Feature importance for intrusions
    intrusion_importance = pd.DataFrame({
        'feature': feature_names,
        'mean_abs_shap': np.abs(intrusion_shap).mean(axis=0),
        'mean_shap': intrusion_shap.mean(axis=0)
    })
    intrusion_importance['category'] = intrusion_importance['feature'].apply(get_category)
    intrusion_importance = intrusion_importance.sort_values('mean_abs_shap', ascending=False)
    
    print("\n TOP 25 FEATURES FOR INTRUSION DETECTION:")
    print("-" * 90)
    print(f"{'Rank':<6} {'Feature':<35} {'Category':<25} {'Avg SHAP':>15}")
    print("-" * 90)
    
    for rank, (idx, row) in enumerate(intrusion_importance.head(25).iterrows(), 1):
        print(f"{rank:<6} {row['feature']:<35} {row['category']:<25} {row['mean_shap']:>+15.6f}")
    
    # Network feature analysis
    print(f"\n KEY NETWORK FEATURES IN INTRUSIONS:")
    print("-" * 90)
    
    key_network_features = ['duration', 'src_bytes', 'dst_bytes', 'count', 'srv_count',
                           'serror_rate', 'srv_serror_rate', 'dst_host_count']
    
    for feat in key_network_features:
        if feat in X_original.columns:
            intrusion_values = X_original.iloc[intrusion_indices][feat]
            if feat in feature_names:
                feat_idx = feature_names.index(feat)
                avg_shap = intrusion_shap[:, feat_idx].mean()
                
                print(f"\n  {feat.upper()}:")
                print(f"    • Mean value: {intrusion_values.mean():.2f}")
                print(f"    • Median value: {intrusion_values.median():.2f}")
                print(f"    • Std dev: {intrusion_values.std():.2f}")
                print(f"    • Min-Max: [{intrusion_values.min():.2f}, {intrusion_values.max():.2f}]")
                print(f"    • Avg SHAP impact: {avg_shap:+.6f}")
    
    # Category analysis for intrusions
    print(f"\n CATEGORY IMPORTANCE FOR INTRUSIONS:")
    print("-" * 90)
    category_intrusion = intrusion_importance.groupby('category').agg({
        'mean_abs_shap': 'sum',
        'feature': 'count'
    }).sort_values('mean_abs_shap', ascending=False)
    category_intrusion.columns = ['Total_Impact', 'Feature_Count']
    
    for cat, row in category_intrusion.iterrows():
        print(f"  {cat:<30} {int(row['Feature_Count']):>5} features, "
              f"Total impact: {row['Total_Impact']:.6f}")
    
    # Generate intrusion-specific visualizations
    print(f"\n Generating intrusion analysis plots...")
    
    # Summary plot for intrusions only
    plt.figure(figsize=(12, 10))
    shap.summary_plot(
        intrusion_shap,
        X_encoded.iloc[intrusion_indices],
        feature_names=feature_names,
        max_display=25,
        show=False
    )
    plt.title(f'SHAP Summary - Intrusion Traffic Only ({len(intrusion_indices)} samples)', 
              fontsize=14, fontweight='bold', pad=20)
    plt.tight_layout()
    plt.savefig('shap_intrusions_summary.png', dpi=150, bbox_inches='tight')
    plt.close()
    print(f" Saved: shap_intrusions_summary.png")
    
    # Top intrusions
    print(f"\n TOP 10 HIGHEST CONFIDENCE INTRUSIONS:")
    print("-" * 90)
    top_intrusion_idx = intrusion_indices[np.argsort(y_proba[intrusion_indices])[-10:][::-1]]
    for rank, idx in enumerate(top_intrusion_idx, 1):
        print(f"{rank:>2}. Sample {idx:<6}  Probability: {y_proba[idx]:.4f}  ", end="")
        
        # Show top contributing feature
        sample_shap = shap_values[idx]
        top_feat_idx = np.argmax(np.abs(sample_shap))
        top_feat = feature_names[top_feat_idx]
        print(f"Top feature: {top_feat} (SHAP: {sample_shap[top_feat_idx]:+.4f})")

def compare_intrusion_vs_normal_advanced():
    """Advanced comparison with network feature focus"""
    print("\n" + "=" * 90)
    print("COMPARISON: INTRUSION vs NORMAL TRAFFIC")
    print("Network Feature Analysis")
    print("=" * 90)
    
    intrusion_idx = np.where(y_pred == 1)[0]
    normal_idx = np.where(y_pred == 0)[0]
    
    if len(intrusion_idx) == 0 or len(normal_idx) == 0:
        print("\n Need both intrusions and normal traffic for comparison")
        return
    
    # SHAP comparison
    intrusion_mean_shap = shap_values[intrusion_idx].mean(axis=0)
    normal_mean_shap = shap_values[normal_idx].mean(axis=0)
    
    comparison = pd.DataFrame({
        'feature': feature_names,
        'intrusion_shap': intrusion_mean_shap,
        'normal_shap': normal_mean_shap,
        'difference': intrusion_mean_shap - normal_mean_shap,
        'abs_difference': np.abs(intrusion_mean_shap - normal_mean_shap)
    })
    comparison['category'] = comparison['feature'].apply(get_category)
    comparison = comparison.sort_values('abs_difference', ascending=False)
    
    print(f"\n TOP 20 MOST DISTINGUISHING FEATURES:")
    print("-" * 90)
    print(f"{'Rank':<6} {'Feature':<30} {'Category':<20} {'Intrusion':>12} {'Normal':>12} {'Diff':>12}")
    print("-" * 90)
    
    for rank, (idx, row) in enumerate(comparison.head(20).iterrows(), 1):
        print(f"{rank:<6} {row['feature']:<30} {row['category']:<20} "
              f"{row['intrusion_shap']:>+12.6f} {row['normal_shap']:>+12.6f} {row['difference']:>+12.6f}")
    
    # Network feature comparison
    print(f"\n KEY NETWORK FEATURES COMPARISON:")
    print("-" * 90)
    
    key_features = ['duration', 'src_bytes', 'dst_bytes', 'count', 'srv_count']
    for feat in key_features:
        if feat in X_original.columns:
            intrusion_vals = X_original.iloc[intrusion_idx][feat]
            normal_vals = X_original.iloc[normal_idx][feat]
            
            if feat in feature_names:
                feat_idx = feature_names.index(feat)
                intrusion_shap = shap_values[intrusion_idx, feat_idx].mean()
                normal_shap = shap_values[normal_idx, feat_idx].mean()
                
                print(f"\n  {feat.upper()}:")
                print(f"    Intrusion: Mean={intrusion_vals.mean():.2f}, Median={intrusion_vals.median():.2f}, SHAP={intrusion_shap:+.6f}")
                print(f"    Normal:    Mean={normal_vals.mean():.2f}, Median={normal_vals.median():.2f}, SHAP={normal_shap:+.6f}")
                print(f"    Difference: {(intrusion_vals.mean() - normal_vals.mean()):.2f} (value), {(intrusion_shap - normal_shap):+.6f} (SHAP)")
    
    # Generate comparison visualizations
    print(f"\n Generating comparison plots...")
    
    # Side-by-side comparison
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(18, 10))
    
    top_20 = comparison.head(20)
    x = np.arange(len(top_20))
    width = 0.35
    
    ax1.barh(x - width/2, top_20['intrusion_shap'], width, label='Intrusion', color='red', alpha=0.7)
    ax1.barh(x + width/2, top_20['normal_shap'], width, label='Normal', color='green', alpha=0.7)
    ax1.set_yticks(x)
    ax1.set_yticklabels(top_20['feature'])
    ax1.set_xlabel('Mean SHAP Value', fontsize=11)
    ax1.set_title('Feature Importance: Intrusion vs Normal', fontsize=12, fontweight='bold')
    ax1.legend(fontsize=10)
    ax1.invert_yaxis()
    ax1.grid(axis='x', alpha=0.3)
    
    # Difference plot
    colors = ['red' if d > 0 else 'green' for d in top_20['difference']]
    ax2.barh(x, top_20['difference'], color=colors, alpha=0.7)
    ax2.set_yticks(x)
    ax2.set_yticklabels(top_20['feature'])
    ax2.set_xlabel('SHAP Difference (Intrusion - Normal)', fontsize=11)
    ax2.set_title('Distinguishing Features', fontsize=12, fontweight='bold')
    ax2.axvline(x=0, color='black', linestyle='-', linewidth=0.8)
    ax2.invert_yaxis()
    ax2.grid(axis='x', alpha=0.3)
    
    plt.tight_layout()
    plt.savefig('intrusion_vs_normal_comparison.png', dpi=150, bbox_inches='tight')
    plt.close()
    print(f" Saved: intrusion_vs_normal_comparison.png")

def export_advanced_explanations():
    """Export comprehensive XAI analysis to CSV"""
    print("\n" + "=" * 90)
    print("EXPORTING ADVANCED XAI ANALYSIS")
    print("=" * 90)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # 1. Main predictions with SHAP values
    explanations_df = df.copy()
    explanations_df['prediction'] = ['intrusion' if p == 1 else 'normal' for p in y_pred]
    explanations_df['probability'] = y_proba
    explanations_df['confidence'] = ['high' if p >= 0.7 else 'medium' if p >= zero_fn_threshold else 'low' 
                                     for p in y_proba]
    
    # Add top 15 SHAP values
    top_15_idx = np.argsort(np.abs(shap_values).mean(axis=0))[-15:][::-1]
    for idx in top_15_idx:
        feature_name = feature_names[idx]
        safe_name = feature_name.replace('/', '_').replace(' ', '_')
        explanations_df[f'shap_{safe_name}'] = shap_values[:, idx]
    
    explanations_df['total_shap'] = shap_values.sum(axis=1)
    
    output_file = f"xai_predictions_{timestamp}.csv"
    explanations_df.to_csv(output_file, index=False)
    print(f"\n Exported predictions with SHAP: {output_file}")
    print(f"   • {len(explanations_df)} samples")
    print(f"   • Top 15 SHAP features included")
    
    # 2. Complete feature importance ranking
    complete_importance = feature_importance_df.copy()
    complete_importance['rank'] = range(1, len(complete_importance) + 1)
    
    importance_file = f"feature_importance_complete_{timestamp}.csv"
    complete_importance.to_csv(importance_file, index=False)
    print(f" Exported complete feature importance: {importance_file}")
    
    # 3. Network feature analysis
    network_analysis = []
    for feat in numeric_features:
        if feat in X_original.columns:
            intrusion_idx = np.where(y_pred == 1)[0]
            normal_idx = np.where(y_pred == 0)[0]
            
            if len(intrusion_idx) > 0 and len(normal_idx) > 0:
                intrusion_vals = X_original.iloc[intrusion_idx][feat]
                normal_vals = X_original.iloc[normal_idx][feat]
                
                network_analysis.append({
                    'feature': feat,
                    'category': get_category(feat),
                    'intrusion_mean': intrusion_vals.mean(),
                    'intrusion_median': intrusion_vals.median(),
                    'intrusion_std': intrusion_vals.std(),
                    'normal_mean': normal_vals.mean(),
                    'normal_median': normal_vals.median(),
                    'normal_std': normal_vals.std(),
                    'mean_difference': intrusion_vals.mean() - normal_vals.mean()
                })
    
    network_df = pd.DataFrame(network_analysis)
    network_file = f"network_feature_analysis_{timestamp}.csv"
    network_df.to_csv(network_file, index=False)
    print(f" Exported network feature analysis: {network_file}")
    
    # 4. Category-wise summary
    category_summary = feature_importance_df.groupby('category').agg({
        'mean_abs_shap': ['sum', 'mean', 'count'],
        'xgb_importance': ['sum', 'mean']
    }).round(6)
    category_summary.columns = ['_'.join(col).strip() for col in category_summary.columns.values]
    category_summary = category_summary.sort_values('mean_abs_shap_sum', ascending=False)
    
    category_file = f"category_importance_summary_{timestamp}.csv"
    category_summary.to_csv(category_file)
    print(f" Exported category summary: {category_file}")
    
    print(f"\n Total files exported: 4")

def interactive_network_search():
    """Interactive search focused on network features"""
    print("\n" + "=" * 90)
    print("INTERACTIVE NETWORK FEATURE SEARCH")
    print("=" * 90)
    
    print("\nSearch options:")
    print("1. Find samples by specific network feature value")
    print("2. Show samples with highest SHAP for a feature")
    print("3. Compare two samples side-by-side")
    print("4. Find anomalous network behavior")
    print("5. Back to main menu")
    
    choice = input("\nSelect option: ").strip()
    
    if choice == '1':
        print("\nAvailable network features:")
        for i, feat in enumerate(numeric_features[:20], 1):
            print(f"{i}. {feat}")
        
        feat_choice = input("\nEnter feature name: ").strip()
        if feat_choice in X_original.columns:
            min_val = float(input(f"Minimum {feat_choice} value: ") or "0")
            max_val = float(input(f"Maximum {feat_choice} value: ") or "999999")
            
            mask = (X_original[feat_choice] >= min_val) & (X_original[feat_choice] <= max_val)
            matching_idx = np.where(mask)[0]
            
            print(f"\n Found {len(matching_idx)} samples with {feat_choice} in [{min_val}, {max_val}]")
            for idx in matching_idx[:15]:
                print(f"Sample {idx}: {feat_choice}={X_original.iloc[idx][feat_choice]:.2f}, "
                      f"Prediction={['NORMAL', 'INTRUSION'][y_pred[idx]]}, "
                      f"Probability={y_proba[idx]:.4f}")
            
            if len(matching_idx) > 15:
                print(f"... and {len(matching_idx) - 15} more")
    
    elif choice == '2':
        feat_choice = input("\nEnter feature name: ").strip()
        if feat_choice in feature_names:
            feat_idx = feature_names.index(feat_choice)
            top_idx = np.argsort(np.abs(shap_values[:, feat_idx]))[-10:][::-1]
            
            print(f"\n TOP 10 SAMPLES by SHAP impact for '{feat_choice}':")
            for rank, idx in enumerate(top_idx, 1):
                shap_val = shap_values[idx, feat_idx]
                print(f"{rank}. Sample {idx}: SHAP={shap_val:+.4f}, "
                      f"Prediction={['NORMAL', 'INTRUSION'][y_pred[idx]]}, "
                      f"Probability={y_proba[idx]:.4f}")
    
    elif choice == '3':
        sample1 = int(input("\nEnter first sample index: ").strip())
        sample2 = int(input("Enter second sample index: ").strip())
        
        if 0 <= sample1 < len(df) and 0 <= sample2 < len(df):
            print(f"\n COMPARISON: Sample {sample1} vs Sample {sample2}")
            print("=" * 90)
            
            print(f"\nSample {sample1}:")
            print(f"  Prediction: {['NORMAL', 'INTRUSION'][y_pred[sample1]]}")
            print(f"  Probability: {y_proba[sample1]:.4f}")
            
            print(f"\nSample {sample2}:")
            print(f"  Prediction: {['NORMAL', 'INTRUSION'][y_pred[sample2]]}")
            print(f"  Probability: {y_proba[sample2]:.4f}")
            
            print(f"\n Key Network Features Comparison:")
            key_features = ['duration', 'src_bytes', 'dst_bytes', 'count', 'srv_count']
            for feat in key_features:
                if feat in X_original.columns:
                    val1 = X_original.iloc[sample1][feat]
                    val2 = X_original.iloc[sample2][feat]
                    print(f"  {feat:<20}: {val1:>12.2f} vs {val2:>12.2f}")
    
    elif choice == '4':
        print("\n Searching for anomalous network behavior...")
        
        # Find samples with extreme values
        anomalies = []
        for feat in ['duration', 'src_bytes', 'dst_bytes']:
            if feat in X_original.columns:
                q99 = X_original[feat].quantile(0.99)
                high_val_idx = X_original[X_original[feat] > q99].index.tolist()
                anomalies.extend(high_val_idx[:5])
        
        anomalies = list(set(anomalies))[:10]
        
        print(f"\n Found {len(anomalies)} potentially anomalous samples:")
        for idx in anomalies:
            print(f"Sample {idx}: Prediction={['NORMAL', 'INTRUSION'][y_pred[idx]]}, "
                  f"Probability={y_proba[idx]:.4f}")



def display_menu():
    print("\n" + "=" * 90)
    print("ADVANCED XAI ANALYSIS MENU")
    print("=" * 90)
    print(" SINGLE SAMPLE ANALYSIS:")
    print("  1. Explain specific sample (with network features)")
    print("  2. Interactive network feature search")
    print()
    print(" GROUP ANALYSIS:")
    print("  3. Explain all detected intrusions (network perspective)")
    print("  4. Compare intrusion vs normal traffic (advanced)")
    print()
    print(" GLOBAL ANALYSIS:")
    print("  5. Show global feature importance (XGBoost + SHAP)")
    print("  6. Network feature category analysis")
    print()
    print(" EXPORT & REPORTS:")
    print("  7. Generate all visualizations")
    print("  8. Export complete XAI analysis to CSV")
    print("  9. Generate PDF report (comprehensive)")
    print()
    print("10. Exit")
    print("=" * 90)

def generate_pdf_report():
    """Generate a comprehensive PDF report"""
    print("\n Generating comprehensive PDF report...")
    print("   (Note: Requires reportlab package)")
    
    try:
        from reportlab.lib.pagesizes import letter, A4
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, PageBreak, Table
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import inch
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        pdf_file = f"xai_report_{timestamp}.pdf"
        
        doc = SimpleDocTemplate(pdf_file, pagesize=letter)
        story = []
        styles = getSampleStyleSheet()
        
        # Title
        story.append(Paragraph("Intrusion Detection - XAI Analysis Report", styles['Title']))
        story.append(Spacer(1, 0.3*inch))
        story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        story.append(Spacer(1, 0.5*inch))
        
        # Summary
        story.append(Paragraph("Executive Summary", styles['Heading1']))
        summary_text = f"""
        Dataset: {csv_path}<br/>
        Total Samples: {len(df)}<br/>
        Intrusions Detected: {intrusion_count} ({intrusion_count/len(df)*100:.1f}%)<br/>
        Normal Traffic: {normal_count} ({normal_count/len(df)*100:.1f}%)<br/>
        Detection Threshold: {zero_fn_threshold:.3f}<br/>
        """
        story.append(Paragraph(summary_text, styles['Normal']))
        story.append(PageBreak())
        
        # Top features
        story.append(Paragraph("Top 10 Most Important Features", styles['Heading1']))
        top_10 = feature_importance_df.head(10)
        
        table_data = [['Rank', 'Feature', 'Category', 'SHAP Score']]
        for rank, (idx, row) in enumerate(top_10.iterrows(), 1):
            table_data.append([str(rank), row['feature'][:30], row['category'][:20], f"{row['mean_abs_shap']:.6f}"])
        
        table = Table(table_data)
        story.append(table)
        
        doc.build(story)
        print(f" PDF report generated: {pdf_file}")
        
    except ImportError:
        print(" reportlab not installed. Install with: pip install reportlab")
    except Exception as e:
        print(f" Error generating PDF: {e}")



print("\n XAI System Ready!")
print(f"   • {len(df)} samples loaded")
print(f"   • {intrusion_count} intrusions detected")
print(f"   • {len(feature_names)} features analyzed")

while True:
    display_menu()
    choice = input("\nSelect option (1-10): ").strip()
    
    if choice == '1':
        sample_idx = input(f"Enter sample index (0-{len(df)-1}): ").strip()
        if sample_idx.isdigit():
            explain_single_sample_advanced(int(sample_idx))
    
    elif choice == '2':
        interactive_network_search()
    
    elif choice == '3':
        explain_intrusions_with_network_features()
    
    elif choice == '4':
        compare_intrusion_vs_normal_advanced()
    
    elif choice == '5':
        show_global_importance_advanced()
    
    elif choice == '6':
        # Category analysis already covered in option 5
        show_global_importance_advanced()
    
    elif choice == '7':
        print("\n Generating all visualizations...")
        show_global_importance_advanced()
        if intrusion_count > 0:
            explain_intrusions_with_network_features()
            if normal_count > 0:
                compare_intrusion_vs_normal_advanced()
        print("\n All visualizations generated!")
    
    elif choice == '8':
        export_advanced_explanations()
    
    elif choice == '9':
        generate_pdf_report()
    
    elif choice == '10':
        print("\n" + "=" * 90)
        print("Thank you for using Advanced XAI Analysis!")
        print("=" * 90)
        break
    
    else:
        print("\n Invalid option. Please select 1-10.")
    
    input("\nPress Enter to continue...")

print("\n XAI ANALYSIS COMPLETE")