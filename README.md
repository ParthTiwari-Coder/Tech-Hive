# 🚀 IntrusionX AI

🏆 Built for REDACT 2025 Hackathon  
📅 November 22-23, 2025 | 📍 SPIT Mumbai  
🎯 Theme: Uncover the Unknown, Secure the Future

---

## 🛡️ Overview

IntrusiveX AI is an intelligent cybersecurity system designed to detect malicious network activity in real time using Machine Learning. The system identifies attacks, explains the reasoning using Explainable AI (SHAP), and stores detected threats securely for tamper-proof auditing.

It provides a modern visual dashboard to analyze anomalies, classify intrusion attempts, visualize threat metrics, and suggest preventive actions.

---

## 🎯 The Problem

Traditional Intrusion Detection Systems operate as "black boxes" - they alert security teams about threats but don't explain why. This makes it hard to trust automated decisions and slows down incident response.

Our Solution: IntrusiveX AI combines powerful ML models with SHAP explainability to provide transparent, interpretable threat detection with actionable recommendations.

---

## 📌 Key Features

🔍 Real-time Intrusion Detection using ML classification models

🎯 Binary & Multi-Class Intrusion Result Labeling (DOS, R2L, U2R, Probe)

📊 Feature Importance & Confusion Matrix Visualization

🧠 Explainable AI using SHAP for model transparency

🔐 Secure Log Storage (Optional: Blockchain/Immutable Records)

🧾 Threat Summary, Suggestions & Response Guidance

⚡ Fast Web Interface with React Frontend and Python Backend

---

## 🏗️ Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React.js, Axios, Chart.js/Recharts |
| Backend | Python (Flask/FastAPI/Django), ML Model (Pickle/Sklearn) |
| ML Model | RandomForest / XGBoost / Gradient Boosting |
| Explainability | SHAP |
| Storage | SQLite / MongoDB / IPFS (Optional) |

---

## 📁 Project Structure

```
IntrusiveX-AI/
│
├── backend/
│   ├── model.pkl
│   ├── api.py
│   ├── requirements.txt
│
├── frontend/
│   ├── src/
│   ├── public/
│   ├── package.json
│
└── README.md
```

---

## ⚙️ Setup & Installation

### 1️⃣ Clone the Repository

```bash
git clone https://github.com/ParthTiwari-Coder/Tech-Hive.git
cd Tech-Hive
```

### 2️⃣ Backend Setup

```bash
cd backend
pip install -r requirements.txt
python api.py
```

Backend will start at: http://localhost:5000

### 3️⃣ Frontend Setup

```bash
cd frontend
npm install
npm start
```

Frontend will start at: http://localhost:3000

---

## 📡 How It Works

1. User uploads network traffic dataset or CSV file

2. Model processes data and detects normal traffic and multiple forms of intrusion (DOS, R2L, U2R, Probe, etc.)

3. Results are sent to UI with per-row detection results, confidence score, threat suggestion and remediation

4. Visualizations (Confusion Matrix, Feature Importance) displayed on dashboard

---

## 🧪 Sample Output

| Input Data Row | Prediction | Confidence | Suggestion |
|----------------|------------|------------|------------|
| Row #1 | 🔥 DOS Attack | 97.2% | Block Source IP |
| Row #2 | ✔ Normal | 92.5% | No action required |

---

## 👥 Team

Parth Tiwari

Tabsir Shaikh

Karishma Kale

Padmaja Kachare

---

## 🚀 Future Enhancements

Live network packet capture integration

Email/SMS alerts for critical threats

Support for additional attack types

Mobile app for monitoring

---

## 🙏 Acknowledgments

Special thanks to Suraksha SPIT Cell and SPIT Mumbai for organizing REDACT 2025, and to our mentors for their guidance throughout the hackathon.

---

## 📞 Contact

GitHub: [@ParthTiwari-Coder](https://github.com/ParthTiwari-Coder)

LinkedIn: [Parth Tiwari](https://www.linkedin.com/in/parth-tiwari-164474331)

---

Made with ❤️ during REDACT 2025 Hackathon

⭐ Star this repo if you found it useful!
