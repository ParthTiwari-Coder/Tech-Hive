## 🚀 IntrusionX AI 

An Explainable Intrusion Detection System for Modern Cybersecurity

🏆 Developed for REDACT 2025 Hackathon
📅 22–23 November 2025 | 📍 SPIT, Mumbai
🎯 Theme: Uncover the Unknown, Secure the Future

🛡️ Overview

IntrusionX AI is an advanced cybersecurity system engineered to detect malicious network activity in real time using state-of-the-art Machine Learning models. Unlike traditional Intrusion Detection Systems—which often behave as opaque “black boxes”—IntrusionX AI integrates Explainable AI (SHAP) to provide clear, human-understandable justifications for every detection decision.

🎯 Problem Statement

Conventional IDS solutions alert administrators about potential threats but fail to explain why those threats were flagged. This lack of transparency slows decisions, reduces trust, and increases the likelihood of missed attacks.

✔ Our Solution

IntrusionX AI delivers a transparent and interpretable threat detection pipeline combining:

Machine Learning-driven intrusion classification

SHAP-based explainability

Secure logging for tamper-proof auditing

Real-time analytics and a sleek reporting dashboard

This empowers cybersecurity teams with clearer insights and faster response capabilities.

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
| Backend | Python (Flask/FastAPI)  ML Model (Pickle/Sklearn) |
| ML Model | RandomForest / XGBoost / Gradient Boosting |
| Explainability | SHAP |


---

## 📁 Project Structure

```
IntrusionX-AI/
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

Backend runs at http://localhost:5000

### 3️⃣ Frontend Setup

```bash
cd frontend
npm install
npm start
```

Frontend runs at http://localhost:3000

---

📡 How It Works

User uploads network traffic data (CSV or dataset)

ML model processes and predicts intrusion types

Each record receives:

Prediction label

Confidence score

SHAP explanation

Recommended action

Dashboard visualizes overall threat metrics and insights

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

We express our gratitude to Suraksha SPIT Cell and SPIT Mumbai for hosting REDACT 2025. Special thanks to our mentors for their continuous support during the hackathon.

## 📞 Contact

GitHub: [@ParthTiwari-Coder](https://github.com/ParthTiwari-Coder)

LinkedIn: [Parth Tiwari](https://www.linkedin.com/in/parth-tiwari-164474331)



⭐ Star this repo if you found it useful!
