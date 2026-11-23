# AI-Navigated Decentralized Self-Sovereign Identity System

## Project Overview

The AI-Navigated Decentralized Self-Sovereign Identity (SSI) System is designed to provide secure digital identity management using cryptographic authentication and AI-based anomaly detection.

The system allows users to manage and authenticate their digital identities while monitoring authentication requests for suspicious activities.

It combines public-key cryptography with intelligent risk analysis to improve security, privacy, and user control.

## Key Features

- **Decentralized Identity Authentication:** Uses public-private key cryptography for secure identity verification.
- **Digital Signature Verification:** Uses Ed25519 cryptography to sign and verify authentication challenges.
- **AI-Based Anomaly Detection:** Analyses authentication traffic to identify unusual patterns.
- **Dynamic Risk Analysis:** Evaluates authentication activity and calculates risk levels.
- **Intelligent Access Decisions:** Uses risk analysis to support ALLOW or DENY decisions.
- **Web-Based Interface:** Provides a frontend for interacting with the authentication system.

## Project Architecture

```text
                User
                 |
                 v
          Web-Based Frontend
                 |
                 v
           FastAPI Backend
                 |
        +--------+--------+
        |        |        |
        v        v        v
     SSI       AI       Risk
    Authentication Detection Analysis
        |        |        |
        +--------+--------+
                 |
                 v
        Authentication Decision
             ALLOW / DENY
```

## Technologies Used

- **Programming Language:** Python, JavaScript
- **Backend:** FastAPI
- **Frontend:** HTML, JavaScript
- **Cryptography:** Python Cryptography Library (Ed25519)
- **AI/ML:** PyTorch
- **Document Processing:** pypdf
- **Testing:** Python Requests

## Project Structure

```text
AI-Navigated-Decentralized-SSI/
│
├── ai_engine/
│   ├── __init__.py
│   └── model.py
│
├── frontend/
│   ├── index.html
│   └── app.js
│
├── ssi_auth/
│   ├── __init__.py
│   └── crypto_utils.py
│
├── vulnerability_engine/
│   ├── __init__.py
│   └── risk_analyzer.py
│
├── tests/
│   └── integration_test.py
│
├── main.py
├── requirements.txt
├── README.md
└── .gitignore
```

## Installation and Setup

### 1. Clone the repository

```bash
git clone https://github.com/anusha-728/AI-Navigated-Decentralised-Self-Soverign-Identity.git
cd AI-Navigated-Decentralised-Self-Soverign-Identity
```

### 2. Create a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the application

```bash
uvicorn main:app --reload
```

Open your browser and visit:

```text
http://127.0.0.1:8000
```

## Future Enhancements

- Integration with decentralized identity standards.
- Improved AI-based fraud and anomaly detection.
- Enhanced identity wallet management.
- Advanced authentication monitoring.

## Author

Developed as an academic project focused on AI-based security and decentralized digital identity management.

