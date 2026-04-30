# 🛡️ ThreatShield Platform

### Advanced Threat Intelligence Platform (TIP) & Dynamic Policy Enforcer

---

## 📌 Overview

ThreatShield Platform is an advanced cybersecurity solution designed for **financial institutions** to combat modern cyber threats such as:

* Zero-day attacks
* Advanced Persistent Threats (APTs)
* Malicious IP/domain-based attacks

This platform combines **Threat Intelligence Aggregation** with a **Dynamic Security Policy Enforcer** to automatically detect and block threats in real-time — without manual intervention.

---

## 🎯 Project Objective

To build a system that:

* Collects **Open Source Intelligence (OSINT)** from multiple threat feeds
* Normalizes and stores threat data efficiently
* Integrates with a **SIEM system (ELK Stack)**
* Automatically enforces firewall rules using system-level commands
* Enables **real-time, automated threat mitigation**

---

## 🧑‍💻 User Personas

### 👨‍💻 SOC Analyst

* Needs: Clean, actionable threat intelligence
* Workflow:

  * Monitors dashboard
  * Investigates real threats only
  * Avoids data overload

### 🛠️ Security Engineer

* Needs: Automated network defense
* Workflow:

  * Reviews firewall rule updates
  * Monitors blocked IPs/domains
  * Ensures system efficiency

### 📋 Compliance Officer

* Needs: Audit-ready logs
* Workflow:

  * Reviews logs for compliance (e.g., PCI-DSS)
  * Ensures regulatory adherence

---

## 🚀 Key Features

* 🔍 OSINT Threat Feed Aggregation
* 🧠 Data Normalization & Risk Scoring
* 📊 SIEM Integration (ELK Stack)
* 🔐 Dynamic Firewall Rule Enforcement
* ⚡ Real-time Threat Blocking
* 🧾 Immutable Logging for Compliance
* 🔄 Rollback Mechanism for False Positives

---

## 🏗️ System Architecture

```
OSINT Feeds (VirusTotal, AlienVault OTX, etc.)
            ↓
    Python Data Aggregator
            ↓
        MongoDB
            ↓
   Data Normalization Engine
            ↓
      Elasticsearch (SIEM)
            ↓
        Kibana Dashboard
            ↓
 Dynamic Policy Enforcer (Python)
            ↓
     Linux iptables Firewall
```

---

## 📂 Project Structure

```
ThreatShield-Platform/
│
├── aggregator/        # OSINT data collection scripts
├── database/          # MongoDB schema & configs
├── normalization/     # Data cleaning & risk scoring
├── enforcer/          # Dynamic firewall rule engine
├── siem/              # ELK integration setup
├── logs/              # System logs
├── docs/              # Documentation
└── README.md
```

---

## ⚙️ Installation & Setup

### 1️⃣ Clone Repository

```bash
git clone https://github.com/YOUR-USERNAME/ThreatShield-Platform.git
cd ThreatShield-Platform
```

---

### 2️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

---

### 3️⃣ Setup MongoDB

```bash
sudo systemctl start mongod
```

---

### 4️⃣ Configure Environment Variables

Create `.env` file:

```
MONGO_URI=your_mongodb_uri
API_KEY_VIRUSTOTAL=your_api_key
API_KEY_OTX=your_api_key
```

---

### 5️⃣ Run Modules

#### ▶️ Run Aggregator

```bash
python aggregator/main.py
```

#### ▶️ Run Policy Enforcer

```bash
sudo python enforcer/enforcer.py
```

---

## 🔄 Dynamic Policy Enforcement Example

```bash
iptables -A INPUT -s <Malicious_IP> -j DROP
```

Automatically blocks malicious traffic based on real-time intelligence.

---

## 📊 SIEM Dashboard

* Visualize threats in **Kibana**
* Monitor:

  * Blocked IPs
  * Risk scores
  * Threat trends

---

## 🧪 Four-Week Development Roadmap

### 📅 Week 1: OSINT Ingestion

* Integrate 3+ threat feeds
* Store data in MongoDB
* Deduplicate entries

### 📅 Week 2: Normalization & SIEM

* Implement risk scoring
* Integrate ELK Stack
* Create dashboards

### 📅 Week 3: Policy Enforcement

* Build Python daemon
* Automate iptables rules
* Enable real-time blocking

### 📅 Week 4: Testing & Reporting

* Add rollback mechanism
* Finalize dashboards
* Document system

---

## 📈 Key Performance Indicators (KPIs)

* ✅ Real-time threat ingestion
* ✅ Zero duplicate indicators
* ✅ Automated firewall updates
* ✅ Low latency impact
* ✅ Accurate threat blocking

---

## ⚠️ Security Considerations

* Run firewall scripts with caution (requires sudo access)
* Implement rollback for false positives
* Protect API keys using environment variables

---

## 🤝 Contributing

1. Fork the repository
2. Create a branch (`feature-name`)
3. Commit changes
4. Push to your fork
5. Create Pull Request

---

## 🐛 Issues

Report bugs via GitHub Issues.

---

## 📄 License

MIT License

---

## 👩‍💻 Author

**Sakshi Gadilkar**

* GitHub: https://github.com/YOUR-USERNAME
* LinkedIn: (Add your profile)

---

## ⭐ Support

If you find this project useful, give it a ⭐ and share!

---

