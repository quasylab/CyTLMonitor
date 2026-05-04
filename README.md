# CyTL — Temporal-Quantitative Logic for Network Traffic Monitoring

CyTL is a framework for specifying and monitoring network traffic using a temporal-quantitative logic.
It allows you to detect patterns such as flooding, brute-force attacks, and anomalous behaviors by combining temporal operators with counting and aggregation over sliding windows.

---

## 🚀 Features

* Temporal logic for network traffic analysis
* Quantitative operators (counting, min, max, aggregation)
* Support for PCAP-based traffic analysis
* **Batch analysis from ZIP archives containing multiple PCAP files**
* Real-time or offline monitoring
* Graphical visualization 

---

## 📦 Requirements

* **Python 3.10 or 3.11 (recommended)**
* pip (latest version)

### Python dependencies

Install all dependencies with:

```bash
pip install -r requirements.txt
```

---

## ⚠️ System Dependencies (IMPORTANT)

CyTL relies on **Scapy** for packet processing.
Depending on your OS, you MUST install additional system libraries:

### 🪟 Windows

* Install **Npcap**:
  https://npcap.com/

### 🐧 Linux (Ubuntu/Debian)

```bash
sudo apt update
sudo apt install libpcap-dev
```

### 🍎 macOS

```bash
brew install libpcap
```

---

## 📥 Installation

Clone the repository:

```bash
git clone https://github.com/YOUR-USERNAME/cytl.git
cd cytl
```

Create a virtual environment:

```bash
python -m venv venv
```

Activate it:

* Linux/macOS:

```bash
source venv/bin/activate
```

* Windows:

```bash
venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## ▶️ Usage

Run the main application:

```bash
python main.py
```

### Linux/macOS

On Linux, packet capture and PCAP processing through Scapy may require elevated privileges.
If you encounter permission errors, run:

```bash
sudo python main.py
```
### 📂 Supported Input Modes

CyTL supports two input modalities:

#### 1. Single PCAP file

* Load and analyze one `.pcap` file at a time

#### 2. ZIP archive (Batch Mode) ⭐

* Load a `.zip` file containing **multiple `.pcap` files**
* CyTL will:

  * automatically extract the archive
  * iterate over all PCAP files
  * analyze each file sequentially
  * aggregate or display results

Example:

```text
dataset.zip
├── attack1.pcap
├── attack2.pcap
└── benign.pcap
```

CyTL will process all files without requiring manual selection.

---

## 📁 Project Structure

```text
cytl/
├── main.py
├── requirements.txt
├── src/              # core logic
├── gui/              # GUI components
├── parser/           # PCAP parsing
├── monitor/          # monitoring engine
└── ...
```

---

## 🧪 Example Workflow

1. Load a `.pcap` file or `.zip` archive
2. Define a CyTL rule (e.g., SYN flooding detection)
3. Run the monitor
4. Inspect alerts and visual output

---

## 🛠️ Development (optional)

```bash
pip install pytest black ruff mypy
```

---

## 🧩 Troubleshooting

### ❌ Scapy not working

* Ensure Npcap/libpcap is installed
* Run with administrator/root privileges if needed

### ❌ ZIP not processed

* Ensure archive contains valid `.pcap` files
* Avoid nested ZIPs (flat structure recommended)

### ❌ GUI not starting

* Check PyQt5 installation
* Ensure your system supports GUI applications

---

## 👨‍💻 Authors

* Marco Quadrini
* Michele Loreti

---

## 📖 Citation

If you use this tool in research, please cite:

> *A Temporal-Quantitative Logic Framework for Monitoring Network Traffic*

---


