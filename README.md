# 🚩 LeetEnum (v1.0)

**Developed by Sudoaman | Property of LeetSecurity LLC**

![Bash](https://img.shields.io/badge/Language-Bash-green?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux-black?style=flat-square)
![License](https://img.shields.io/badge/License-LeetSec-red?style=flat-square)

## 👋 Namaste! What is LeetEnum?

**LeetEnum** is a high-performance, fully automated reconnaissance engine designed for Bug Bounty Hunters and Red Teamers who want results, not headaches.

We know the struggle—running `subfinder`, then sorting files, then running `httpx`, then `nuclei` one by one... it is a big headache and takes too much time.

**LeetEnum solves this problem.** You just give it a domain name, and it handles the entire kill chain automatically. It is built to be a **"Set and Forget"** tool. You run the command, go sleep or watch a movie, and get a notification on your phone when the hacking is done.

It is built to be **Smart**. It checks your RAM and CPU before starting. If you have a small laptop, it runs gently (Potato Mode). If you have a big Cloud VPS (like Azure/AWS), it runs in **Beast Mode** (50x Parallelism) and finishes the job very fast.

## 🔥 Why use this tool? (Key Features)

1. **🧠 Smart Auto-Scaling (No Lag)**
   The tool automatically checks your PC/VPS specifications (RAM & CPU).
   * If you have a **small laptop (4GB RAM)**, it runs gently (Potato Mode).
   * If you have a **big VPS (64GB+ RAM)**, it goes full **Beast Mode** and hammers the target.

2. **👀 Monitor Mode (The Hunter)**
   Run the tool today on `target.com`. Run it again after 7 days.
   The tool will compare the results and tell you **only the NEW subdomains** that appeared. This is best for finding fresh bugs before anyone else.

3. **🔄 Self-Updating**
   Never use an old version. Just run `./leetenum.sh -update` and it will pull the latest code and features from the LeetSec repository automatically.

4. **⏸️ Smart Resume (Peace of Mind)**
   Internet disconnected? Server restarted? **No tension.**
   Just run the script again. It remembers exactly where it stopped (using checkpoint files) and continues from there. It won't waste time doing the same work twice.

5. **🔔 Instant Alerts**
   Get a notification on your phone (**Telegram, Discord, or Slack**) the moment a scan finishes or if a critical vulnerability is found.

6. **📸 Visual Recon**
   It automatically takes screenshots of all live websites using `gowitness`. You can browse them later to spot Admin Panels easily.

7. **🛡️ Auto-Installation (Universal)**
   You don't need to manually install tools. The script detects your OS (Kali, Ubuntu, Arch, etc.) and installs missing dependencies like `puredns`, `massdns`, or `nuclei` automatically.

## 🚀 Installation Guide

It is very simple to install. Just open your terminal and run these commands one by one:

**Step 1: Download the tool**
```bash
git clone [https://github.com/theleetsec/LeetSec-Tools.git](https://github.com/theleetsec/LeetSec-Tools.git)
cd LeetSec-Tools
````

**Step 2: Give permission**

```bash
chmod +x leetenum.sh
```

**Step 3: First Time Setup**
This will install all necessary tools and help you set up your Notification Webhooks.

```bash
./leetenum.sh --reset
```

*(Note: If the script asks for a password, it is installing system dependencies like massdns or chromium)*

## 🛠️ How to Use

### 1️⃣ Basic Scan (Start Here)

Best for scanning a single website or domain for the first time.

```bash
./leetenum.sh -d target.com
```

### 2️⃣ Monitor Mode (Find New Subdomains)

Use this if you have already scanned the target before and want to check for **new changes**.

```bash
./leetenum.sh -d target.com -m
```

### 3️⃣ Deep Scan (Slow but Thorough)

By default, the tool scans the Top 1,000 ports for speed. Use this if you want to scan **ports 1-10,000** to find hidden services.

```bash
./leetenum.sh -d target.com --deep
```

### 4️⃣ Background Mode (Recommended for VPS)

If you are scanning a big target like `microsoft.com`, the script will automatically ask if you want to run in **Tmux**. Say **Yes**.
This keeps the scan running safely in the background even if you close your terminal.

### 5️⃣ Update the Tool

To get the latest version and bug fixes instantly:

```bash
./leetenum.sh -update
```

### 6️⃣ Reset Configuration

If you want to change your API keys or Telegram/Discord settings later.

```bash
./leetenum.sh --reset
```

## 📂 Output Files (Where is my data?)

All your results are saved nicely in the `recon_<target>/<timestamp>/` folder.

| File Name | What is inside? |
| :--- | :--- |
| **REPORT.md** | A clean summary of the whole scan (Open this first). |
| **master\_dns.txt** | A huge list of every subdomain found. |
| **live.txt** | List of all working websites (HTTP/HTTPS). |
| **screenshots/** | Folder containing images of all the websites. |
| **reports/nuclei.txt** | List of vulnerabilities found. |
| **new\_subs.txt** | (Monitor Mode Only) List of newly discovered domains. |

## ⚠️ Disclaimer

**This tool is created by Sudoaman (LeetSec) for Educational and Ethical Hacking purposes only.**

Please do not use this tool on websites where you do not have written permission. The author is not responsible for any misuse or damage caused by this tool.

**Happy Hunting\! 🎯**
