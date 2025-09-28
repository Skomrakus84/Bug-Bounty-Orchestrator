# Bug Bounty Orchestrator

System do zarządzania i automatyzacji procesu Bug Bounty dla celów prywatnych.

## 🚀 Szybkie uruchomienie

### Wymagania wstępne
- Docker & Docker Compose

### Uruchomienie
```bash
# Sklonuj repozytorium
git clone <repository-url>
cd bug-bounty-orchestrator

# Uruchom aplikację
docker-compose up --build
```

### Dostęp do aplikacji
- **Frontend**: http://localhost
- **Backend API**: http://localhost:8000
- **Dokumentacja API**: http://localhost:8000/docs

## 📋 Konfiguracja integracji (opcjonalne)

1. Skopiuj plik konfiguracyjny:
```bash
cp .env.example .env
```

2. Edytuj `.env` i dodaj swoje klucze API:
```bash
# Integracje zewnętrzne
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK
SHODAN_API_KEY=your_shodan_key
BUGCROWD_API_KEY=your_bugcrowd_key
JIRA_SERVER=https://yourcompany.atlassian.net
GITHUB_TOKEN=your_github_token
```

## 🏗️ Architektura

### Backend (FastAPI)
- **Automatyczne skanowanie** z 20+ narzędziami bezpieczeństwa
- **Integracje API** (Shodan, VirusTotal, Bugcrowd, Jira, GitHub)
- **Baza danych** PostgreSQL z SQLAlchemy
- **REST API** z pełną dokumentacją

### Frontend (React + Vite)
- **Nowoczesny dark theme** z Tailwind CSS
- **Responsywny design** mobilny/pulpit
- **Real-time updates** wyników skanowania
- **Zarządzanie skanami** (start, delete, rerun)

### Narzędzia bezpieczeństwa
- **OSINT**: Subfinder, Amass, Sublist3r, crt.sh, Whois, Dig, Nslookup
- **Web**: Feroxbuster, Gobuster, Dirsearch, ffuf, SQLMap, Nuclei
- **API**: Mitmproxy, Schemathesis, Restler
- **Mobile**: ADB, Apktool, Jadx, MobSF, Frida, Objection
- **Network**: Tshark, Tcpreplay, Wireshark
- **Fuzzing**: Boofuzz, AFL, Wfuzz, Radamsa, Peach, Zzuf
- **Static**: Semgrep, Bandit
- **Reverse Engineering**: Ghidra, Radare2, Cutter, Strings, Objdump, Readelf

## 🔧 Rozwój lokalny

### Backend
```bash
cd backend
pip install -r requirements.txt
python -m uvicorn app.main:app --reload --port 8000
```

### Frontend
```bash
cd frontend
npm install
npm run dev
```

## 📊 Funkcjonalności

- ✅ **Automatyczne skanowanie** wszystkich narzędzi
- ✅ **Raporty Markdown + PDF** z Pandoc
- ✅ **Integracje platform** bug bounty
- ✅ **Real-time monitoring** postępów
- ✅ **Statystyki i dashboard**
- ✅ **Filtrowanie i sortowanie** skanów
- ✅ **Responsywny UI** z dark theme

## 🐳 Docker

Aplikacja jest w pełni konteneryzowana:
- **Multi-stage builds** dla optymalizacji
- **Izolacja usług** (backend, frontend, database)
- **Hot reload** w trybie development
- **Production ready** konfiguracja
<div align="center">
<img width="1200" height="475" alt="GHBanner" src="https://github.com/user-attachments/assets/0aa67016-6eaf-458a-adb2-6e31a0763ed6" />
</div>

# Run and deploy your AI Studio app

This contains everything you need to run your app locally.

View your app in AI Studio: https://ai.studio/apps/drive/1PwvWCI9mMW8HX8gL-OPhTxkskIqeDaRi

## Run Locally

**Prerequisites:**  Node.js


1. Install dependencies:
   `npm install`
2. Set the `GEMINI_API_KEY` in [.env.local](.env.local) to your Gemini API key
3. Run the app:
   `npm run dev`
