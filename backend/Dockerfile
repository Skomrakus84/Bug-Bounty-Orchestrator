FROM python:3.11-slim
WORKDIR /app

# Install system dependencies and security tools
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    unzip \
    nmap \
    pandoc \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install subfinder
RUN curl -s https://api.github.com/repos/projectdiscovery/subfinder/releases/latest \
    | grep "browser_download_url.*linux_amd64.zip" \
    | cut -d '"' -f 4 \
    | wget -i - -O subfinder.zip \
    && unzip -o subfinder.zip \
    && mv subfinder /usr/local/bin/ \
    && rm subfinder.zip

# Install httpx
RUN curl -s https://api.github.com/repos/projectdiscovery/httpx/releases/latest \
    | grep "browser_download_url.*linux_amd64.zip" \
    | cut -d '"' -f 4 \
    | wget -i - -O httpx.zip \
    && unzip -o httpx.zip \
    && mv httpx /usr/local/bin/ \
    && rm httpx.zip

# Install nuclei
RUN curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
    | grep "browser_download_url.*linux_amd64.zip" \
    | cut -d '"' -f 4 \
    | wget -i - -O nuclei.zip \
    && unzip -o nuclei.zip \
    && mv nuclei /usr/local/bin/ \
    && rm nuclei.zip

# Install amass
# RUN curl -s https://api.github.com/repos/OWASP/Amass/releases/latest \
#     | grep "browser_download_url.*linux_amd64.zip" \
#     | cut -d '"' -f 4 \
#     | wget -i - -O amass.zip \
#     && unzip -o amass.zip \
#     && mv amass /usr/local/bin/ \
#     && rm amass.zip

# Install naabu
# RUN curl -s https://api.github.com/repos/projectdiscovery/naabu/releases/latest \
#     | grep "browser_download_url.*linux_amd64.zip" \
#     | cut -d '"' -f 4 \
#     | wget -i - -O naabu.zip \
#     && unzip -o naabu.zip \
#     && mv naabu /usr/local/bin/ \
#     && rm naabu.zip

# Install ffuf
RUN curl -s https://api.github.com/repos/ffuf/ffuf/releases/latest \
    | grep "browser_download_url.*linux_amd64.tar.gz" \
    | cut -d '"' -f 4 \
    | wget -i - -O ffuf.tar.gz \
    && tar -xzf ffuf.tar.gz \
    && mv ffuf /usr/local/bin/ \
    && rm ffuf.tar.gz

# Install dirsearch
RUN git clone https://github.com/maurosoria/dirsearch.git /opt/dirsearch \
    && cd /opt/dirsearch \
    && pip install -r requirements.txt

# Install sqlmap
RUN git clone https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap

# Install gobuster
# RUN curl -s https://api.github.com/repos/OJ/gobuster/releases/latest \
#     | grep "browser_download_url.*linux-amd64.tar.gz" \
#     | cut -d '"' -f 4 \
#     | wget -i - -O gobuster.tar.gz \
#     && tar -xzf gobuster.tar.gz \
#     && mv gobuster /usr/local/bin/ \
#     && rm gobuster.tar.gz

# Install feroxbuster
# RUN curl -s https://api.github.com/repos/epi052/feroxbuster/releases/latest \
#     | grep "browser_download_url.*x86_64-linux-feroxbuster.tar.gz" \
#     | cut -d '"' -f 4 \
#     | wget -i - -O feroxbuster.tar.gz \
#     && tar -xzf feroxbuster.tar.gz \
#     && mv feroxbuster /usr/local/bin/ \
#     && rm feroxbuster.tar.gz

# Install mitmproxy
RUN pip install mitmproxy

# Install schemathesis
RUN pip install schemathesis

# Install restler
# RUN wget https://github.com/microsoft/restler-fuzzer/releases/download/v9.2.1/restler-linux-x64.tar.gz \
#     && tar -xzf restler-linux-x64.tar.gz \
#     && mv restler /usr/local/bin/ \
#     && rm restler-linux-x64.tar.gz

# Install playwright
# RUN pip install playwright \
#     && playwright install

# Install selenium
# RUN pip install selenium

# Install appium
# RUN npm install -g appium

# Install apktool
# RUN wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool \
#     && wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.7.0.jar \
#     && mv apktool /usr/local/bin/ \
#     && mv apktool_2.7.0.jar /usr/local/bin/apktool.jar \
#     && chmod +x /usr/local/bin/apktool

# Install whois, dig, nslookup (dnsutils)
RUN apt-get update && apt-get install -y dnsutils whois

# Install semgrep
RUN pip install semgrep

# Install bandit
RUN pip install bandit

# Install tcpdump
RUN apt-get install -y tcpdump

# Install jaeles - advanced web application scanner
RUN curl -s https://api.github.com/repos/jaeles-project/jaeles/releases/latest \
    | grep "browser_download_url.*linux.zip" \
    | cut -d '"' -f 4 \
    | wget -i - -O jaeles.zip \
    && unzip -o jaeles.zip \
    && mv jaeles /usr/local/bin/ \
    && rm jaeles.zip

# Install katana - advanced web crawler
RUN curl -s https://api.github.com/repos/projectdiscovery/katana/releases/latest \
    | grep "browser_download_url.*linux_amd64.zip" \
    | cut -d '"' -f 4 \
    | wget -i - -O katana.zip \
    && unzip -o katana.zip \
    && mv katana /usr/local/bin/ \
    && rm katana.zip

# Install uncover - passive data gathering
RUN curl -s https://api.github.com/repos/projectdiscovery/uncover/releases/latest \
    | grep "browser_download_url.*linux_amd64.zip" \
    | cut -d '"' -f 4 \
    | wget -i - -O uncover.zip \
    && unzip -o uncover.zip \
    && mv uncover /usr/local/bin/ \
    && rm uncover.zip

# Install dnsx - advanced DNS toolkit
RUN curl -s https://api.github.com/repos/projectdiscovery/dnsx/releases/latest \
    | grep "browser_download_url.*linux_amd64.zip" \
    | cut -d '"' -f 4 \
    | wget -i - -O dnsx.zip \
    && unzip -o dnsx.zip \
    && mv dnsx /usr/local/bin/ \
    && rm dnsx.zip

# Install alterx - subdomain wordlist generator
RUN curl -s https://api.github.com/repos/projectdiscovery/alterx/releases/latest \
    | grep "browser_download_url.*linux_amd64.zip" \
    | cut -d '"' -f 4 \
    | wget -i - -O alterx.zip \
    && unzip -o alterx.zip \
    && mv alterx /usr/local/bin/ \
    && rm alterx.zip

# Install interactsh - out-of-band interaction server
RUN curl -s https://api.github.com/repos/projectdiscovery/interactsh/releases/latest \
    | grep "browser_download_url.*interactsh-client.*linux_amd64.zip" \
    | cut -d '"' -f 4 \
    | wget -i - -O interactsh.zip \
    && unzip -o interactsh.zip \
    && mv interactsh-client /usr/local/bin/interactsh \
    && rm interactsh.zip

# Install notify - notification service
RUN curl -s https://api.github.com/repos/projectdiscovery/notify/releases/latest \
    | grep "browser_download_url.*linux_amd64.zip" \
    | cut -d '"' -f 4 \
    | wget -i - -O notify.zip \
    && unzip -o notify.zip \
    && mv notify /usr/local/bin/ \
    && rm notify.zip

# Install Nikto - web server scanner
RUN git clone https://github.com/sullo/nikto.git /opt/nikto \
    && cd /opt/nikto \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && chmod +x /usr/local/bin/nikto

# Install Wapiti - web application vulnerability scanner
RUN pip install wapiti3

# Install XSStrike - XSS detection suite
RUN git clone https://github.com/s0md3v/XSStrike.git /opt/XSStrike \
    && cd /opt/XSStrike \
    && pip install -r requirements.txt

# Install CMSeek - CMS detection and exploitation
RUN git clone https://github.com/Tuhinshubhra/CMSeeK.git /opt/CMSeeK \
    && cd /opt/CMSeeK \
    && pip install -r requirements.txt

# Install wfuzz - web application fuzzer (alternative to skipfish)
RUN pip install wfuzz

# Install whatweb - web technology fingerprinting
RUN apt-get update && apt-get install -y whatweb

# Install Lynis - security auditing tool
RUN apt-get update && apt-get install -y lynis

# Install OpenSCAP - security compliance checking
RUN apt-get update && apt-get install -y openscap-common libopenscap33 openscap-scanner python3-openscap

# Install ClamAV - antivirus engine
RUN apt-get install -y clamav clamav-daemon

# Install RKHunter - rootkit detector
RUN apt-get install -y rkhunter

# Install chkrootkit - rootkit detection
RUN apt-get install -y chkrootkit

# Install AIDE - file integrity checker
RUN apt-get install -y aide

# Install auditd - Linux audit framework
RUN apt-get install -y auditd

# Install fail2ban - intrusion prevention
RUN apt-get install -y fail2ban

# Install Suricata - advanced IDS/IPS
RUN apt-get install -y suricata

# Install Lynis - security auditing tool for Linux
RUN apt-get update && apt-get install -y lynis

# Install Brakeman - security scanner for Ruby on Rails
RUN gem install brakeman

# Install PMD - static analysis for multiple languages
RUN wget https://github.com/pmd/pmd/releases/download/pmd_releases%2F6.55.0/pmd-bin-6.55.0.zip \
    && unzip pmd-bin-6.55.0.zip \
    && mv pmd-bin-6.55.0 /opt/pmd \
    && ln -s /opt/pmd/bin/pmd /usr/local/bin/pmd \
    && rm pmd-bin-6.55.0.zip

# Install ClamAV - antivirus engine
RUN apt-get update && apt-get install -y clamav clamav-daemon \
    && freshclam

# Install YARA - malware detection
RUN pip install yara-python

# Install OpenSCAP - security compliance checking
RUN apt-get update && apt-get install -y openscap-scanner

# Install Safety - Python dependency vulnerability scanner
RUN pip install safety

# Install Trivy - container vulnerability scanner
RUN wget https://github.com/aquasecurity/trivy/releases/download/v0.40.0/trivy_0.40.0_Linux-64bit.tar.gz \
    && tar -xzf trivy_0.40.0_Linux-64bit.tar.gz \
    && mv trivy /usr/local/bin/ \
    && rm trivy_0.40.0_Linux-64bit.tar.gz

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt alembic
COPY .env .
COPY . .
RUN chmod +x start.sh
EXPOSE 8000
ENV PYTHONPATH=/app
CMD ./start.sh
