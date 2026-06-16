FROM kalilinux/kali-rolling:2025.4

# Prevent prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Update and Upgrade
RUN apt update && apt full-upgrade -y

# Install Tools & Dependencies
RUN apt install -y \
    # Basics & Network
    curl=8.18.0-2 \
    wget=1.25.0-2 \
    git=1:2.51.0-1 \
    build-essential=12.12 \
    jq=1.8.1-4+b1 \
    ca-certificates=20250419 \
    libssl-dev=3.5.4-1+b1 \
    zlib1g-dev=1:1.3.dfsg+really1.3.1-1+b2 \
    libffi-dev=3.5.2-3+b1 \
    libsqlite3-dev=3.46.1-9 \
    libbz2-dev=1.0.8-6+b1 \
    libreadline-dev=8.3-3+b1 \
    liblzma-dev=5.8.2-2 \
    tk-dev=8.6.16 \
    uuid-dev=2.41.3-3 \
    apt-transport-https=3.1.14+kali1 \
    libncurses5-dev \
    # Python (System default) & Go & Rust
    python3-pip=25.3+dfsg-1 \
    golang-go=2:1.24~2 \
    cargo=1.91.1+dfsg1-1 \
    # Network Scanning & Enumeration
    nmap=7.98+dfsg-1kali1 \
    netcat-traditional=1.10-50.1 \
    wireshark=4.6.3-1 \
    gobuster=3.8.2-1 \
    ffuf=2.1.0-1+b10 \
    masscan=2:1.3.2+ds1-2 \
    amass=5.0.1-0kali4 \
    dnsenum=1.3.2-1 \
    theharvester=4.9.2-0kali1 \
    responder=3.2.2.0-0kali1 \
    netexec=1.5.0-0kali1 \
    fierce=1.6.0-1 \
    # Web
    feroxbuster=2.13.1-0kali1 \
    dirb=2.22+dfsg-7 \
    nikto=1:2.5.0+git20230114.90ff645-0kali1 \
    sqlmap=1.10-1 \
    arjun=2.2.7-1 \
    wafw00f=2.3.2-1 \
    wpscan=3.8.28-0kali1 \
    # Passwords & Auth
    hydra=9.6-3 \
    john=1.9.0-Jumbo-1+git20211102-0kali10 \
    hashcat=7.1.2+ds1-3 \
    wordlists=2026.1.2 \
    # Wireless & SMB
    aircrack-ng=1:1.7+git20230807.4bf83f1a-2+b1 \
    smbclient=2:4.23.5+dfsg-1 \
    # Enum / Recon
    enum4linux=0.9.1-0kali2 \
    enum4linux-ng=1.3.7-0kali1 \
    autorecon=0.0~git20251116.e7e98f6-0kali1 \
    impacket-scripts=1.10 \
    seclists=2025.3-0kali1 \
    sublist3r=1.1-5 \
    exploitdb=20260118-0kali1 \
    # Binary Analysis / Reversing
    steghide=0.5.1-15 \
    foremost=1.5.7-11+b2 \
    ghidra=12.0.2+ds-0kali1 \
    gdb=17.1-2 \
    # Frameworks
    metasploit-framework=6.4.111-0kali1 \
    burpsuite=2025.12.5-0kali1 \
    # Cloud
    trivy=0.66.0-0kali1 \
    # Misc
    pipx=1.8.0-1 \
 && rm -rf /var/lib/apt/lists/*

# Compile Python 3.11 from Source (Mirrors VM Instructions)
WORKDIR /usr/src
RUN wget https://www.python.org/ftp/python/3.11.9/Python-3.11.9.tgz && \
    tar -xzf Python-3.11.9.tgz && \
    cd Python-3.11.9 && \
    ./configure --enable-optimizations --with-ensurepip=install && \
    make -j$(nproc) && \
    make altinstall && \
    cd .. && rm -rf Python-3.11.9*

# Verify Python 3.11
RUN python3.11 --version

# Ensure pip for 3.11
RUN python3.11 -m ensurepip && \
    python3.11 -m pip install --upgrade pip

# Install Cloud Tools with pipx
RUN pipx ensurepath
RUN pipx install prowler==3.11.3
RUN pipx install scoutsuite==5.14.0

# Create standard dirbuster wordlist symlinks (wordlists pkg uses seclists naming)
RUN mkdir -p /usr/share/wordlists/dirbuster && \
    ln -sf /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt && \
    ln -sf /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt  /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt && \
    ln -sf /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt   /usr/share/wordlists/dirbuster/directory-list-2.3-big.txt

# Go Environment
ENV GOPATH=/root/go
ENV PATH=$PATH:/usr/local/go/bin:$GOPATH/bin

# Go Tools
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.12.0 && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.7.0 && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@v1.4.0 && \
    go install -v github.com/hahwul/dalfox/v2@v2.12.0

# Update Nuclei templates
RUN nuclei -update-templates

# Rustscan
ENV PATH=$PATH:/root/.cargo/bin
RUN cargo install rustscan --version 2.4.1

# ParamSpider (pinned to tested commit)
RUN git clone https://github.com/devanshbatham/ParamSpider.git /opt/ParamSpider && \
    cd /opt/ParamSpider && \
    git checkout 790eb91213419e9c4ddec2c91201d4be5399cb77 && \
    pipx install .

# Setup Workspace
WORKDIR /app

# Copy requirements FIRST to leverage cache
COPY requirements.txt .

# Create Virtual Env using our compiled Python 3.11
ENV VIRTUAL_ENV=/app/.venv
RUN python3.11 -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# Copy the rest of the application
COPY . .

# Expose the port
EXPOSE 8888

# Default command
CMD ["/app/.venv/bin/python", "hexstrike_server.py"]
