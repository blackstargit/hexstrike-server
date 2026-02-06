FROM kalilinux/kali-rolling

# Prevent prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Update and Upgrade
RUN apt update && apt full-upgrade -y

# Install Tools & Dependencies
# Removed 'python3.11' specific packages as they are not in the repo; we will build from source.
# Added 'libncurses5-dev' and other build deps for Python compilation.
RUN apt install -y \
    # Basics & Network
    curl wget git build-essential jq ca-certificates \
    libssl-dev zlib1g-dev libffi-dev libsqlite3-dev libbz2-dev \
    libreadline-dev liblzma-dev tk-dev uuid-dev \
    apt-transport-https libncurses5-dev \
    # Python (System default) & Go & Rust
    python3-pip golang-go cargo \
    # Network Scanning & Enumeration
    nmap netcat-traditional wireshark gobuster ffuf \
    masscan amass dnsenum theharvester responder \
    netexec fierce \
    # Web
    feroxbuster dirb nikto sqlmap arjun wafw00f wpscan \
    # Passwords & Auth
    hydra john hashcat \
    # Wireless & SMB
    aircrack-ng smbclient \
    # Enum / Recon
    enum4linux enum4linux-ng autorecon \
    impacket-scripts seclists sublist3r exploitdb \
    # Binary Analysis / Reversing
    steghide foremost ghidra gdb \
    # Frameworks
    metasploit-framework burpsuite \
    # Cloud
    trivy \
    # Misc
    pipx \
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
RUN pipx install prowler
RUN pipx install scoutsuite

# Go Environment
ENV GOPATH=/root/go
ENV PATH=$PATH:/usr/local/go/bin:$GOPATH/bin

# Go Tools
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -v github.com/hahwul/dalfox/v2@latest

# Update Nuclei templates
RUN nuclei -update-templates

# Rustscan
ENV PATH=$PATH:/root/.cargo/bin
RUN cargo install rustscan

# ParamSpider
RUN git clone https://github.com/devanshbatham/ParamSpider.git /opt/ParamSpider && \
    cd /opt/ParamSpider && \
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