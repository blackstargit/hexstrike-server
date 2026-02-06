# How to Run HexStrike AI in Docker on Windows (WSL)

This guide will help you run the HexStrike AI server inside a fully-loaded Kali Linux Docker container, completely managed from your Windows/WSL environment.

## Prerequisites

1.  **Docker Desktop for Windows**: Not installed? [Download here](https://www.docker.com/products/docker-desktop/).
    - Ensure **"Use the WSL 2 based engine"** is checked in Docker Desktop Settings > General.
    - Ensure your WSL distro is enabled in Docker Desktop Settings > Resources > WSL Integration.

## Step-by-Step Instructions

### 1. Build and Start the Container

Open your terminal (WSL or PowerShell) and navigate to this directory:

```bash
cd x:\code\hexstrike-main\hexstrike\original\hexstrike-ai
# Or in WSL, the path might look like:
# cd /mnt/x/code/hexstrike-main/hexstrike/original/hexstrike-ai
```

Run the following command to build the image (installing all tools) and start the server:

```bash
docker compose up --build -d
```

- `--build`: Rebuilds the image to ensure all tools are installed.
- `-d`: Detached mode (runs in the background).

_Note: The first build will take a while (10-20+ minutes) as it downloads and installs ~5GB+ of Kali tools._

### 2. Verify the Server is Running

Check the logs to make sure the HexStrike Python server started successfully:

```bash
docker compose logs -f
```

You should see output indicating the server is listening (usually on port 8888).

### 3. Using the Tools "Inside" the Container

The server is running, but if you need to manually run scans or access the tools (nmap, nuclei, etc.) interactively:

```bash
docker exec -it hexstrike-server /bin/bash
```

Once inside, you are in a fully configured Kali environment:

- **Python Virtual Env**: Active by default (via `ENV PATH`).
- **Go Tools**: Installed and in PATH (nuclei, subfinder, etc.).
- **Kali Tools**: Metasploit, Nmap, Burp Suite, etc., are confirmed installed.

Example commands to try inside:

```bash
nmap --version
nuclei -version
python hexstrike_server.py # (If you stopped the background one)
```

### 4. Stopping the Server

To stop and remove the container:

```bash
docker compose down
```

## Troubleshooting

- **Port Conflicts**: If port 8888 is in use, edit `docker-compose.yml` and change the port mapping (e.g., `9000:8888`).
- **Permission Errors**: Docker usually handles permissions, but if you have issues writing files, check directories mapped in `volumes`.
- **Git Bash / Windows Terminal Issues**:
  If you see an error like `exec: "C:/Program Files/Git/usr/bin/bash": ...`:
  - **Git Bash tries to convert paths.**
  - Use a double slash: `docker exec -it hexstrike-server //bin/bash`
  - Or simply: `docker exec -it hexstrike-server bash`
