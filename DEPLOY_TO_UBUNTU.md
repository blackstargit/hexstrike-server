# Deploying HexStrike AI to Ubuntu Server via Docker Hub

This guide explains how to move your fully configured Docker image from your local Windows machine to a remote Ubuntu server using Docker Hub ("Docker Cloud").

## Prerequisites

1.  **Docker Hub Account**: Create one at [hub.docker.com](https://hub.docker.com/) if you haven't already.
2.  **SSH Access**: You must have SSH access to your Ubuntu server.

---

## Part 1: Push Image from Windows (Local)

**1. Login to Docker Hub**
Open your terminal (PowerShell or Git Bash) and log in to the Docker registry:

```bash
docker login
# Enter your Docker Hub Username and Password when prompted
```

**2. Tag the Image**
We need to alias your local image (`hexstrike-ai-hexstrike`) to point to your Docker Hub repository.
_Replace `YOUR_DOCKERHUB_USERNAME` with your real username (e.g., `johndoe123`)._

```bash
docker tag hexstrike-ai-hexstrike:latest YOUR_DOCKERHUB_USERNAME/hexstrike-ai:latest
```

**3. Push to Cloud**
Upload the image. _Warning: The image is large (~5GB+), so this will take time depending on your upload speed._

```bash
docker push YOUR_DOCKERHUB_USERNAME/hexstrike-ai:latest
```

---

## Part 2: Deploy on Ubuntu Server (Remote)

Connect to your Ubuntu server via SSH, then run the following commands.

**1. Install Docker (If not meant installed)**

```bash
sudo apt update
sudo apt install -y docker.io
sudo systemctl enable --now docker
# Add your user to docker group to run without sudo (Optional)
sudo usermod -aG docker $USER
newgrp docker
```

**2. Pull the Image**
Download the image you just pushed.
_Replace `YOUR_DOCKERHUB_USERNAME` with your username._

```bash
docker pull YOUR_DOCKERHUB_USERNAME/hexstrike-ai:latest
```

**3. Run the Container**
Run the server in the background using the code baked into the image.

- `--network host`: Allows the container to see the server's network interfaces (crucial for Nmap/scanning).
- `--privileged`: Gives tool access to raw sockets.
- `--restart unless-stopped`: Auto-restarts the server if it crashes or the server reboots.

```bash
docker run -d \
  --name hexstrike-server \
  --network host \
  --privileged \
  --restart unless-stopped \
  YOUR_DOCKERHUB_USERNAME/hexstrike-ai:latest
```

**4. Check Status**
Verify the server is running and view logs:

```bash
docker logs -f hexstrike-server
```

---

## Updating the Deployment

If you make code changes locally in Windows:

1.  **Rebuild locally**: `docker compose up --build -d`
2.  **Retag**: `docker tag hexstrike-ai-hexstrike:latest YOUR_USERNAME/hexstrike-ai:latest`
3.  **Push**: `docker push YOUR_USERNAME/hexstrike-ai:latest`
4.  **On Server**: `docker pull ...` and then stop/rm the old container and run the new one.
