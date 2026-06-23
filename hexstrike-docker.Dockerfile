FROM hexstrike-base:stable

# Setup Workspace
WORKDIR /app

# Copy requirements FIRST to leverage cache
COPY requirements.txt .

# Create Virtual Env using our compiled Python 3.11
ENV VIRTUAL_ENV=/app/.venv
RUN python3.11 -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:/root/.local/bin:/usr/share/ghidra/support:$PATH"

RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# Install peda GDB extension (not present in base image; code expects ~/peda/peda.py)
RUN git clone --depth 1 https://github.com/longld/peda.git /root/peda

# Copy the rest of the application
COPY . .

# Expose the port
EXPOSE 8888

# Default command
CMD ["/app/.venv/bin/python", "hexstrike_server.py"]
