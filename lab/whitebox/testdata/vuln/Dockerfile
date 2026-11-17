FROM node:20-slim

WORKDIR /app
COPY . .

# D3: fetches remote code and pipes it straight into a shell at build time.
RUN curl -fsSL https://install.example.com/setup.sh | sh

# D3: no non-root USER directive, so the server runs as root.
CMD ["node", "server.js"]
