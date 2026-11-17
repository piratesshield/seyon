FROM node:20-slim

WORKDIR /app
COPY . .
RUN npm ci --omit=dev

# Drops to a dedicated non-root user before running the server.
USER node
CMD ["node", "server.js"]
