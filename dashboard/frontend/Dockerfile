# Dashboard Frontend Dockerfile
FROM node:18-alpine

WORKDIR /app

# Install dependencies
COPY dashboard/frontend/package.json /app/package.json
# If a lockfile exists, copy it to improve reproducibility
# COPY dashboard/frontend/package-lock.json /app/package-lock.json
RUN npm install --legacy-peer-deps

# Copy source
COPY dashboard/frontend/ /app/

EXPOSE 3000

# Default command: start development server
CMD ["npm", "start"]
