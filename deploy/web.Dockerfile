# CyberGuard website + web server for the cloud server (9 Nov 2026). Built by deploy/docker-compose.cloud.yml
# (context: the project folder; .dockerignore keeps .env files, the backend and Git history out).

# 1) build the website in "public" mode: it calls /api on its own address
FROM node:22-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
# The Turnstile SITE key is public by design (it is shown in every visitor's browser); the SECRET key stays on the
# backend only.
ARG VITE_TURNSTILE_SITE_KEY=""
ENV VITE_TURNSTILE_SITE_KEY=$VITE_TURNSTILE_SITE_KEY
# (9 Nov) Google sign-in: the OAuth CLIENT ID is public too (Google shows it in the browser); empty = no Google button
ARG VITE_GOOGLE_CLIENT_ID=""
ENV VITE_GOOGLE_CLIENT_ID=$VITE_GOOGLE_CLIENT_ID
RUN npm run build -- --mode public

# 2) Caddy serves the website and sends /api/* to the backend; it gets and renews the HTTPS certificate itself
FROM caddy:2.10-alpine
COPY deploy/Caddyfile /etc/caddy/Caddyfile
COPY --from=build /app/dist /srv
