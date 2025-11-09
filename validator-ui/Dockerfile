# syntax=docker/dockerfile:1

ARG ASSET_BASE_PATH=/

FROM node:20-bullseye AS builder

ARG ASSET_BASE_PATH
WORKDIR /app

# Configure pnpm via Corepack and install dependencies
RUN corepack enable

COPY validator-ui/pnpm-lock.yaml validator-ui/package.json ./
RUN pnpm install --frozen-lockfile

COPY validator-ui/ .

# Ensure the asset base path is available during the build step
ENV ASSET_BASE_PATH=${ASSET_BASE_PATH}
RUN pnpm build

FROM nginx:1.27-alpine AS runtime

ARG ASSET_BASE_PATH
ENV ASSET_BASE_PATH=${ASSET_BASE_PATH}

RUN addgroup -S app && adduser -S -G app app

COPY validator-ui/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /app/dist /usr/share/nginx/html

HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:8080/healthz || exit 1

USER app

EXPOSE 8080
CMD ["nginx", "-g", "daemon off;"]
