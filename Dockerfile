FROM node:26.13.1-bookworm-slim

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY LICENSE THIRD_PARTY_NOTICES.md ./
COPY tsconfig.json drizzle.config.ts biome.json vitest.config.ts ./
COPY src/ ./src/
COPY test/unit/ ./test/unit/
COPY scripts/generate-keys.ts scripts/tsconfig.json ./scripts/
COPY docker/ ./docker/
RUN mkdir keys && chown node:node keys
USER node
EXPOSE 3000
CMD ["npm", "start"]
