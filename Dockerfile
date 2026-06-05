FROM node:22-alpine

RUN apk add --no-cache python3 make g++ tini

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

ARG BUILD_DATE=unknown
ENV BUILD_DATE=$BUILD_DATE

COPY . .

RUN mkdir -p /app/public/uploads /app/db && \
    addgroup -g 1001 nodejs && \
    adduser -S -u 1001 -G nodejs nodejs && \
    chown -R nodejs:nodejs /app

USER nodejs

ENV NODE_ENV=production
ENV PORT=3000
ENV UPLOAD_DIR=/app/public/uploads
ENV DB_PATH=/app/db/qrmaster.db

EXPOSE 3000

HEALTHCHECK --interval=60s --timeout=10s --start-period=60s --retries=5 \
  CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:3000/health || exit 1

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "server.js"]
