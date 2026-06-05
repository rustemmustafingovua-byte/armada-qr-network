FROM node:22-alpine

WORKDIR /app

RUN apk add --no-cache python3 make g++

COPY package*.json ./
RUN npm ci --only=production

COPY . .

RUN mkdir -p /data/uploads /data/db

EXPOSE 3000

ENV NODE_ENV=production

CMD ["node", "server.js"]
