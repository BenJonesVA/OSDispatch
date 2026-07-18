FROM node:20-alpine

RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app

COPY package*.json ./
RUN npm install --omit=dev --loglevel=error

COPY server.js ./
COPY db/ ./db/
COPY views/ ./views/

USER appuser

EXPOSE 3000

CMD ["node", "server.js"]
