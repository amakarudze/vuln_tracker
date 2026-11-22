FROM node:26-alpine
WORKDIR /app
COPY package*.json .
RUN npm ci --omit=dev
COPY . /app
CMD ["node","./src/app.js"]