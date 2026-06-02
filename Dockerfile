FROM node:20-alpine
WORKDIR /app
COPY package.json .
RUN npm install
COPY server.js .
RUN mkdir -p /data
EXPOSE 3001
CMD ["node", "server.js"]
