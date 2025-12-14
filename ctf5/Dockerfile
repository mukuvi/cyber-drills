FROM node:20.14.0

WORKDIR /app

COPY . .

RUN npm install --build-from-source && npm install -g pm2

# Make init script executable
RUN chmod +x init.sh

EXPOSE 3000

# Use init.sh as entrypoint which will start the app with pm2
CMD ["./init.sh"]