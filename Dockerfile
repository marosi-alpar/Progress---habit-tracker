# Use an official Node image as base
# FROM node:22-slim
FROM --platform=linux/amd64 node:22-slim

# Create app directory
WORKDIR /usr/src/app

# Copy package.json and install dependencies
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy source code
COPY . .

# Build the app
RUN npm run build

# Expose the port NestJS listens on (default 80)
EXPOSE 80

# Start the app
CMD ["node", "dist/src/main.js"]
