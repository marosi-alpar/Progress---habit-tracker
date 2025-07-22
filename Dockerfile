# Use an official Node image as base
FROM node:22

# Create app directory
WORKDIR /app

# Copy package.json and install dependencies
COPY package*.json ./
RUN npm install

# Copy source code
COPY . .

# Build the app
RUN npm run build

# Expose the port NestJS listens on (default 3000)
EXPOSE 8080

# Start the app
CMD ["node", "dist/src/main"]
