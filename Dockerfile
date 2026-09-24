# Development image — runs the Vite dev server.
# For production, build static assets and deploy to Vercel/any static host
# (see README "Vercel Deployment").
FROM node:20-slim

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm install

COPY . .

EXPOSE 5173
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
