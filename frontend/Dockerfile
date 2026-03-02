FROM node:20-alpine

RUN corepack enable && corepack prepare pnpm@latest --activate

ENV CI=true

WORKDIR /app

COPY package.json ./
RUN pnpm install

COPY . .

EXPOSE 3000

CMD ["pnpm", "dev"]
