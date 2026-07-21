# Aegis all-in-one, SINGLE process: FastAPI serves API + targets + dashboard
FROM node:20-alpine AS dash
WORKDIR /dash
COPY dashboard/package*.json ./
RUN npm install
COPY dashboard/ .
ARG VITE_AEGIS_API=
ENV VITE_AEGIS_API=$VITE_AEGIS_API
ARG VITE_DEFAULT_TARGET=http://localhost:8000/t0
ENV VITE_DEFAULT_TARGET=$VITE_DEFAULT_TARGET
ARG VITE_BUILD_TAG=full-app-v2
ENV VITE_BUILD_TAG=$VITE_BUILD_TAG
RUN npm run build

FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY aegis ./aegis
RUN pip install --no-cache-dir .
COPY --from=dash /dash/dist ./static
COPY deploy/start.sh /start.sh
RUN chmod +x /start.sh
EXPOSE 8000
CMD ["/start.sh"]
