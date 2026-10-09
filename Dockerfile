# 1. Partimos de la imagen oficial, que ya trae Java y Dependency-Check instalados
FROM owasp/dependency-check:latest

# 2. Cambiamos a root para poder instalar Node.js
USER root
RUN apk add --no-cache nodejs npm

# 3. Instalamos las dependencias de nuestro servidor
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev
COPY . .

# 4. Ruta del ejecutable de Dependency-Check dentro de la imagen
ENV DC_PATH=/usr/share/dependency-check/bin/dependency-check.sh
EXPOSE 3000

# 5. La imagen oficial arranca Dependency-Check; lo reemplazamos por nuestro servidor
ENTRYPOINT []
CMD ["node", "server.js"]
