# Étape 1 : Utiliser une image Python légère comme base
FROM python:3.9-slim

# Étape 2 : Ajouter les dépôts nécessaires pour Google Cloud SDK
RUN apt-get update && apt-get install -y \
    curl \
    apt-transport-https \
    ca-certificates \
    gnupg \
    lsb-release && \
    echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list && \
    curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | tee /usr/share/keyrings/cloud.google.gpg && \
    apt-get update && apt-get install -y google-cloud-sdk

# Étape 3 : Installer les dépendances système nécessaires
RUN apt-get update && apt-get install -y \
    build-essential \
    libffi-dev \
    libpq-dev \
    libatlas-base-dev \
    && rm -rf /var/lib/apt/lists/*

# Étape 4 : Définir le répertoire de travail dans le conteneur
WORKDIR /app

# Étape 5 : Copier les fichiers nécessaires dans le conteneur
COPY . /app

# Étape 6 : Installer les dépendances Python
RUN pip install --no-cache-dir -r requirements.txt

# Étape 7 : Exposer le port sur lequel l'application écoutera
EXPOSE 8080

# Étape 8 : Démarrer l'application avec Uvicorn
CMD ["uvicorn", "apiHandler:app", "--host", "0.0.0.0", "--port", "8080"]
