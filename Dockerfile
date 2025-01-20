# Étape 1 : Utiliser une image Python légère comme base
FROM python:3.9-slim

# Étape 2 : Installer les dépendances système nécessaires
RUN apt-get update && apt-get install -y \
    build-essential \
    libffi-dev \
    libpq-dev \
    libatlas-base-dev \
    && rm -rf /var/lib/apt/lists/*

# Étape 3 : Définir le répertoire de travail dans le conteneur
WORKDIR /app

# Étape 4 : Copier les fichiers nécessaires dans le conteneur
COPY . /app

# Étape 5 : Installer les dépendances Python
RUN pip install --no-cache-dir -r requirements.txt

# Étape 6 : Exposer le port sur lequel l'application écoutera
EXPOSE 8080

# Étape 7 : Démarrer l'application avec Uvicorn
CMD ["uvicorn", "apiHandler:app", "--host", "0.0.0.0", "--port", "8080"]
