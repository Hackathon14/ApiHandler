# Étape 1 : Utiliser une image Python 3.10 comme base
FROM python:3.10-slim

# Étape 2 : Installer les dépendances système nécessaires
RUN apt-get update && apt-get install -y \
    build-essential \
    libffi-dev \
    libpq-dev \
    libatlas-base-dev \
    && rm -rf /var/lib/apt/lists/*

# Étape 3 : Mettre à jour pip
RUN pip install --upgrade pip

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
