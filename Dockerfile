# Étape 1 : Utiliser une image Python légère comme base
FROM python:3.9-slim

# Étape 2 : Définir le répertoire de travail dans le conteneur
WORKDIR /app

# Étape 3 : Copier les fichiers nécessaires dans le conteneur
COPY . /app

# Étape 4 : Installer les dépendances Python
RUN pip install --no-cache-dir -r requirements.txt

# Étape 5 : Configurer les variables d'environnement pour la base de données
ENV DATABASE_URL="mysql+pymysql://lophias:EqHVe0\`VFEA32zsC@hackeco-recycli:3306/recycli"

# Étape 6 : Exposer le port sur lequel l'application écoutera
EXPOSE 8080

# Étape 7 : Démarrer l'application avec Uvicorn
CMD ["uvicorn", "apihandler:app", "--host", "0.0.0.0", "--port", "8080"]
