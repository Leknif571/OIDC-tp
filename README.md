# OIDC-tp

Contributeur :

Noe Ziadi
Loan Keovilay
Valentin Mignon
Adel Boukada



Start projet :

Start le container docker de keycloak avec la commande :

```
docker run -p 8080:8080 -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:latest start-dev
```

Configurer keycloak en créant un realm et un client OIDC.

Créer un fichier .env à la racine du projet en vous référant à l'exemple .env-exemple

Lancer le serveur avec la commande :
node server.js

Rendez-vous sur http://localhost:3000 pour accéder à l'application.