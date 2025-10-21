# Web Security Scanner

Scanner de sécurité web avec interface web.

## Utilisation

### Docker
```bash
docker run -p 5000:5000 ghcr.io/waddenn/scan:latest
```

### Local
```bash
pip install -r requirements.txt
python start_web.py
```

Interface : http://localhost:5000

## Fonctionnalités

- Analyse des en-têtes HTTP de sécurité
- Vérification des certificats SSL
- Rapports HTML avec graphiques
- Interface web responsive

## Docker Compose

```bash
docker-compose up
```