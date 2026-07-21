# Déployer Aegis (app complète : dashboard + API + cibles)

L'app est un conteneur unique : un processus FastAPI sert tout (front, API, cibles).

## Option A — Render (gratuit, le plus simple)
1. Push le repo sur GitHub
2. render.com → **New → Blueprint** → sélectionne le repo (le `render.yaml` est détecté)
3. C'est tout — Render build le Dockerfile et expose l'URL publique

## Option B — Railway
1. railway.app → **New Project → Deploy from GitHub repo**
2. Le `railway.toml` configure tout (Dockerfile + healthcheck)

## Option C — VPS / ta machine
```bash
docker build -t aegis .
docker run -p 8000:8000 -e AEGIS_SECRET_KEY=$(openssl rand -hex 32) aegis
# → http://localhost:8000
```

## Après déploiement
1. Crée ton compte sur l'écran de connexion
2. (Optionnel) Ajoute ta clé Kimi Code dans "Your LLM provider key" pour le mode agentique
3. Audite les cibles intégrées (/t0 /t1 /t2) ou vérifie tes propres sites dans "My targets"
