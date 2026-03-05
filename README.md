# ProcWatch (Debian) — Flask

Application web locale pour lister les processus (style `top`) et appliquer un **scoring heuristique** pour repérer des **scripts / exécutions fileless / persistance / comportements atypiques**.

Couleurs:
- **Bleu**: système
- **Vert**: applications
- **Jaune**: commandes (CLI)
- **Rouge**: **suspect** (score heuristique >= seuil)

> Important: ce n’est pas un antivirus. “Rouge” = “à investiguer”.

---

## Fonctionnalités ajoutées

### 1) Détection renforcée “scripts malveillants”
- Interpréteurs (bash/sh/python/node/php/perl/ruby)
- Exécutions inline (`-c/-e/-r`)
- `curl|bash`, `wget|sh`, base64/openssl, reverse shell, persistance cron/systemd, mineur
- Lecture best-effort de variables d’environnement (LD_PRELOAD, BASH_ENV, etc.)
- **Scan du contenu du script** (si un chemin de script est détectable et lisible)

### 2) Corrélation parent → enfant (process tree)
- Chaîne parent/grand-parent (jusqu’à 3 niveaux)
- Détection `curl/wget -> interpréteur` et patterns “LOLBins chain”

### 3) Analyse réseau (résumé + scoring)
- Comptage des IP privées/publiques
- Ports atypiques (heuristique)
- Volume de connexions

### 4) Intégrité / provenance
- **Propriétaire dpkg** via `dpkg -S` (cache)
- Signal si binaire “système” sans paquet dpkg

### 5) Baseline (SQLite)
- Enregistre les hashes (SHA256) et commandes déjà vus
- Signale les binaires/commandes “jamais vus” (conservateur)

### 6) Allowlist (whitelist)
- Fichier `data/allowlist.json`
- Permet de réduire les faux positifs (hash, chemin, regex cmdline, nom, user)

### 7) Actions (optionnelles, protégées par token)
- Suspend / Resume / Kill / Renice
- Modification allowlist
- Nécessite `PROCWATCH_ADMIN_TOKEN`

### 8) Export / Diff
- Export JSON / CSV
- Diff entre snapshots (process démarrés/arrêtés, changements de score)

### 9) Auditd (best-effort)
- Lecture de `/var/log/audit/audit.log` (si présent)
- Regroupe événements par record id (SYSCALL/EXECVE)

### 10) eBPF (optionnel)
- Intégration via fichier JSONL (par défaut `/tmp/procwatch_ebpf.jsonl`)
- Script bpftrace fourni dans `tools/ebpf/`

### 11) YARA (optionnel)
- Si `yara-python` est installé, scan possible (sur demande) via l’UI
- Règles basiques dans `rules/yara/`

---

## Installation

```bash
cd procwatch
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Optionnel: YARA
```bash
pip install yara-python
```

---

## Lancer

Sans actions admin:
```bash
python app.py
```

Avec actions admin + seuil rouge modifiable:
```bash
export PROCWATCH_ADMIN_TOKEN="change-moi"
export PROCWATCH_RED_THRESHOLD=3
python app.py
```

Puis:
- local: http://127.0.0.1:5000
- LAN: http://IP_DE_TA_MACHINE:5000

---

## Notes importantes (fiabilité)
- Le scoring est **heuristique**. Attends-toi à des **faux positifs** et des **faux négatifs**.
- Sans root, plusieurs infos peuvent être vides (cwd, environ, connexions, open_files).
- Pour des enquêtes sérieuses: combine avec journaux (auditd/syslog), intégrité (AIDE), et outils dédiés.
