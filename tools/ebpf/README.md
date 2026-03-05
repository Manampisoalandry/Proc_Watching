# eBPF (optionnel)

Ce projet peut lire des événements eBPF depuis un fichier JSONL (par défaut: /tmp/procwatch_ebpf.jsonl).

## Pré-requis
- noyau Linux compatible eBPF
- bpftrace (ou un outil équivalent)
- exécution en root

## Exemple
```bash
sudo bpftrace procwatch.bt > /tmp/procwatch_ebpf.jsonl
```

Puis dans ProcWatch:
- endpoint: /api/ebpf/events
- variable d'environnement: PROCWATCH_EBPF_LOG=/tmp/procwatch_ebpf.jsonl
