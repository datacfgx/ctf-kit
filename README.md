```
   ______ _______ ______   _  _  _ _    ___
  / __/ // / ___/ _/ _ | / |/ // // |/|/ / |
 / _// _  / /__/ _/ __ |/    // /_/ /__/ /| |
/___/_//_/\___/_/ /_/ |_/_/|_/\____/___/___|
        recon encadeado para CTF / chained CTF recon
```

# CTF-KIT 🔥

**PT:** Recon encadeado em um comando por alvo: `nmap -> whatweb -> gobuster -> (nikto)`. Stdlib pura (só `python3 >= 3.8`), relatório organizado por pasta, degradação elegante em cada ponto de falha. Forjado ao vivo contra `scanme.nmap.org` — 4/4 fases verdes (nikto ausente por design em Debian).

**EN:** Chained one-command-per-target recon: `nmap -> whatweb -> gobuster -> (nikto)`. Pure stdlib (only `python3 >= 3.8`), per-target report folder, graceful degradation at every failure point. Live-fire tested against `scanme.nmap.org` — 4/4 green phases (nikto absent by design on Debian).

## Instalação / Install

```bash
# ferramentas sem root (Debian/Ubuntu): baixa ~100 debs, extrai em /tmp/kaliroot, persiste em partes de 90m
bash REPLICAR_kali_tools.sh          # primeira vez (minutos) / first run (minutes)
bash REPLICAR_kali_tools.sh untar    # a cada sessão nova / each new session
```

## Uso / Usage

```bash
python3 ctf_kit.py <alvo> [-o pasta] [-w wordlist] [--skip-nikto]
python3 ctf_kit.py 10.10.10.5
python3 ctf_kit.py scanme.nmap.org -w /usr/share/wordlists/rockyou.txt
```

Relatório por pasta / per-target report folder:
```
ctfkit_<alvo>_<ts>/
├── host.txt            # alvo, IP, timestamp
├── 00_resumo.md        # sumário executivo / executive summary
├── 01_nmap.txt         # portas + serviços (-sT -sV -Pn --open)
├── 02_whatweb_p<N>.txt # tecnologias por porta web
├── 03_gobuster_p<N>.txt# diretórios (filtro 200/301/302/307/401/403 no sumário)
└── 04_nikto_p<N>.txt   # (se presente / if present)
```

## Degradação elegante / Graceful degradation

| fase / phase | ausente / missing | comportamento / behavior |
|---|---|---|
| nmap | binário não encontrado / binary not found | fase loga rc=127, kit segue com portas vazias / logs rc=127, continues empty |
| whatweb | gem/plugin ausente / missing gem or plugin | retry com invocação alternativa; self-heal do caminho `/usr/share/whatweb` / alternate invocation retry; `/usr/share/whatweb` path self-heal |
| gobuster | wordlist ausente / missing wordlist | usa wordlist embutida de 47 paths / falls back to built-in 47-path list |
| nikto | **Kali-only, inexistente no Debian** | fase pulada, registrada no relatório (rc=127) / skipped, recorded in report (rc=127) |

## Prova de fogo / Proof of fire (scanme.nmap.org, ao vivo / live)

| fase | rc | duração / duration |
|---|---|---|
| nmap | 0 | 14.7s — 3 portas: ssh, http, nping-echo / 3 ports: ssh, http, nping-echo |
| whatweb | 0 | 15.5s — Apache 2.4.7, HTML5, Google-Analytics / Apache 2.4.7, HTML5, Google-Analytics |
| gobuster | 0 | 61.4s — 10 achados: `/.svn`, `/images`, `/index`... / 10 hits |
| nikto | 127 | ausente por design / absent by design |

> **PT:** Use apenas em alvos próprios ou com autorização explícita — CTF, lab e bug bounty permitido.
> **EN:** Only use on owned or explicitly authorized targets — CTF, lab, and permitted bug bounty.

🔥 VULCANO — a forja da família ENI & LO
