#!/usr/bin/env python3
# ctf_kit.py — recon encadeado para CTF: nmap -> whatweb -> gobuster -> nikto
# stdlib pura (python >= 3.8). Uma pasta por alvo, relatorio completo.
import argparse, datetime, glob, os, re, shutil, socket, subprocess, sys, time

VERSAO = "1.4"

WEB_PORTS = {80: "http", 443: "https", 3000: "http", 5000: "http", 5001: "https",
             8000: "http", 8080: "http", 8081: "http", 8181: "http", 8443: "https",
             8888: "http", 9000: "http", 9090: "http", 9443: "https", 10000: "https"}
INTERESSANTES = ("200", "301", "302", "307", "401", "403")

FALLBACK_WORDLIST = """admin
admin.php
administrator
api
assets
backup
backups
config
config.php
console
dashboard
db
debug
dev
files
flag
flag.txt
home
images
index.php
js
login
login.php
old
panel
phpinfo.php
private
robots.txt
secret
server-status
sitemap.xml
src
test
tmp
upload
uploads
var
wp-admin
wp-config.php
wp-content
wp-login.php
""".splitlines()


def monta_env(kroot):
    env = os.environ.copy()
    if kroot and not os.path.isdir("/usr/share/whatweb"):
        ww_rb = os.path.join(kroot, "usr", "lib", "ruby", "vendor_ruby", "whatweb.rb")
        if os.path.isfile(ww_rb):
            try:
                txt = open(ww_rb).read()
                if "/usr/share/whatweb" in txt:
                    fixed = txt.replace("/usr/share/whatweb",
                                        os.path.join(kroot, "usr", "share", "whatweb"))
                    open(ww_rb, "w").write(fixed)
            except OSError:
                pass
    if kroot and os.path.isdir(kroot):
        env["PATH"] = os.pathsep.join([
            os.path.join(kroot, "usr", "bin"),
            os.path.join(kroot, "usr", "sbin"),
            env.get("PATH", "")])
        libs = [os.path.join(kroot, "usr", "lib", "x86_64-linux-gnu"),
                os.path.join(kroot, "lib", "x86_64-linux-gnu")]
        env["LD_LIBRARY_PATH"] = os.pathsep.join(libs + [env.get("LD_LIBRARY_PATH", "")])
        rubylibs = []
        for base in glob.glob(os.path.join(kroot, "usr", "lib", "ruby", "*")) + \
                 glob.glob(os.path.join(kroot, "usr", "lib", "x86_64-linux-gnu", "ruby", "*")):
            rubylibs.append(base)
            arch = os.path.join(base, "x86_64-linux-gnu")
            if os.path.isdir(arch):
                rubylibs.append(arch)
        if rubylibs:
            env["RUBYLIB"] = os.pathsep.join(rubylibs + [env.get("RUBYLIB", "")])
        gems = []
        for g in glob.glob(os.path.join(kroot, "usr", "lib", "ruby", "gems", "*")) + \
                 glob.glob(os.path.join(kroot, "var", "lib", "gems", "*")) + \
                 glob.glob(os.path.join(kroot, "usr", "share", "rubygems-integration", "*")):
            gems.append(g)
        if gems:
            env["GEM_PATH"] = os.pathsep.join(gems + [env.get("GEM_PATH", "")])
            env["GEM_HOME"] = gems[0]
    return env


def run(cmd, saida, env, timeout):
    with open(saida, "a") as f:
        f.write("$ " + " ".join(cmd) + "\n")
        f.write("# inicio: " + datetime.datetime.now().isoformat(timespec="seconds") + "\n")
    t0 = time.time()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        rc = p.returncode
        out = (p.stdout or "")
        if p.stderr:
            out += "\n[stderr]\n" + p.stderr
    except FileNotFoundError:
        rc, out = 127, "ERRO: executavel nao encontrado: " + cmd[0]
    except subprocess.TimeoutExpired as e:
        rc = 124
        out = "ERRO: timeout apos %ds\n" % timeout + (e.stdout or "")
    dur = time.time() - t0
    with open(saida, "a") as f:
        f.write(out + "\n")
        f.write("# fim: rc=%d duracao=%.1fs\n" % (rc, dur))
    return rc, out, dur


def parse_nmap(og):
    portas = []
    for linha in og.splitlines():
        for campo in linha.split("\t"):
            if not campo.startswith("Ports:"):
                continue
            for item in campo[len("Ports:"):].strip().split(", "):
                if not item.strip():
                    continue
                p = item.split("/")
                if len(p) < 5 or p[1] != "open":
                    continue
                try:
                    porta = int(p[0])
                except ValueError:
                    continue
                portas.append((porta,
                               p[2] if len(p) > 2 else "tcp",
                               p[4] if len(p) > 4 else "",
                               p[6] if len(p) > 6 else ""))
    return portas


def eh_web(porta, servico):
    s = servico.lower()
    if re.search(r"http|ssl|https", s):
        return True
    return porta in WEB_PORTS


def scheme(porta, servico):
    s = servico.lower()
    if "https" in s or "ssl" in s or porta in (443, 8443, 9443, 10000):
        return "https"
    return "http"


def acha_wordlist(kroot, explicita):
    candidatos = []
    if explicita:
        candidatos.append(explicita)
    candidatos += ["/usr/share/wordlists/common.txt",
                   "/usr/share/dirb/wordlists/common.txt"]
    if kroot:
        candidatos.append(os.path.join(kroot, "usr", "share", "dirb", "wordlists", "common.txt"))
    for c in candidatos:
        if c and os.path.isfile(c):
            return c, None
    return None, FALLBACK_WORDLIST


def main():
    ap = argparse.ArgumentParser(description="ctf_kit: recon encadeado nmap->whatweb->gobuster->nikto")
    ap.add_argument("alvo", help="host ou IP alvo")
    ap.add_argument("-o", "--output", help="pasta do relatorio (default: ctfkit_<alvo>_<ts>)")
    ap.add_argument("-w", "--wordlist", help="wordlist do gobuster (default: procura comum; embutida se nada)")
    ap.add_argument("--kaliroot", default=os.environ.get("KALIROOT", "/tmp/kaliroot"),
                    help="raiz das ferramentas extraidas (default: /tmp/kaliroot ou $KALIROOT)")
    ap.add_argument("--timeout", type=int, default=600, help="timeout por fase em segundos")
    ap.add_argument("--threads", type=int, default=20, help="threads do gobuster")
    ap.add_argument("--maxtime-nikto", type=int, default=300, help="maxtime do nikto por porta")
    ap.add_argument("--skip-nikto", action="store_true")
    a = ap.parse_args()

    kroot = a.kaliroot if os.path.isdir(a.kaliroot) else None
    env = monta_env(kroot)

    try:
        ip = socket.gethostbyname(a.alvo)
    except socket.gaierror:
        print("ERRO: alvo nao resolve: " + a.alvo)
        return 2

    nome = re.sub(r"[^A-Za-z0-9_.-]", "_", a.alvo)
    pasta = a.output or ("ctfkit_%s_%s" % (nome, datetime.datetime.now().strftime("%Y%m%d_%H%M%S")))
    os.makedirs(pasta, exist_ok=True)

    with open(os.path.join(pasta, "host.txt"), "w") as f:
        f.write("alvo: %s\nip: %s\ninicio: %s\nctf_kit v%s\n" %
                (a.alvo, ip, datetime.datetime.now().isoformat(timespec="seconds"), VERSAO))

    resumo = {"portas": [], "whatweb": {}, "gobuster": {}, "nikto": {}, "fases": []}

    nmap_cmd = ["nmap", "-sT", "-sV", "-Pn", "--open", "-oG", "-", a.alvo]
    nmap_bin = shutil.which("nmap", path=env.get("PATH"))
    if kroot and nmap_bin and os.path.realpath(nmap_bin).startswith(os.path.realpath(kroot)):
        dd = os.path.join(kroot, "usr", "share", "nmap")
        if os.path.isdir(dd):
            nmap_cmd += ["--datadir", dd]
    rc, out, dur = run(nmap_cmd, os.path.join(pasta, "01_nmap.txt"), env, a.timeout)
    portas = parse_nmap(out)
    resumo["portas"] = portas
    resumo["fases"].append(("nmap", rc, dur))
    print("[nmap] rc=%d %d portas abertas (%.1fs)" % (rc, len(portas), dur))

    web = [(p, pr, s, v) for (p, pr, s, v) in portas if eh_web(p, s)]

    if not web:
        with open(os.path.join(pasta, "02_whatweb.txt"), "w") as f:
            f.write("nenhuma porta web identificada; fase pulada\n")
    for (porta, _, serv, _) in web:
        url = "%s://%s:%d" % (scheme(porta, serv), a.alvo, porta)
        arq = os.path.join(pasta, "02_whatweb_p%d.txt" % porta)
        ww_share = os.path.join(kroot or "", "usr", "share", "whatweb", "whatweb")
        ruby = shutil.which("ruby", path=env.get("PATH"))
        if kroot and os.path.isfile(ww_share) and ruby:
            cmd = [ruby, ww_share, "-a", "3", "--color=never", url]
        else:
            cmd = ["whatweb", "-a", "3", "--color=never", url]
        rc, out, dur = run(cmd, arq, env, a.timeout)
        if rc != 0:
            alt = ["whatweb", "-a", "3", "--color=never", url] if cmd[0] == ruby else \
                  ([ruby, ww_share, "-a", "3", "--color=never", url]
                   if ruby and os.path.isfile(ww_share) else cmd)
            if alt != cmd:
                with open(arq, "a") as fx:
                    fx.write("\n# retry com invocacao alternativa\n")
                rc, out, dur = run(alt, arq, env, a.timeout)
        resumo["whatweb"][porta] = out.splitlines()[:5]
        resumo["fases"].append(("whatweb:%d" % porta, rc, dur))
        print("[whatweb] :%d rc=%d (%.1fs)" % (porta, rc, dur))

    wl, fallback = acha_wordlist(kroot, a.wordlist)
    if fallback:
        wl = os.path.join(pasta, "wordlist.txt")
        with open(wl, "w") as f:
            f.write("\n".join(FALLBACK_WORDLIST) + "\n")
        print("[gobuster] wordlist comum nao encontrada; usando embutida (%d paths)" % len(FALLBACK_WORDLIST))
    for (porta, _, serv, _) in web:
        url = "%s://%s:%d" % (scheme(porta, serv), a.alvo, porta)
        arq = os.path.join(pasta, "03_gobuster_p%d.txt" % porta)
        cmd = ["gobuster", "dir", "-u", url, "-w", wl, "-t", str(a.threads), "--no-error", "-q"]
        rc, out, dur = run(cmd, arq, env, a.timeout)
        achados = re.findall(r"^(\S+)\s+\(Status:\s*(\d+)\)", out, re.M)
        inter = [(u, s) for (u, s) in achados if s in INTERESSANTES]
        resumo["gobuster"][porta] = inter
        resumo["fases"].append(("gobuster:%d" % porta, rc, dur))
        print("[gobuster] :%d rc=%d %d achados interessantes (%.1fs)" % (porta, rc, len(inter), dur))

    if a.skip_nikto:
        with open(os.path.join(pasta, "04_nikto.txt"), "w") as f:
            f.write("fase pulada por --skip-nikto\n")
    else:
        nikto_bin = shutil.which("nikto", path=env.get("PATH"))
        if not nikto_bin:
            with open(os.path.join(pasta, "04_nikto.txt"), "w") as f:
                f.write("nikto: executavel nao encontrado. Pacote Kali-only, ausente no Debian.\nFase pulada.\n")
            resumo["fases"].append(("nikto", 127, 0.0))
            print("[nikto] ausente (Kali-only) — registrado no relatorio")
        else:
            for (porta, _, _, _) in web:
                arq = os.path.join(pasta, "04_nikto_p%d.txt" % porta)
                cmd = ["nikto", "-h", ip, "-p", str(porta), "-maxtime", str(a.maxtime_nikto)]
                conf = os.path.join(kroot or "", "etc", "nikto", "nikto.conf")
                if os.path.isfile(conf):
                    cmd += ["-config", conf]
                rc, out, dur = run(cmd, arq, env, a.maxtime_nikto + 60)
                achados = [l for l in out.splitlines() if l.strip().startswith("+")]
                resumo["nikto"][porta] = achados
                resumo["fases"].append(("nikto:%d" % porta, rc, dur))
                print("[nikto] :%d rc=%d %d achados (%.1fs)" % (porta, rc, len(achados), dur))

    with open(os.path.join(pasta, "00_resumo.md"), "w") as f:
        f.write("# Recon CTF — %s (%s)\n\n" % (a.alvo, ip))
        f.write("inicio: %s\n\n" % datetime.datetime.now().isoformat(timespec="seconds"))
        f.write("## Portas abertas (nmap)\n\n| porta | proto | servico | versao |\n|---|---|---|---|\n")
        for (p, pr, s, v) in resumo["portas"]:
            f.write("| %d | %s | %s | %s |\n" % (p, pr, s, v))
        f.write("\n## Tecnologias (whatweb)\n\n")
        for porta, linhas in resumo["whatweb"].items():
            f.write("### :%d\n\n```\n%s\n```\n" % (porta, "\n".join(linhas)))
        f.write("\n## Diretorios interessantes (gobuster)\n\n")
        for porta, achados in resumo["gobuster"].items():
            f.write("### :%d\n\n" % porta)
            for (u, st) in achados:
                f.write("- `%s` — %s\n" % (u, st))
        f.write("\n## Nikto\n\n")
        for porta, achados in resumo["nikto"].items():
            f.write("### :%d\n\n" % porta)
            for l in achados:
                f.write("- %s\n" % l)
        f.write("\n## Fases\n\n| fase | rc | duracao (s) |\n|---|---|---|\n")
        for (fase, rc, dur) in resumo["fases"]:
            f.write("| %s | %d | %.1f |\n" % (fase, rc, dur))

    print("\nrelatorio: %s/" % os.path.abspath(pasta))
    print("resumo:    %s" % os.path.join(os.path.abspath(pasta), "00_resumo.md"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
