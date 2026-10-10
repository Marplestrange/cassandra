#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Drisse ATEK
"""LES OUTILS DE SÉCURITÉ DE CASSANDRA — une seule façon de les installer et de les faire passer.

L'installeur (install.sh) et le bouton « Installer » de l'onglet Sécurité appellent ce même programme.
Cassandra ne dépend d'aucun de ces outils : elle lit ce qu'ils laissent dans <données>/securite/*.json,
et dit « non installé » quand ils n'y sont pas.

    cassandra_securite_outils.py etat                  → JSON : chaque outil, installé, actif, dernier passage
    cassandra_securite_outils.py installer <outil>     → installe, règle, programme son passage régulier
    cassandra_securite_outils.py lancer <outil>        → un passage tout de suite, résultat en JSON
    cassandra_securite_outils.py convient <outil>      → la machine s'y prête-t-elle ? (code 0 = oui)

Outils : lynis (audit de durcissement), trivy (failles des images Docker), clamav (antivirus des fichiers
venus de l'extérieur), crowdsec (blocage collaboratif des attaquants).

Réglages facultatifs dans <config>/securite-outils.conf (format CLÉ=valeur) :
    CLAMAV_CIBLES=/home /var/www /srv          dossiers analysés par ClamAV (défaut : ceux-là s'ils existent,
                                               plus /root, /tmp, /var/tmp et les données de Cassandra)
    CONFIANCE=203.0.113.0/24 198.51.100.7      adresses jamais bannies par CrowdSec, EN PLUS de ce qui est
                                               détecté (réseaux locaux, Tailscale, l'adresse publique)
Rien n'est jamais supprimé ni mis en quarantaine : un fichier infecté est signalé, la décision revient à l'humain.
"""
import glob
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

CONF_DIR = os.environ.get("CASSANDRA_CONF_DIR") or "/etc/cassandra"
DATA_DIR = os.environ.get("CASSANDRA_DATA_DIR") or "/var/lib/cassandra"
SORTIE = os.path.join(DATA_DIR, "securite")
MOI = os.path.realpath(__file__)
OUTILS = ("lynis", "trivy", "clamav", "crowdsec")
# Quand chacun repasse seul : les audits la nuit du week-end, CrowdSec en continu (son résumé, 15 min).
CALENDRIER = {"lynis": "Sun *-*-* 03:30", "trivy": "Sun *-*-* 04:15", "clamav": "Sat *-*-* 02:30", "crowdsec": "*:0/15"}
TAILSCALE = ["100.64.0.0/10", "fd7a:115c:a1e0::/48"]


# ── petits outils ──────────────────────────────────────────────────────────────
def sh(cmd, timeout=600, env=None, entree=None):
    """(code, sortie) — jamais d'exception : un outil absent rend 127."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="replace", input=entree,
                           env=dict(os.environ, **(env or {})))
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except FileNotFoundError:
        return 127, "%s introuvable" % cmd[0]
    except subprocess.TimeoutExpired:
        return 124, "délai dépassé"


def dire(m):
    print("   " + m, flush=True)


def reglages():
    out = {}
    try:
        for l in open(os.path.join(CONF_DIR, "securite-outils.conf"), encoding="utf-8"):
            l = l.strip()
            if l and not l.startswith("#") and "=" in l:
                k, _, v = l.partition("=")
                out[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        pass
    return out


def ecrire(outil, d):
    os.makedirs(SORTIE, mode=0o750, exist_ok=True)
    d["outil"], d["quand"] = outil, time.strftime("%Y-%m-%d %H:%M:%S")
    tmp = os.path.join(SORTIE, ".%s.json" % outil)
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(d, f, ensure_ascii=False, indent=1)
    os.replace(tmp, os.path.join(SORTIE, "%s.json" % outil))
    return d


_APT_FRAIS = [False]


def apt(*paquets):
    env = {"DEBIAN_FRONTEND": "noninteractive"}
    if not _APT_FRAIS[0]:
        sh(["apt-get", "update", "-q"], timeout=900, env=env)
        _APT_FRAIS[0] = True
    rc, o = sh(["apt-get", "install", "-y", "-q", *paquets], timeout=1800, env=env)
    if rc:
        raise RuntimeError("apt-get install %s : %s" % (" ".join(paquets), o.strip().splitlines()[-1:] or o))


def memoire_mo():
    try:
        return int(re.search(r"MemTotal:\s+(\d+)", open("/proc/meminfo").read()).group(1)) // 1024
    except Exception:
        return 0


def actif(unite):
    return sh(["systemctl", "is-active", unite], timeout=10)[1].strip() == "active"


def docker_images():
    rc, o = sh(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"], timeout=30)
    return sorted({x for x in o.split() if x and "<none>" not in x}) if rc == 0 else []


def programmer(outil):
    """La minuterie systemd de l'outil : il repasse seul, même sans Cassandra."""
    nom = "cassandra-secu-" + outil
    with open("/etc/systemd/system/%s.service" % nom, "w", encoding="utf-8") as f:
        f.write("[Unit]\nDescription=Cassandra — passage de %s\nAfter=network-online.target\n\n"
                "[Service]\nType=oneshot\nNice=19\nIOSchedulingClass=idle\nEnvironment=CASSANDRA_DATA_DIR=%s\n"
                "Environment=CASSANDRA_CONF_DIR=%s\nExecStart=/usr/bin/python3 %s lancer %s\n" % (outil, DATA_DIR, CONF_DIR, MOI, outil))
    with open("/etc/systemd/system/%s.timer" % nom, "w", encoding="utf-8") as f:
        f.write("[Unit]\nDescription=Cassandra — passage régulier de %s\n\n[Timer]\nOnCalendar=%s\nPersistent=true\n"
                "RandomizedDelaySec=%s\n\n[Install]\nWantedBy=timers.target\n" % (outil, CALENDRIER[outil], "60" if outil == "crowdsec" else "20m"))
    sh(["systemctl", "daemon-reload"], timeout=60)
    sh(["systemctl", "enable", "--now", nom + ".timer"], timeout=60)


def depot_apt(nom, url_cle, ligne):
    """Un dépôt apt signé (Trivy) : la clé en anneau dédié, jamais dans le trousseau global."""
    anneau = "/usr/share/keyrings/%s.gpg" % nom
    with urllib.request.urlopen(url_cle, timeout=30) as r:
        cle = r.read()
    rc, o = sh(["gpg", "--dearmor", "--yes", "-o", anneau], timeout=60, entree=cle.decode("latin-1"))
    if rc:
        apt("gnupg")
        rc, o = sh(["gpg", "--dearmor", "--yes", "-o", anneau], timeout=60, entree=cle.decode("latin-1"))
        if rc:
            raise RuntimeError("clé du dépôt %s : %s" % (nom, o))
    with open("/etc/apt/sources.list.d/%s.list" % nom, "w", encoding="utf-8") as f:
        f.write(ligne.replace("{anneau}", anneau) + "\n")
    _APT_FRAIS[0] = False


# ── convient : la machine s'y prête-t-elle ? ───────────────────────────────────
def convient(outil):
    """(oui, pourquoi)"""
    if outil == "trivy":
        return (bool(shutil.which("docker")), "Docker présent" if shutil.which("docker") else "pas de Docker : rien à analyser")
    if outil == "clamav":
        m = memoire_mo()
        return (m >= 3500, "%d Mo de mémoire%s" % (m, "" if m >= 3500 else " : le démon de ClamAV (~1,5 Go) l'écraserait"))
    return True, ""


# ── installer ──────────────────────────────────────────────────────────────────
def installer(outil):
    if not shutil.which("apt-get"):
        raise RuntimeError("seuls Debian et Ubuntu (apt) sont pris en charge")
    if outil == "lynis":
        apt("lynis")
    elif outil == "trivy":
        if not shutil.which("trivy"):
            apt("ca-certificates", "gnupg")
            depot_apt("trivy", "https://aquasecurity.github.io/trivy-repo/deb/public.key",
                      "deb [signed-by={anneau}] https://aquasecurity.github.io/trivy-repo/deb generic main")
            apt("trivy")
    elif outil == "clamav":
        apt("clamav", "clamav-daemon", "clamav-freshclam")
        if not glob.glob("/var/lib/clamav/*.c[lv]d"):
            dire("Premières signatures (quelques minutes)…")
            sh(["systemctl", "stop", "clamav-freshclam"], timeout=60)
            sh(["freshclam", "--quiet"], timeout=1800)
        sh(["systemctl", "enable", "--now", "clamav-freshclam", "clamav-daemon"], timeout=120)
    elif outil == "crowdsec":
        installer_crowdsec()
    else:
        raise RuntimeError("outil inconnu : %s" % outil)
    programmer(outil)
    dire("Premier passage de %s…" % outil)
    try:
        lancer(outil)
    except Exception as e:
        dire("premier passage remis à plus tard : %s" % e)


def reseaux_de_confiance():
    """Ce que CrowdSec ne bannit jamais : les réseaux locaux de la machine, Tailscale, son adresse publique
    (un visiteur de la maison sort par elle), et ce que les réglages ajoutent."""
    out = set(TAILSCALE)
    rc, o = sh(["ip", "-o", "addr", "show"], timeout=10)
    for l in o.splitlines():
        if " docker" in l or " br-" in l or " veth" in l:
            continue
        m = re.search(r"\binet6?\s+([0-9a-fA-F:.]+/\d+)", l)
        if not m:
            continue
        try:
            n = ipaddress.ip_network(m.group(1), strict=False)
        except ValueError:
            continue
        if n.is_private and not n.is_loopback and not n.is_link_local:
            out.add(str(n))
        elif n.version == 6 and n.is_global and n.prefixlen == 64:
            out.add(str(n))     # le préfixe IPv6 du réseau local : public, mais c'est la maison
    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=6) as r:
            ip = r.read().decode().strip()
        ipaddress.ip_address(ip)
        out.add(ip)
    except Exception:
        pass
    out.update(x for x in reglages().get("CONFIANCE", "").replace(",", " ").split() if x)
    return sorted(out)


def journaux_nginx():
    """Les journaux d'accès et d'erreurs que nginx écrit vraiment, lus dans sa configuration : un panneau
    d'hébergement les range souvent par site, ailleurs que dans /var/log/nginx."""
    rc, o = sh(["nginx", "-T"], timeout=30)
    out = set(p for p in glob.glob("/var/log/nginx/*.log"))
    if rc == 0:
        for m in re.finditer(r"^\s*(?:access_log|error_log)\s+([^\s;]+)", o, re.M):
            p = m.group(1)
            if p.startswith("/") and p != "/dev/null":
                out.add(p)
    return sorted(out)


def ecrire_crowdsec_reglages():
    """Liste blanche et sources : réécrites à chaque passage (un site ajouté entre seul). Rend True si changé."""
    change = False
    blanc = "/etc/crowdsec/parsers/s02-enrich/cassandra-confiance.yaml"
    cidr = [x for x in reseaux_de_confiance() if "/" in x]
    ips = [x for x in reseaux_de_confiance() if "/" not in x]
    texte = ("# Écrit par Cassandra (cassandra_securite_outils.py) — réécrit à chaque passage.\n"
             "name: cassandra/confiance\ndescription: \"La maison, le tailnet et l'adresse publique ne sont jamais bannis\"\n"
             "whitelist:\n  reason: \"réseau de confiance (Cassandra)\"\n"
             + ("  ip:\n" + "".join("    - \"%s\"\n" % x for x in ips) if ips else "")
             + ("  cidr:\n" + "".join("    - \"%s\"\n" % x for x in cidr) if cidr else ""))
    change |= _ecrire_si_change(blanc, texte)
    sources = []
    nx = journaux_nginx()
    if nx:
        sources.append("filenames:\n" + "".join("  - %s\n" % p for p in nx) + "labels:\n  type: nginx")
    if not os.path.exists("/var/log/auth.log"):
        # Debian 12 et suivantes : sshd écrit au journal systemd, plus dans auth.log.
        sources.append("source: journalctl\njournalctl_filter:\n  - \"_SYSTEMD_UNIT=ssh.service\"\nlabels:\n  type: syslog")
    # Le commentaire DANS le premier document : seul avant un « --- », il ferait un document vide.
    acq = "/etc/crowdsec/acquis.d/cassandra.yaml"
    if sources:
        change |= _ecrire_si_change(acq, "# Écrit par Cassandra (cassandra_securite_outils.py) — réécrit à chaque passage.\n"
                                         + "\n---\n".join(sources) + "\n")
    elif os.path.exists(acq):
        os.unlink(acq)      # notre propre fichier de réglage, jamais une donnée
        change = True
    return change


def _ecrire_si_change(chemin, texte):
    try:
        if open(chemin, encoding="utf-8").read() == texte:
            return False
    except OSError:
        pass
    os.makedirs(os.path.dirname(chemin), exist_ok=True)
    with open(chemin, "w", encoding="utf-8") as f:
        f.write(texte)
    return True


def crowdsec_port_libre():
    """L'API locale de CrowdSec écoute par défaut sur 127.0.0.1:8080, un port que bien des machines donnent déjà
    à autre chose (un conteneur, un proxy) : CrowdSec meurt alors au démarrage. Si un autre programme le tient,
    on déplace l'API sur le premier port libre à partir de 8180, dans ses trois fichiers (le moteur, cscli, le videur)."""
    import socket
    conf = "/etc/crowdsec/config.yaml"
    try:
        t = open(conf, encoding="utf-8").read()
    except OSError:
        return
    m = re.search(r"listen_uri:\s*([0-9.]+):(\d+)", t)
    if not m:
        return
    hote, port = m.group(1), int(m.group(2))
    rc, o = sh(["ss", "-Hltnp", "sport", "= :%d" % port], timeout=10)
    if not o.strip() or "crowdsec" in o:
        return
    neuf = next(p for p in range(8180, 8300) if not sh(["ss", "-Hltn", "sport", "= :%d" % p], timeout=10)[1].strip()
                and socket.socket().connect_ex(("127.0.0.1", p)) != 0)
    vieux = "%s:%d" % (hote, port)
    for f in [conf, "/etc/crowdsec/local_api_credentials.yaml"] + glob.glob("/etc/crowdsec/bouncers/*.yaml"):
        try:
            t = open(f, encoding="utf-8").read()
        except OSError:
            continue
        if vieux in t:
            with open(f, "w", encoding="utf-8") as g:
                g.write(t.replace(vieux, "%s:%d" % (hote, neuf)))
    dire("API locale de CrowdSec déplacée de %d (pris) à %d." % (port, neuf))


def installer_crowdsec():
    if not shutil.which("cscli"):
        apt("curl", "ca-certificates")
        # Le dépôt officiel de CrowdSec (son script ne fait qu'ajouter le dépôt et sa clé).
        with urllib.request.urlopen("https://install.crowdsec.net", timeout=30) as r:
            script = r.read().decode("utf-8", "replace")
        with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as f:
            f.write(script)
        try:
            rc, o = sh(["sh", f.name], timeout=600)
            if rc:
                raise RuntimeError("dépôt CrowdSec : %s" % o.strip()[-300:])
        finally:
            os.unlink(f.name)
        _APT_FRAIS[0] = False
        apt("crowdsec")
    # Le videur : il applique les décisions dans le pare-feu du noyau (iptables, ou nftables seul).
    if not glob.glob("/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml"):
        apt("crowdsec-firewall-bouncer-iptables" if shutil.which("iptables") else "crowdsec-firewall-bouncer-nftables")
    collections = ["crowdsecurity/linux", "crowdsecurity/sshd", "crowdsecurity/nginx", "crowdsecurity/base-http-scenarios",
                   "crowdsecurity/http-cve"]
    rc, o = sh(["find", "/var/www", "/srv", "-maxdepth", "6", "-name", "wp-config.php", "-print", "-quit"], timeout=60)
    if o.strip().startswith("/"):
        collections.append("crowdsecurity/wordpress")
    sh(["cscli", "hub", "update"], timeout=300)
    for c in collections:
        sh(["cscli", "collections", "install", c], timeout=300)
    ecrire_crowdsec_reglages()
    crowdsec_port_libre()
    sh(["systemctl", "enable", "crowdsec", "crowdsec-firewall-bouncer"], timeout=60)
    sh(["systemctl", "restart", "crowdsec"], timeout=120)
    sh(["systemctl", "restart", "crowdsec-firewall-bouncer"], timeout=120)


# ── lancer : un passage, un résultat ───────────────────────────────────────────
def lancer(outil):
    if outil == "lynis":
        return lancer_lynis()
    if outil == "trivy":
        return lancer_trivy()
    if outil == "clamav":
        return lancer_clamav()
    if outil == "crowdsec":
        return lancer_crowdsec()
    raise RuntimeError("outil inconnu : %s" % outil)


def lancer_lynis():
    os.makedirs(SORTIE, mode=0o750, exist_ok=True)
    rapport = os.path.join(SORTIE, "lynis-report.dat")
    sh(["lynis", "audit", "system", "--cronjob", "--quiet", "--report-file", rapport,
        "--logfile", os.path.join(SORTIE, "lynis.log")], timeout=1800)
    score, av, sug, ver = None, [], [], ""
    for l in open(rapport, encoding="utf-8", errors="replace"):
        k, _, v = l.rstrip("\n").partition("=")
        if k == "hardening_index":
            score = int(v) if v.isdigit() else None
        elif k == "lynis_version":
            ver = v
        elif k in ("warning[]", "suggestion[]"):
            c = v.split("|")
            e = {"id": c[0], "texte": c[1] if len(c) > 1 else "", "detail": c[2] if len(c) > 2 and c[2] != "-" else ""}
            (av if k == "warning[]" else sug).append(e)
    return ecrire("lynis", {"score": score, "version": ver, "avertissements": av, "suggestions_n": len(sug), "suggestions": sug[:25]})


def lancer_trivy():
    cache = os.path.join(SORTIE, "trivy-cache")
    images = []
    for img in docker_images():
        rc, o = sh(["trivy", "image", "--quiet", "--scanners", "vuln", "--severity", "HIGH,CRITICAL", "--format", "json",
                    "--cache-dir", cache, "--timeout", "20m", img], timeout=1500)
        try:
            j = json.loads(o[o.index("{"):]) if "{" in o else {}
        except ValueError:
            j = {}
        if not j:
            images.append({"image": img, "erreur": o.strip()[-200:] or "lecture impossible"})
            continue
        vu, crit, haute, corr, ex = set(), 0, 0, 0, []
        for r in j.get("Results") or []:
            for v in r.get("Vulnerabilities") or []:
                cle = (v.get("VulnerabilityID"), v.get("PkgName"))
                if cle in vu:
                    continue
                vu.add(cle)
                if v.get("Severity") == "CRITICAL":
                    crit += 1
                else:
                    haute += 1
                if v.get("FixedVersion"):
                    corr += 1
                ex.append({"id": v.get("VulnerabilityID"), "gravite": v.get("Severity"), "paquet": v.get("PkgName"),
                           "version": v.get("InstalledVersion"), "corrigee_en": v.get("FixedVersion") or ""})
        ex.sort(key=lambda x: (x["gravite"] != "CRITICAL", not x["corrigee_en"]))
        images.append({"image": img, "critiques": crit, "hautes": haute, "corrigeables": corr, "exemples": ex[:8]})
    return ecrire("trivy", {"images": images})


def lancer_clamav():
    r = reglages()
    cibles = r.get("CLAMAV_CIBLES", "").split() or ["/home", "/var/www", "/srv", "/root", "/tmp", "/var/tmp", DATA_DIR]
    cibles = [c for c in cibles if os.path.isdir(c)]
    # Un seul fil (pas de balayage multiple) : le démon prendrait tous les cœurs, et la machine alerterait sur sa
    # propre charge pendant le balayage. Plus lent, mais la nuit, ça ne gêne personne.
    debut = time.time()
    if actif("clamav-daemon"):
        rc, o = sh(["clamdscan", "--fdpass", "--infected", *cibles], timeout=12 * 3600)
    else:
        rc, o = sh(["clamscan", "-r", "-i", "--max-filesize=50M", *cibles], timeout=12 * 3600)
    infectes = []
    for l in o.splitlines():
        m = re.match(r"(.+?):\s+(.+?)\s+FOUND$", l)
        if m:
            infectes.append({"fichier": m.group(1), "menace": m.group(2)})
    analyses = re.search(r"Scanned files:\s*(\d+)", o)
    sig = max((os.path.getmtime(p) for p in glob.glob("/var/lib/clamav/*.c[lv]d")), default=0)
    # Le code 2 vient aussi d'un simple fichier illisible (une socket, un tube) : seules les vraies erreurs comptent.
    # Un fichier qui disparaît ou qu'on ne peut pas ouvrir (les /tmp/systemd-private-* des services) non plus.
    benins = ("Not supported file type", "Access denied", "Can't access file", "No such file", "Permission denied")
    erreurs = [l for l in o.splitlines() if ("ERROR" in l or "Can't" in l or "Could not" in l)
               and not any(b in l for b in benins)]
    return ecrire("clamav", {"cibles": cibles, "analyses": int(analyses.group(1)) if analyses else None,
                             "duree_min": round((time.time() - debut) / 60),
                             "infectes": infectes[:200], "erreur": "" if rc in (0, 1) or not erreurs else " ; ".join(erreurs[:3])[-300:],
                             "signatures": time.strftime("%Y-%m-%d %H:%M", time.localtime(sig)) if sig else ""})


def lancer_crowdsec():
    if ecrire_crowdsec_reglages():
        sh(["systemctl", "reload-or-restart", "crowdsec"], timeout=120)
    rc, o = sh(["cscli", "decisions", "list", "-a", "-o", "raw"], timeout=120)
    origines = {}
    locales = []
    for l in o.splitlines()[1:]:
        c = l.split(",")
        if len(c) < 5:
            continue
        origines[c[1]] = origines.get(c[1], 0) + 1
        if c[1] in ("crowdsec", "cscli"):
            locales.append({"ip": c[2], "raison": c[3], "action": c[4], "expire": c[8] if len(c) > 8 else ""})
    rc, o = sh(["cscli", "alerts", "list", "--since", "24h", "-o", "json"], timeout=120)
    try:
        alertes = json.loads(o) or []
    except ValueError:
        alertes = []
    scen = {}
    for a in alertes:
        s = a.get("scenario") or "?"
        scen[s] = scen.get(s, 0) + 1
    return ecrire("crowdsec", {
        "moteur": actif("crowdsec"), "videur": actif("crowdsec-firewall-bouncer"),
        "decisions_locales": len(locales), "liste_communautaire": sum(n for k, n in origines.items() if k not in ("crowdsec", "cscli")),
        "origines": origines, "bannies": locales[:50], "alertes_24h": len(alertes),
        "scenarios_24h": sorted(({"scenario": k, "n": v} for k, v in scen.items()), key=lambda x: -x["n"])[:10]})


# ── etat ───────────────────────────────────────────────────────────────────────
def version(outil):
    cmd = {"lynis": ["lynis", "show", "version"], "trivy": ["trivy", "--version"], "clamav": ["clamscan", "--version"],
           "crowdsec": ["crowdsec", "-version"]}[outil]
    rc, o = sh(cmd, timeout=20)
    m = re.search(r"\d+\.\d+(\.\d+)?", o)
    return m.group(0) if rc == 0 and m else ""


def etat():
    binaires = {"lynis": "lynis", "trivy": "trivy", "clamav": "clamscan", "crowdsec": "cscli"}
    services = {"clamav": ["clamav-daemon", "clamav-freshclam"], "crowdsec": ["crowdsec", "crowdsec-firewall-bouncer"]}
    out = {}
    for o in OUTILS:
        inst = bool(shutil.which(binaires[o]))
        ok, pourquoi = convient(o)
        f = os.path.join(SORTIE, "%s.json" % o)
        out[o] = {"installe": inst, "version": version(o) if inst else "", "convient": ok, "pourquoi": pourquoi,
                  "services": {s: actif(s) for s in services.get(o, [])} if inst else {},
                  "minuterie": actif("cassandra-secu-%s.timer" % o) if inst else False,
                  "en_cours": actif("cassandra-secu-%s.service" % o) if inst else False,
                  "resultat": f if os.path.exists(f) else ""}
    return out


def main(a):
    if not a or a[0] in ("-h", "--help", "aide"):
        print(__doc__)
        return 0
    if a[0] == "etat":
        print(json.dumps(etat(), ensure_ascii=False))
        return 0
    if len(a) < 2 or a[1] not in OUTILS:
        print("outil attendu : " + ", ".join(OUTILS), file=sys.stderr)
        return 2
    if a[0] == "convient":
        ok, pourquoi = convient(a[1])
        print(pourquoi)
        return 0 if ok else 1
    if os.geteuid() != 0:
        print("à lancer en root", file=sys.stderr)
        return 1
    try:
        if a[0] == "installer":
            installer(a[1])
            dire("%s installé et programmé." % a[1])
        elif a[0] == "lancer":
            d = lancer(a[1])
            dire("%s : passage terminé (%s)." % (a[1], d["quand"]))
        else:
            print("commande inconnue : %s" % a[0], file=sys.stderr)
            return 2
    except Exception as e:
        print("✘ %s : %s" % (a[1], e), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
