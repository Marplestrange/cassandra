#!/usr/bin/env python3
"""Exécute UNE commande sur une machine de la flotte, avec l'identité que Cassandra garde pour elle
(multiserver.json, chiffrée sous le secret maître flotte.key). La clé n'existe en clair que le temps de la
connexion, dans un fichier 0600 effacé aussitôt ; rien n'est imprimé d'autre que la sortie de la commande.

Usage : flotte_exec.py --liste | flotte_exec.py <machine> <commande>"""
import base64, hashlib, json, os, subprocess, sys, tempfile

DATA = os.environ.get("CASSANDRA_DATA_DIR", "/var/lib/cassandra")
CONF = os.environ.get("CASSANDRA_CONF_DIR", "/etc/cassandra")


def dechiffrer(stored: str, cle: bytes) -> str:
    if not stored:
        return ""
    if stored.startswith("enc1:"):
        from cryptography.fernet import Fernet
        return Fernet(base64.urlsafe_b64encode(cle)).decrypt(stored[5:].encode()).decode()
    if stored.startswith(("enc0:",)):
        sys.exit("format enc0 non géré ici")
    return stored


serveurs = json.load(open(os.path.join(DATA, "multiserver.json")))
if len(sys.argv) < 2 or sys.argv[1] == "--liste":
    for s in serveurs:
        print(s.get("name"), s.get("ssh_host"), s.get("ssh_user"), s.get("ssh_auth"), "clé" if s.get("ssh_key") else "")
    sys.exit(0)
nom, cmd = sys.argv[1], " ".join(sys.argv[2:])
s = next((x for x in serveurs if str(x.get("name") or "").lower() == nom.lower()), None)
if not s:
    sys.exit("machine inconnue : %s" % nom)
maitre = open(os.path.join(CONF, "flotte.key")).read().strip().encode()
cle = hashlib.pbkdf2_hmac("sha256", maitre, b"cassandra-multiserver-token-encryption-v1", iterations=100_000, dklen=32)
pk = dechiffrer(s.get("ssh_key", ""), cle)
base = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=12", "-o", "LogLevel=ERROR", "-p", str(s.get("ssh_port") or 22)]
cible = "%s@%s" % (s.get("ssh_user") or "root", s.get("ssh_host"))
if not pk:
    mdp = dechiffrer(s.get("ssh_pass", ""), cle) if s.get("ssh_auth") == "password" else ""
    if not mdp:
        r = subprocess.run(base + [cible, cmd])
        sys.exit(r.returncode)
    # Le mot de passe passe par l'environnement du seul processus ssh (SSH_ASKPASS) : jamais sur le disque,
    # jamais dans la ligne de commande.
    fd, ask = tempfile.mkstemp(suffix=".sh")
    try:
        os.write(fd, b'#!/bin/sh\nprintf "%s\\n" "$CASSANDRA_FLOTTE_MDP"\n')
        os.close(fd)
        os.chmod(ask, 0o700)
        env = dict(os.environ, SSH_ASKPASS=ask, SSH_ASKPASS_REQUIRE="force", DISPLAY="none", CASSANDRA_FLOTTE_MDP=mdp)
        r = subprocess.run(["BatchMode=no" if x == "BatchMode=yes" else x for x in base] + ["-o", "PubkeyAuthentication=no",
                            "-o", "NumberOfPasswordPrompts=1", cible, cmd], env=env, stdin=subprocess.DEVNULL)
    finally:
        os.unlink(ask)
    sys.exit(r.returncode)
fd, chemin = tempfile.mkstemp(suffix=".pem")
try:
    os.write(fd, (pk.strip() + "\n").encode())
    os.close(fd)
    os.chmod(chemin, 0o600)
    r = subprocess.run(base + ["-o", "IdentitiesOnly=yes", "-i", chemin, cible, cmd])
finally:
    os.unlink(chemin)
sys.exit(r.returncode)
