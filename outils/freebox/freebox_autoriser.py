#!/usr/bin/env python3
"""Demande à la Freebox d'autoriser l'application « Cassandra » (API locale). La box affiche la demande sur son
écran ; on la valide avec la flèche droite. Le jeton d'application est écrit dans /etc/cassandra (0600) et n'est
jamais affiché. Lecture seule ensuite : rien ici ne change un réglage de la box."""
import json, os, sys, time, urllib.request

BOX = os.environ.get("FREEBOX_URL", "http://mafreebox.freebox.fr")
JETON_F = "/etc/cassandra/freebox-app.token"
APP = {"app_id": "center.cassandra", "app_name": "Cassandra", "app_version": "18.0", "device_name": "Orion"}


def api(chemin, corps=None):
    req = urllib.request.Request(BOX + chemin, data=json.dumps(corps).encode() if corps is not None else None,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.load(r)


v = api("/api_version")
base = "/api/v%s" % str(v.get("api_version", "15")).split(".")[0]
print("Freebox : %s, API %s" % (v.get("box_model_name") or v.get("device_name"), v.get("api_version")))
r = api(base + "/login/authorize/", APP)
if not r.get("success"):
    sys.exit("demande refusée : %s" % r)
jeton, piste = r["result"]["app_token"], r["result"]["track_id"]
print("Demande envoyée : valide-la sur l'écran de la Freebox (flèche droite). J'attends 3 minutes.", flush=True)
fin = time.time() + 180
etat = "pending"
while time.time() < fin:
    etat = api("%s/login/authorize/%s" % (base, piste)).get("result", {}).get("status")
    if etat != "pending":
        break
    time.sleep(3)
print("Réponse de la box : %s" % {"granted": "AUTORISÉE", "denied": "refusée", "timeout": "délai dépassé",
                                   "unknown": "inconnue", "pending": "toujours en attente"}.get(etat, etat))
if etat == "granted":
    os.makedirs(os.path.dirname(JETON_F), exist_ok=True)
    fd = os.open(JETON_F, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"app_id": APP["app_id"], "app_token": jeton, "base": base, "box": BOX}, f)
    print("Jeton rangé dans %s (0600)." % JETON_F)
