#!/usr/bin/env python3
"""Lecture SEULE de ce que la Freebox expose : redirections (manuelles et UPnP), DMZ, IPv6, accès distant, VPN.
Aucun jeton, aucun mot de passe n'est imprimé."""
import hashlib, hmac, json, sys, urllib.request

JETON_F = "/etc/cassandra/freebox-app.token"
c = json.load(open(JETON_F))
BOX, BASE = c["box"], c["base"]


def api(chemin, corps=None, session=""):
    h = {"Content-Type": "application/json"}
    if session:
        h["X-Fbx-App-Auth"] = session
    req = urllib.request.Request(BOX + BASE + chemin, data=json.dumps(corps).encode() if corps is not None else None,
                                 headers=h)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        try:
            return json.load(e)
        except Exception:
            return {"success": False, "error_code": "http_%d" % e.code}


defi = api("/login/")["result"]["challenge"]
mdp = hmac.new(c["app_token"].encode(), defi.encode(), hashlib.sha1).hexdigest()
s = api("/login/session/", {"app_id": c["app_id"], "password": mdp})
if not s.get("success"):
    sys.exit("session refusée : %s" % s.get("error_code"))
S = s["result"]["session_token"]
print("Droits accordés à l'application :", ", ".join(k for k, v in (s["result"].get("permissions") or {}).items() if v))


def lire(titre, chemin):
    r = api(chemin, session=S)
    if not r.get("success"):
        print("\n== %s : illisible (%s)" % (titre, r.get("error_code") or r.get("msg")))
        return None
    return r.get("result")


x = lire("Connexion", "/connection/")
if x:
    print("\n== Connexion : %s · IPv4 publique %s · IPv6 %s" % (x.get("state"), x.get("ipv4"), x.get("ipv6")))
x = lire("Réglages de la connexion", "/connection/config/")
if x:
    print("== Accès distant à Freebox OS : %s (port HTTPS %s) · réponse au ping : %s · WOL : %s" % (
        "OUI" if x.get("remote_access") else "non", x.get("remote_access_port") or x.get("api_remote_access_port"),
        "oui" if x.get("ping") else "non", "oui" if x.get("wol") else "non"))
x = lire("IPv6", "/connection/ipv6/config/")
if x:
    print("== IPv6 : %s · pare-feu IPv6 de la box : %s" % ("activé" if x.get("ipv6_enabled") else "désactivé",
          {True: "ACTIF", False: "DÉSACTIVÉ"}.get(x.get("ipv6_firewall"), x.get("ipv6_firewall"))))
x = lire("Redirections de ports", "/fw/redir/")
if x is not None:
    print("\n== Redirections de ports manuelles : %d" % len(x or []))
    for r in x or []:
        print("   %s %s:%s → %s:%s (%s)%s" % ("●" if r.get("enabled") else "○", r.get("ip_proto"),
              "%s-%s" % (r.get("wan_port_start"), r.get("wan_port_end")) if r.get("wan_port_start") != r.get("wan_port_end") else r.get("wan_port_start"),
              r.get("lan_ip"), r.get("lan_port"), r.get("comment") or r.get("hostname") or "",
              (" · depuis %s" % r.get("src_ip")) if r.get("src_ip") not in (None, "", "0.0.0.0") else ""))
x = lire("Redirections UPnP", "/upnpigd/redir/")
if x is not None:
    print("== Redirections ouvertes SEULES par des appareils (UPnP) : %d" % len(x or []))
    for r in x or []:
        print("   %s %s → %s:%s (%s)" % (r.get("proto"), r.get("ext_port"), r.get("int_ip"), r.get("int_port"), r.get("desc")))
x = lire("UPnP", "/upnpigd/config/")
if x:
    print("== UPnP : %s" % ("ACTIVÉ" if x.get("enabled") else "désactivé"))
x = lire("DMZ", "/fw/dmz/")
if x:
    print("== DMZ : %s" % (("ACTIVE vers %s" % x.get("ip")) if x.get("enabled") else "désactivée"))
x = lire("Ports de la box", "/fw/incoming/")
if x is not None:
    ouverts = [p for p in (x or []) if p.get("enabled")]
    print("== Ports ouverts par la box elle-même : %s" % (", ".join("%s %s/%s" % (p.get("id"), p.get("in_port"), p.get("type")) for p in ouverts) or "aucun"))
x = lire("Serveurs VPN", "/vpn/")
if x is not None:
    print("== Serveurs VPN : %s" % (", ".join("%s %s" % (v.get("name"), v.get("state")) for v in (x or [])) or "aucun"))
api("/login/logout/", {}, session=S)
