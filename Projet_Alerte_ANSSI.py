import feedparser
import requests
import re
import requests
import pandas as pd
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

url_ANSSI = "https://www.cert.ssi.gouv.fr/avis/feed/"

# extraction flux RSS des avis et alertes de l'ANSSI
def flux_RSS(url):
    rss_feed = feedparser.parse(url)
    dico={}
    id_pattern = r"CERTFR-\d{4}-[A-Z]{3}-\d{4}"
    for entry in rss_feed.entries:
        id_ANSSI = re.findall(id_pattern, entry.link)[0]
        categorie= entry.link.split("/")[3]
        dico[id_ANSSI]={"Titre": entry.title, 
                        "Type":categorie,
                        "Description":entry.description, 
                        "Lien":entry.link, 
                        "Date":entry.published}
    return dico

# dictionnaire = flux_RSS(url_ANSSI)
# for k in dictionnaire.keys():
#     print(k)
#     print(dictionnaire[k]["Titre"])
#     print(dictionnaire[k]["Type"])
#     print(dictionnaire[k]["Description"])
#     print(dictionnaire[k]["Lien"])
#     print(dictionnaire[k]["Date"], "\n")
# print(len(dictionnaire))

#Extraction des CVE à partir du lien json d'une alerte/avis de l'ANSSI
def CVE(url):
    url_json = f"{url}json/"
    response = requests.get(url_json)
    data = response.json()
    #Extraction des CVE reference dans la clé cves du dict data

    ref_cves=list(data["cves"])
    #attention il s’agit d’une liste des dictionnaires avec name et url comme clés

    # Extraction des CVE avec une regex
    cve_pattern = r"CVE-\d{4}-\d{4,7}"
    cve_list = list(set(re.findall(cve_pattern, str(data))))

    return cve_list

# cve=CVE("https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-001/")
# print(" ".join(cve))


# Attribue "Critique", "Elevée", "Moyenne" ou "Faible" à partir du score CVSS
def niveau_cvss(s):
    if s is None:
        return None
    s = float(s)
    if s >= 9.0:
        return "Critique"
    elif s >= 7.0:
        return "Élevée"
    elif s >= 4.0:
        return "Moyenne"
    else:
        return "Faible"
    
# Permet d'obtenir le score CVSS et le type CWE associé
def API_MITRE(cve_id):
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    response = requests.get(url)
    if response.status_code != 200:
        return None, None, None, "Non disponible", "Non disponible", {}
    data = response.json()

    # Extraire la description
    if "containers" not in data:
        return None, None, None, "Non disponible", "Non disponible", {}
    
    descs = data.get("containers", {}).get("cna", {}).get("descriptions", [])
    description = descs[0].get("value") if descs else None

    # Extraire le score CVSS
    #ATTENTION tous les CVE ne contiennent pas nécessairement ce champ, gérez l’exception,
    #ou peut etre au lieu de cvssV3_0 c’est cvssV3_1 ou autre clé
    cvss_score = None
    try:
        cvss_score = data["containers"]["cna"]["metrics"][0]["cvssV3_1"]["baseScore"]
    except (KeyError):
        try:
            cvss_score = data["containers"]["cna"]["metrics"][0]["cvssV3_0"]["baseScore"]
        except(KeyError):
            try:
                cvss_score = data["containers"]["adp"][0]["metrics"][0]["cvssV3_1"]["baseScore"]
            except (KeyError):
                try:
                    cvss_score = data["containers"]["adp"][0]["metrics"][0]["cvssV3_0"]["baseScore"]
                except:
                    cvss_score = None
    niveau=niveau_cvss(cvss_score)
    
    cwe = "Non disponible"
    cwe_desc="Non disponible"
    problemtype =  data["containers"]["adp"][0].get("problemTypes", {}) or data["containers"]["cna"].get("problemTypes", {})

    if problemtype and "descriptions" in problemtype[0]:
        cwe = problemtype[0]["descriptions"][0].get("cweId", "")
        cwe_desc=problemtype[0]["descriptions"][0].get("description", "")
  
    # Extraire les produits affectés
    affected = data.get("containers", {}).get("cna", {}).get("affected", [])
    dico={}
    for product in affected:
        product_name = product.get("product")
        if not product_name:
            continue
        dico[product_name]={"vendor": product.get("vendor", "Vendor inconnu"),
                            "versions" : [v.get("version") for v in product.get("versions", []) if v.get("status") == "affected" and v.get("version")]
        }
    return description, cvss_score, niveau, cwe, cwe_desc, dico

# description, cvss_score, niveau, cwe, cwe_desc, dico = API_MITRE("CVE-2025-43532")
# print(f"Description : {description}\n")
# print(f"Score CVSS : {cvss_score}\n")
# print(f"Niveau CVSS : {niveau}\n")
# print(f"Type CWE : {cwe}\n")
# print(f"CWE Description : {cwe_desc}\n\n")
# for k in dico :
#     print(f"Éditeur : {dico[k]["vendor"]}, Produit : {k}, Versions : {', '.join(dico[k]["versions"])}")


# url = f"https://cveawg.mitre.org/api/cve/CVE-2025-43532"
# response = requests.get(url)
# data = response.json()

# print(data["containers"]["adp"][0]["problemTypes"][0]["descriptions"][0]["cweId"])
# print(data["containers"]["adp"][0]["problemTypes"])


#URL de l'API EPSS pour récupérer la probabilité d'exploitation
def API_EPSS(cve_id):

    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    # Requête GET pour récupérer les données JSON

    response = requests.get(url)
    data = response.json()
    # Extraire le score EPSS
    epss_data = data.get("data", [])
    score_EPSS=None
    if epss_data:
        epss_score = epss_data[0]["epss"]
        score_EPSS=epss_score
    return score_EPSS

# print(f"Score EPSS :", API_EPSS("CVE-2025-14373"))


def DataFrame():
    dico_ANSSI = flux_RSS(url_ANSSI)
    rows = []
    for id_ANSSI in dico_ANSSI:
        cve_liste=CVE(dico_ANSSI[id_ANSSI]["Lien"])
        for cve_id in cve_liste :
            score_EPSS=API_EPSS(cve_id)
            description, cvss_score, niveau_cvss, cwe, cwe_desc, dico_produits = API_MITRE(cve_id)
            for produit in dico_produits : 
                rows.append({
                    "ID_ANSSI": id_ANSSI,
                    "Titre_ANSSI":dico_ANSSI[id_ANSSI]["Titre"],
                    "Type":dico_ANSSI[id_ANSSI]["Type"],
                    "Date":dico_ANSSI[id_ANSSI]["Date"],
                    "CVE":cve_id,
                    "CVSS":cvss_score,
                    "Base_Severity":niveau_cvss,
                    "CWE":cwe,
                    "EPSS":score_EPSS,
                    "Lien":dico_ANSSI[id_ANSSI]["Lien"],
                    "Description": description.replace("\r\n", ". ").replace("\r", ". ").replace("\n", ". "),
                    "Éditeur":dico_produits[produit]["vendor"],
                    "Produit":produit,
                    "Versions_Affectées": ", ".join(str(v) for v in dico_produits[produit]["versions"] if v is not None)
                })
    df = pd.DataFrame(rows)
    return df

# df=DataFrame()
# df.to_csv("cve_enrichies.csv", index=False, sep=";", encoding="utf-8-sig")         
            
#dictionnaire attribuant le type de problème aux cwe qui apparaissent le plus fréquemment
dico_cwe = {
    # Fichiers / chemins / permissions fichier
    "CWE-22": "Fichiers",
    "CWE-61": "Fichiers",
    "CWE-378": "Fichiers",
    "CWE-59": "Fichiers",

    # Mémoire (corruption, overflow, UAF, fuites)
    "CWE-121": "Mémoire",
    "CWE-122": "Mémoire",
    "CWE-125": "Mémoire",
    "CWE-170": "Mémoire",
    "CWE-190": "Mémoire",
    "CWE-401": "Mémoire",
    "CWE-404": "Mémoire",
    "CWE-409": "Mémoire",
    "CWE-416": "Mémoire",
    "CWE-476": "Mémoire",
    "CWE-787": "Mémoire",
    "CWE-789": "Mémoire",
    "CWE-825": "Mémoire",

    # DoS / crash / robustesse
    "CWE-400": "DoS",
    "CWE-407": "DoS",
    "CWE-674": "DoS",
    "CWE-755": "DoS",
    "CWE-835": "DoS",
    "CWE-909": "DoS",

    # Validation / encodage / parsing
    "CWE-20": "Validation",
    "CWE-75": "Validation",
    "CWE-113": "Validation",
    "CWE-116": "Validation",
    "CWE-129": "Validation",
    "CWE-130": "Validation",
    "CWE-147": "Validation",
    "CWE-248": "Validation",
    "CWE-349": "Validation",
    "CWE-392": "Validation",
    "CWE-393": "Validation",
    "CWE-444": "Validation",
    "CWE-489": "Validation",
    "CWE-650": "Validation",

    # AuthN/AuthZ / contrôle d’accès / permissions
    "CWE-250": "AuthZ/AuthN",
    "CWE-268": "AuthZ/AuthN",
    "CWE-279": "AuthZ/AuthN",
    "CWE-284": "AuthZ/AuthN",
    "CWE-285": "AuthZ/AuthN",
    "CWE-287": "AuthZ/AuthN",
    "CWE-303": "AuthZ/AuthN",
    "CWE-356": "AuthZ/AuthN",
    "CWE-364": "AuthZ/AuthN",
    "CWE-639": "AuthZ/AuthN",
    "CWE-732": "AuthZ/AuthN",
    "CWE-862": "AuthZ/AuthN",
    "CWE-863": "AuthZ/AuthN",

    # Crypto / hasard / TLS
    "CWE-295": "Crypto/TLS",
    "CWE-324": "Crypto/TLS",
    "CWE-338": "Crypto/TLS",

    # Injections (XSS / commande / code / SSRF / désérialisation / XXE / regex, etc.)
    "CWE-78": "Injections",
    "CWE-79": "Injections",
    "CWE-93": "Injections",
    "CWE-94": "Injections",
    "CWE-502": "Injections",
    "CWE-611": "Injections",
    "CWE-918": "Injections",

    # Concurrence / race conditions
    "CWE-233": "Concurrence",
    "CWE-362": "Concurrence",
    "CWE-367": "Concurrence",
    "CWE-669": "Concurrence",

    # InfoLeak / exposition d’info / secrets
    "CWE-200": "InfoLeak",
    "CWE-203": "InfoLeak",
    "CWE-209": "InfoLeak",
    "CWE-212": "InfoLeak",
    "CWE-359": "InfoLeak",
    "CWE-524": "InfoLeak",
    "CWE-602": "InfoLeak",

    # Réseau / HTTP (en-têtes, redirections, etc.)
    "CWE-113": "Réseau/HTTP",
    "CWE-392": "Réseau/HTTP",
    "CWE-393": "Réseau/HTTP",

    # Logique / calcul
    "CWE-682": "Logique",
    "CWE-908": "Logique",

    # API / état / conception / divers
    "CWE-407": "API/État",
    "CWE-440": "API/État",
    "CWE-524": "API/État",
    "CWE-665": "API/État",
    "CWE-670": "API/État",
    "CWE-843": "API/État",
    "CWE-943": "API/État",
}

FAMILLES_HAUT_RISQUE = {
    "Mémoire",            
    "Injections",        
    "AuthZ/AuthN",  
    "Validation",  
    "Fichiers",
    "Dos"
}


load_dotenv()

def send_email(to_email, subject, body):
    from_email = os.getenv("EMAIL_ADDRESS")
    password = os.getenv("EMAIL_PASSWORD")

    if not from_email or not password:
        raise ValueError("Variables d'environnement EMAIL_ADDRESS ou EMAIL_PASSWORD manquantes")

    # Création du message avec MIMEMultipart pour compatibilité Gmail
    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.ehlo()               # Important pour Gmail
            server.starttls()           # TLS sécurisé
            server.login(from_email, password)
            server.send_message(msg)    # send_message gère mieux les entêtes
        print(f"Email envoyé avec succès à {to_email}")
    except Exception as e:
        print("Erreur lors de l'envoi :", e)


# send_email(
#     to_email="steven.chang@edu.devinci.fr",
#     subject="Test",
#     body="Ceci est un test d'envoi d'email depuis Python."
# )


def Risque(avis):
    df = pd.read_csv("BDD_clients.csv", sep=";", encoding="latin1")
    for avis_row in avis.itertuples(index=False):
        for row in df.itertuples(index=False):
            exposition =0
            cvss =5.5 
            epss=0.05
            bonus=0
            if row.Version in avis_row.Versions_Affectées.split(","):
                exposition=1
            if avis_row.CVSS:
                cvss= avis_row.CVSS
            if avis_row.EPSS:
                epss= avis_row.EPSS
            if dico_cwe.get(avis_row.CWE,"") in FAMILLES_HAUT_RISQUE:
                bonus =0.1
            risque = 100*exposition*(0.55*cvss/10 +0.35*epss + bonus)
            print("expo:", exposition)
            print("cvss:", cvss)
            print("epss:", epss)
            print(risque)
            if risque > 65 :
                send_email(row.Email, "Alerte CVE critique", f"Mettez à jour votre {row.Produit_utilisé} pour la {avis_row.CVE}\n")


data_test = [{
        "ID_ANSSI": "CERTFR-2025-AVI-1115",
        "Titre_ANSSI": "Vulnérabilité dans Trend Micro Apex One",
        "Type": "avis",
        "Date": "Tue, 16 Dec 2025 00:00:00 +0000",
        "Lien": "https://www.cert.ssi.gouv.fr/avis/CERTFR-2025-AVI-1115/",
        "CVE": "CVE-2025-49844",
        "CVSS": 10.0,
        "Base_SeverityCriticité": "Critique",
        "CWE": "CWE-416",
        "EPSS": 0.05974,
        "Description": "Redis is an open source, in-memory database that persists on disk.",
        "Produit": "redis",
        "Éditeur": "redis",
        "Versions_Affectées": "< 8.2.2"
    },
    {
        "ID_ANSSI": "CERTFR-2025-AVI-1129",
        "Titre_ANSSI": "Multiples vulnérabilités dans les produits VMware (19 décembre 2025)",
        "Type": "avis",
        "Date": "Fri, 19 Dec 2025 00:00:00 +0000",
        "Lien": "https://www.cert.ssi.gouv.fr/avis/CERTFR-2025-AVI-1129/",
        "CVE": "CVE-2025-27221",
        "CVSS": 3.2,
        "Base_SeverityCriticité": "Faible",
        "CWE": "CWE-212",
        "EPSS": 0.00029,
        "Description": "In the URI gem before 1.0.3 for Ruby, the URI handling methods (URI.join, URI#merge, URI#+) have an inadvertent leakage of authentication credentials because userinfo is retained even after changing the host.",
        "Produit": "URI",
        "Éditeur": "ruby-lang",
        "Versions_Affectées": "0, 0.12.0, 0.13.0, 1.0.0"
    }
]

df_test = pd.DataFrame(data_test)
# Risque(df_test)



