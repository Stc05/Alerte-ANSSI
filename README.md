# Alertes ANSSI — Collecte, enrichissement et déclenchement d’alertes (CVSS/EPSS/CWE)

Ce projet Python automatise :
1) la **collecte** des avis/alertes ANSSI via le flux RSS,  
2) l’**extraction des CVE** associées à chaque bulletin,  
3) l’**enrichissement** des CVE (CVSS + CWE + produits/versions via l’API MITRE, EPSS via FIRST),  
4) le **calcul d’un score de risque** par client (exposition + CVSS + EPSS + bonus CWE),  
5) l’**envoi d’un email d’alerte** lorsque le risque dépasse un seuil.

---

## Fonctionnalités (selon le code)

### 1) Collecte ANSSI (RSS)
- Source : `https://www.cert.ssi.gouv.fr/avis/feed/`
- Fonction : `flux_RSS(url)`
- Sortie : dictionnaire indexé par `CERTFR-YYYY-(ALE|AVI)-XXXX` contenant :
  - `Titre`, `Type` (avis/alerte), `Description`, `Lien`, `Date`

### 2) Extraction des CVE depuis ANSSI
- Fonction : `CVE(url)`
- Principe : prend l’URL d’un bulletin ANSSI, appelle son endpoint JSON (`{url}json/`), puis extrait la liste de `CVE-YYYY-NNNN...`.

### 3) Enrichissement MITRE (CVSS / CWE / Produits / Versions)
- Fonction : `API_MITRE(cve_id)`
- API utilisée : `https://cveawg.mitre.org/api/cve/{cve_id}`
- Retourne :
  - `description`
  - `cvss_score` (gestion des cas `cvssV3_1`, `cvssV3_0` et variantes dans `cna`/`adp`)
  - `niveau` (Critique/Élevée/Moyenne/Faible via `niveau_cvss`)
  - `cwe` + `cwe_desc`
  - `dico_produits` : mapping produit → {vendor, versions affectées}

### 4) Enrichissement EPSS (probabilité d’exploitation)
- Fonction : `API_EPSS(cve_id)`
- API utilisée : `https://api.first.org/data/v1/epss?cve={cve_id}`
- Retourne : `score_EPSS` (0 à 1)

### 5) Construction de la base “vulnérabilités enrichies”
- Fonction : `DataFrame()`
- Pour chaque bulletin ANSSI → pour chaque CVE → pour chaque produit affecté :
  - crée une ligne avec :
    - `ID_ANSSI`, `Titre_ANSSI`, `Type`, `Date`, `CVE`, `CVSS`, `Base_Severity`, `CWE`, `EPSS`,
    - `Lien`, `Description`, `Éditeur`, `Produit`, `Versions_Affectées`
- Exemple d’export (commenté dans le code) :
  - `df.to_csv("cve_enrichies.csv", sep=";", encoding="utf-8-sig", index=False)`

### 6) Catégorisation CWE → familles
- Dictionnaire : `dico_cwe` (ex: `CWE-416` → `Mémoire`, `CWE-22` → `Fichiers`, etc.)
- Familles “haut risque” : `FAMILLES_HAUT_RISQUE`

### 7) Calcul du risque + alerte email
- Fonction : `Risque(avis)`
- Lit une base clients : `BDD_clients.csv`
- Pour chaque vulnérabilité (`avis`) et chaque client :
  - **Exposition** : `exposition = 1` si la `Version` du client est dans `Versions_Affectées` (split simple par virgule)
  - **Valeurs par défaut** si données manquantes :
    - `cvss = 5.5`
    - `epss = 0.05`
  - **Bonus CWE** : `bonus = 0.1` si la famille associée au CWE est dans `FAMILLES_HAUT_RISQUE`
  - **Formule du score** :
    ```
    risque = 100 * exposition * (0.55 * cvss/10 + 0.35 * epss + bonus)
    ```
  - **Seuil d’alerte** : si `risque > 65` → envoi d’un email au client

---
