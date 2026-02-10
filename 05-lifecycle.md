## Table des matières

1. [Introduction et contexte CERT-Bund](./01-introduction.md)
2. [Typologie : Warnungen / Advisories / Lageberichte / Analyses](./02-typology.md)
3. [Structure des données et Parsing](./03-data-structure-parsing.md)
4. [Accès aux données (Portail, RSS, endpoints)](./04-data-access.md)
5. [Cycle de vie et Mises à jour](./05-lifecycle.md)

---

# 5. Cycle de vie des publications CERT-Bund / BSI

## 5.1 Objectif de cette section

Cette section décrit le **cycle de vie** des publications du **CERT-Bund / BSI**, notamment :

* la fréquence et les mécanismes de mise à jour ;
* l’évolution d’un advisory dans le temps (révisions CSAF) ;
* l’impact sur les **CVE**, les produits affectés, les correctifs et les références ;
* les bonnes pratiques pour synchroniser et maintenir un **référentiel interne** à jour.

---

## 5.2 Comprendre le modèle CERT-Bund / BSI

Contrairement à la **NVD** (enregistrements CVE) ou à la **CISA KEV** (liste priorisée), CERT-Bund publie des **documents opérationnels**.

La différence clé est que CERT-Bund fournit une représentation **structurée machine-readable** via **CSAF v2.0**, avec un mécanisme de tracking intégré.

Les publications CERT-Bund :

* peuvent regrouper plusieurs vulnérabilités,
* portent sur un produit, une gamme ou une version range,
* intègrent des recommandations (patch / workaround),
* sont susceptibles d’évoluer dans le temps via **révisions CSAF**.

---

## 5.3 Fréquence et mécanismes de mise à jour

Un advisory CERT-Bund peut être mis à jour après publication suite à :

* publication de correctifs par l’éditeur
* correction/clarification du périmètre (versions réellement vulnérables)
* ajout/suppression de CVE
* enrichissement des références (vendor advisory, GitHub advisory, EUVD, etc.)
* évolution de la criticité ou du wording (sévérité agrégée)

### 5.3.1 Indicateurs de version (CSAF)

Le cycle de vie du document est porté par le bloc :

* `document.tracking`

Champs critiques :

* `tracking.id` : identifiant stable
* `tracking.version` : version courante
* `tracking.status` : ex. `final`
* `tracking.revision_history[]` : historique des révisions

✅ Ce tracking est l’équivalent (amélioré) d’un `lastModified`.

---

## 5.4 Cycle de vie typique d’une publication CSAF CERT-Bund

### 5.4.1 Étapes

1. **Publication initiale (v1)**

   * création d’un advisory CSAF (ex. `WID-SEC-W-2026-0001`)
   * ajout des notes : description / summary
   * définition des produits affectés
   * ajout des références principales

2. **Révisions / enrichissements**

   * ajout de CVE manquantes
   * enrichissement du `product_tree`
   * ajout d’une version corrigée (`*-fixed`)
   * ajout de sources externes (advisory éditeur, GHSA, EUVD)
   * clarification du résumé / impact

3. **Stabilisation**

   * document marqué `final`
   * révisions ultérieures rares

4. **Obsolescence (implicite)**

   * advisory reste publié et accessible
   * mais la pertinence opérationnelle décroît (patch appliqué / EOL)

---

## 5.5 Indicateurs de mise à jour (équivalent CERT-Bund de `lastModified`)

CERT-Bund offre plusieurs niveaux de signaux fiables.

### 5.5.1 A) `document.tracking.current_release_date`

* **Signal fort** : date de release courante
* **Usage** : ingestion incrémentale

### 5.5.2 B) `document.tracking.version`

* incrément version (string)
* indique clairement une révision

### 5.5.3 C) `document.tracking.revision_history[]`

Historique des versions.

Exemple typique :

* `number: 1` → Initiale Fassung

➡️ Utiliser `revision_history` comme source de vérité d’audit.

### 5.5.4 D) Horodatages techniques

Selon implémentation HTTP/CDN :

* header `Last-Modified` (si présent)
* `ETag`

✅ Recommandation : stocker `etag` + `fetched_at`.

### 5.5.5 E) Hash de contenu

Calcul :

* `content_hash` = SHA256 du JSON normalisé (ou du champ `document` + `vulnerabilities`)

➡️ Détection de tout drift (même silencieux).

---

## 5.6 Évolution des vulnérabilités (CVE)

### 5.6.1 Où sont les CVE ?

Les CVE sont explicitement présentes dans :

* `vulnerabilities[].cve`

✅ Extraction directe (pas de parsing regex nécessaire).

### 5.6.2 Changements possibles

Lors d’une mise à jour CERT-Bund, une révision CSAF peut impacter :

* ajout/suppression de CVE
* modification `product_status.known_affected`
* ajout de nouveaux `product_id` (nouvelles versions affectées)
* ajout de produits corrigés (`*-fixed`)
* enrichissement des références

---

## 5.7 Champs critiques à capturer dans une base interne

### 5.7.1 Identité

* `cert_bund_id` : `document.tracking.id` (ex. `WID-SEC-W-2026-0004`)
* `title` : `document.title`
* `source` : `CERT-Bund`
* `portal_url` : référence `category=self` portail (si dispo)
* `csaf_url` : référence `category=self` CSAF JSON (si dispo)

### 5.7.2 Contenu

* `summary` : note `category=summary`
* `description` : note `category=description`
* `severity_text` : `document.aggregate_severity.text`
* `tlp` : `document.distribution.tlp.label`

### 5.7.3 Produits affectés

* `affected_products[]` : résolution via :

  * `product_tree`
  * `vulnerabilities[].product_status.known_affected`

### 5.7.4 Vulnérabilités liées

* `cve_ids[]` : `vulnerabilities[].cve`

### 5.7.5 Références

* `references[]` : `document.references[]`

### 5.7.6 Détection de changements

* `tracking.version`
* `tracking.current_release_date`
* `revision_history[]`
* `etag`
* `fetched_at`
* `content_hash`

---

## 5.8 Bonnes pratiques pour synchronisation (pipeline)

### 5.8.1 Import initial (historique)

Objectif : construire un référentiel complet.

* récupérer les feeds `WHITE`
* itérer sur toutes les entrées ROLIE
* télécharger chaque CSAF JSON
* stocker brut + normalisé

✅ Bonnes pratiques :

* conserver les advisories CSAF brutes
* construire un index interne sur `tracking.id`

---

### 5.8.2 Synchronisation incrémentale (recommandée)

* exécuter le crawler feed CSAF à fréquence régulière
* pour chaque item :

  * récupérer CSAF
  * comparer :

    * `tracking.version`
    * ou `content_hash`
  * si changement → reprocessing

✅ Stratégie :

* **feed ROLIE** = découverte
* **CSAF JSON** = vérité
* **JSON interne pivot** = exploitation

---

### 5.8.3 Détection des changements critiques

Surveiller particulièrement :

* ajout d’une CVE critique à un advisory existant
* extension du périmètre `known_affected`
* apparition d’un fixed product (`*-fixed`) indiquant un correctif
* nouvelles références exploit / PoC

---

## 5.9 Résumé (à retenir)

* CERT-Bund publie des **documents opérationnels**, structurés via **CSAF**

* Les mises à jour sont pilotées via :

  * `document.tracking.version`
  * `current_release_date`
  * `revision_history`

* Pour un référentiel interne fiable :

  * feeds WHITE = découverte
  * CSAF JSON = extraction
  * tracking/hash = détection update

* Meilleure méthode :

  * import historique via feed ROLIE
  * incrémental via comparaison version/hash
