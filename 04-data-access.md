## Table des matières

1. [Introduction et contexte CERT-Bund](./01-introduction.md)
2. [Typologie : Warnungen / Advisories / Lageberichte / Analyses](./02-typology.md)
3. [Structure des données et Parsing](./03-data-structure-parsing.md)
4. [Accès aux données (Portail, RSS, endpoints)](./04-data-access.md)
5. [Cycle de vie et Mises à jour](./05-lifecycle.md)

---

# 4. Accès aux données (CERT-Bund / BSI)

## 4.1 Vue d’ensemble

L’accès aux publications du **CERT-Bund / BSI** est principalement assuré via :

* le portail **WID (Warn- und Informationsdienst)**,
* la diffusion **CSAF machine-readable** via les endpoints `/.well-known/csaf/`.

Contrairement à des sources à base de HTML/PDF uniquement, le BSI propose un modèle standardisé, exploitable directement en ingestion :

* découverte des feeds via **provider-metadata.json**
* lecture de **feeds ROLIE (listes d’advisories)**
* récupération des advisories unitaires CSAF (JSON)

L’objectif opérationnel est de disposer de mécanismes automatisables pour :

* détecter de nouvelles publications,
* récupérer le JSON CSAF source,
* historiser / versionner,
* alimenter les pipelines CTI/SOC.

---

## 4.2 Points d’entrée officiels (Portail & Endpoints CSAF)

| Type de contenu                        | Point d’accès                                                      | Description et usage                                                                                                                  |
| :------------------------------------- | :----------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------ |
| **Provider Metadata (CSAF discovery)** | `https://wid.cert-bund.de/.well-known/csaf/provider-metadata.json` | Point d’entrée officiel pour découvrir les feeds CSAF disponibles (TLP, URLs feed ROLIE).                                             |
| **Portail WID (Kurzinformationen)**    | `https://wid.cert-bund.de/portal/wid/kurzinformationen`            | Portail web (lecture humaine) : listes d’informations et alertes courtes. Utile pour crawling/monitoring, mais moins stable que CSAF. |

---

## 4.3 Découverte des feeds CSAF (provider-metadata.json)

Le fichier `provider-metadata.json` expose la liste des flux ROLIE disponibles.

Extrait (à retenir uniquement : TLP WHITE) :

```json
{
  "canonical_url": "https://wid.cert-bund.de/.well-known/csaf/provider-metadata.json",
  "distributions": [
    {
      "rolie": {
        "feeds": [
          {
            "tlp_label": "WHITE",
            "url": "https://wid.cert-bund.de/.well-known/csaf/white/bsi-white.json"
          },
          {
            "tlp_label": "WHITE",
            "url": "https://wid.cert-bund.de/.well-known/csaf/white/bsi-wid-white.json"
          },
          {
            "tlp_label": "WHITE",
            "url": "https://wid.cert-bund.de/.well-known/csaf/white/bsi-cvd-white.json"
          }
        ]
      }
    }
  ]
}
```

### Recommandation

✅ Restreindre l’ingestion aux feeds **TLP:WHITE** (information publiquement diffusable), et ignorer les feeds `GREEN`.

---

## 4.4 Feeds ROLIE / CSAF à ingérer (WHITE uniquement)

### 4.4.1 `bsi-white.json`

* **URL** : `https://wid.cert-bund.de/.well-known/csaf/white/bsi-white.json`
* **Contenu** : flux général BSI (publique).
* **Usage** : veille standard, couverture large.

### 4.4.2 `bsi-wid-white.json`

* **URL** : `https://wid.cert-bund.de/.well-known/csaf/white/bsi-wid-white.json`
* **Contenu** : publications WID orientées vulnérabilités / sécurité.
* **Usage** : ingestion advisories cert-bund exploitables SOC/vuln.

### 4.4.3 `bsi-cvd-white.json`

* **URL** : `https://wid.cert-bund.de/.well-known/csaf/white/bsi-cvd-white.json`
* **Contenu** : advisories issus du processus CVD (Coordinated Vulnerability Disclosure) BSI.
* **Usage** : vulnérabilités confirmées, souvent associées à CVE.

---

## 4.5 Méthodes d’accès recommandées

### 4.5.1 Collecte CSAF (recommandée)

* **Approche** :

  1. charger `provider-metadata.json`
  2. extraire les URLs des feeds `WHITE`
  3. parser les feeds ROLIE (liste d’items)
  4. télécharger les advisories unitaires CSAF (JSON)

* **Avantages** :

  * machine-readable
  * robuste
  * adapté ingestion incrémentale

* **Limites** :

  * dépendance au schéma CSAF
  * besoin de traiter correctement le versioning (`tracking`)

✅ Bonnes pratiques :

* conserver le CSAF brut
* dédoublonner par `document.tracking.id`
* gérer mises à jour via `tracking.version` / `revision_history`

---

### 4.5.2 Collecte portail WID (fallback / enrichissement)

* **URL** : `https://wid.cert-bund.de/portal/wid/kurzinformationen`

* **Approche** : crawling HTML ou monitoring des changements.

* **Avantages** :

  * visibilité humaine
  * détection de “breaking news” / alertes courtes

* **Limites** :

  * structure HTML peut évoluer
  * moins fiable que CSAF pour l’automatisation

✅ Bonnes pratiques :

* parser DOM (CSS selectors / XPath)
* conserver HTML brut (audit)
* corréler les items portail aux items CSAF via références `self`.

---

## 4.6 Ingestion incrémentale & state store

Pour garantir une ingestion fiable :

* stocker l’état : dernier `document.tracking.current_release_date` traité (par feed)
* dédoublonner sur :

  * `document.tracking.id`
  * * `tracking.version`
* déclencher une alerte si une version change (update silencieux)

✅ Objectif SOC/CTI : garantir traçabilité, éviter les “missed updates”.
