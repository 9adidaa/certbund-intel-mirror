## Table des matières

1. [Introduction et contexte CERT-Bund](./01-introduction.md)
2. [Typologie : Warnungen / Advisories / Lageberichte / Analyses](./02-typology.md)
3. [Structure des données et Parsing](./03-data-structure-parsing.md)
4. [Accès aux données (Portail, RSS, endpoints)](./04-data-access.md)
5. [Cycle de vie et Mises à jour](./05-lifecycle.md)

---

# 3. Structure des données — CERT-Bund / BSI (CSAF & modèle JSON)

## 3.1 Objectif de cette section

Cette section décrit la structure des données exploitables côté **CERT-Bund / BSI**, principalement via le format **CSAF (Common Security Advisory Framework)**.

Objectifs :

* ingestion des publications depuis le **portail WID** et/ou endpoints CSAF,
* extraction des **métadonnées** (identifiant WID, dates, titre, langue),
* parsing des sections riches (notes descriptives / résumés / disclaimers),
* extraction de données actionnables : **CVE**, produits affectés, versions, CPE, références,
* normalisation vers un modèle interne SOC/CTI.

---

## 3.2 Format général des données (CSAF)

Contrairement à des CERT diffusant majoritairement des PDF/HTML (scraping), CERT-Bund / BSI publie des advisories sous un format **machine-readable** standardisé : **CSAF v2.0**.

Le CSAF est structuré autour de trois blocs majeurs :

* `document` : métadonnées + informations éditoriales
* `product_tree` : description normalisée des produits / vendors / versions
* `vulnerabilities` : liste des CVE et statut d’affectation

✅ Dans une chaîne d’ingestion, il est recommandé de conserver :

* le JSON CSAF brut (source of truth),
* un JSON interne normalisé (pivot CTI/SOC).

---

## 3.3 Modèle de données (JSON CSAF) — champ par champ

> Exemple : objet représentant un **BSI CERT-Bund Security Advisory** au format CSAF.

### 3.3.1 `document`

Objet principal contenant la partie « publication » : qui publie, quoi, quand, quelle sévérité.

#### `document.aggregate_severity`

Sévérité globale agrégée de la publication (au niveau advisory), typiquement textuelle.

* **Type** : object
* **Champ** : `text` (string)
* **Exemples** : `"mittel"`, `"hoch"`
* **Usage** :

  * classification rapide,
  * mapping vers un score interne (low/medium/high/critical),
  * triage SOC.

⚠️ Attention : ce champ n’est pas un CVSS numérique mais une **gravité éditoriale**.

---

#### `document.category`

Catégorie de document CSAF.

* **Type** : string
* **Exemple** : `"csaf_base"`
* **Usage** : validation du schéma.

---

#### `document.csaf_version`

Version du standard CSAF.

* **Type** : string
* **Exemple** : `"2.0"`
* **Usage** :

  * validation,
  * compatibilité parsing.

---

#### `document.distribution.tlp`

Information de diffusion selon le modèle **TLP (Traffic Light Protocol)**.

* **Type** : object
* **Champs** :

  * `label` (string) — ex. `"WHITE"`
  * `url` (string) — ex. `https://www.first.org/tlp/`
* **Usage** :

  * gouvernance partage / redistribution,
  * politique interne de visibilité.

---

#### `document.lang`

Langue principale de la publication.

* **Type** : string
* **Exemple** : `"de-DE"`
* **Usage** :

  * routage NLP/LLM,
  * traduction,
  * indexation.

---

#### `document.source_lang`

Langue de la source d’origine, si différente.

* **Type** : string
* **Exemple** : `"en-US"`
* **Usage** :

  * différencier contenu traduit/issu de sources externes.

---

#### `document.title`

Titre de la publication (lecture humaine).

* **Type** : string
* **Exemples** :

  * `"Gitea: Schwachstelle ermöglicht Offenlegung von Informationen"`
  * `"Moxa NPort: Mehrere Schwachstellen"`
* **Usage** :

  * affichage dashboards,
  * classification vendor/product,
  * feature NLP.

---

#### `document.publisher`

Informations sur l’éditeur de la publication.

* **Type** : object
* **Champs** :

  * `category` — ex. `"other"`
  * `contact_details` — ex. `csaf-provider@cert-bund.de`
  * `name` — ex. `Bundesamt für Sicherheit in der Informationstechnik`
  * `namespace` — ex. `https://www.bsi.bund.de`
* **Usage** :

  * attribution,
  * contact SOC/CSIRT,
  * pivot de provenance.

---

#### `document.notes[]`

Liste de notes éditoriales. Cette section contient une part importante de la **sémantique utile**.

* **Type** : array(object)
* **Champs typiques** :

  * `category` — ex. `legal_disclaimer`, `description`, `summary`, `general`
  * `text` — contenu texte
  * `title` — optionnel

Catégories usuelles observées :

* `legal_disclaimer` : disclaimer légal BSI
* `description` : description du produit
* `summary` : résumé attaque/impact
* `general` : informations complémentaires (ex : OS affectés)

**Usage SOC/CTI :**

* extraire `summary` comme snippet/preview,
* tagger les impacts (`information disclosure`, `DoS`, `RCE`, etc.),
* extraction OS affectés.

---

#### `document.references[]`

Références structurées : self links + sources externes.

* **Type** : array(object)
* **Champs** :

  * `category` — `self` / `external`
  * `summary` — description
  * `url` — lien

On observe généralement deux entrées `self` :

* **CSAF Version** (JSON) : endpoint `/.well-known/csaf/...json`
* **Portal Version** (HTML) : page WID sur `wid.cert-bund.de/portal/...`

✅ Bonnes pratiques :

* considérer la référence CSAF comme source machine-readable,
* utiliser la référence portail pour affichage / contexte.

---

#### `document.tracking`

Bloc de suivi de version (cycle de vie du document CSAF).

* **Type** : object
* **Champs clés** :

  * `id` — ex. `WID-SEC-W-2026-0001`
  * `status` — ex. `final`
  * `version` — ex. `1`
  * `initial_release_date`
  * `current_release_date`
  * `revision_history[]` : liste des révisions
  * `generator` : moteur générant le JSON (BSI-WID)

**Usage :**

* dédoublonnage par `tracking.id`
* gestion de mises à jour (version / revision_history)
* ingestion incrémentale (dates)

✅ Recommandation : normaliser toutes les dates en **ISO-8601 UTC** dans le modèle interne.

---

### 3.3.2 `product_tree`

Décrit les produits affectés sous forme d’arbre.

#### `product_tree.branches[]`

Structure hiérarchique généralement observée :

* `vendor` → `product_name` → `product_version_range` / `product_version`

Chaque feuille peut contenir un objet `product` avec :

* `name`
* `product_id`
* `product_identification_helper.cpe` (optionnel mais précieux)

---

#### Exemple de lecture

* vendor : `Open Source`
* product_name : `Gitea`
* range : `<1.25.2` (affected)
* version : `1.25.2` (fixed)

**Usage :**

* inventory matching (CMDB ↔ vendor/product/version)
* génération d’un dictionnaire `product_id → {vendor, product, version_range}`
* normalisation CPE lorsque présent

---

### 3.3.3 `vulnerabilities[]`

Liste des vulnérabilités documentées (souvent 1..n CVE).

#### `vulnerabilities[].cve`

* **Type** : string
* **Exemples** : `CVE-2025-69413`, `CVE-2025-1977`
* **Usage** :

  * corrélation NVD,
  * enrichissement CVSS/CWE,
  * corrélation CISA KEV,
  * scoring EPSS.

---

#### `vulnerabilities[].product_status`

Statut des produits associés à une vulnérabilité.

* **Type** : object
* **Champ courant** : `known_affected[]`
* **Valeur** : liste de `product_id` issus du `product_tree`

✅ Bonnes pratiques :

* résoudre les `product_id` vers vendor/product/version_range
* produire une liste finale `affected_products[]` normalisée

---

#### `vulnerabilities[].release_date`

Date de publication associée à la vulnérabilité (souvent alignée avec advisory).

* **Type** : string (datetime ISO-8601)
* **Exemple** : `2026-01-01T23:00:00.000+00:00`

---

#### `vulnerabilities[].title`

Titre/label de la vulnérabilité.

* **Type** : string
* **Exemple** : `"CVE-2025-69413"`

---

## 3.4 Mapping vers un modèle interne (recommandé)

Pour exploitation CTI/SOC, il est recommandé de normaliser CSAF vers un schéma pivot :

* `doc_id` : `document.tracking.id` (ex. `WID-SEC-W-2026-0001`)
* `doc_type` : dérivé du portail (Security Advisory / Warnung)
* `source` : `CERT-Bund`
* `title` : `document.title`
* `severity_text` : `document.aggregate_severity.text`
* `tlp` : `document.distribution.tlp.label`
* `published_at` : `document.tracking.initial_release_date`
* `updated_at` : `document.tracking.current_release_date`
* `summary` : note `category=summary`
* `description` : note `category=description`
* `references[]` : `document.references`
* `cve_list[]` : `vulnerabilities[].cve`
* `affected_products[]` : resolved via `product_tree` + `product_status`
* `cpe_list[]` : extraction `product_identification_helper.cpe`
* `raw_csaf` : JSON brut conservé

✅ Cela permet ensuite de corréler automatiquement :

* CERT-Bund ↔ CVE ↔ NVD
* CERT-Bund ↔ CISA KEV / EPSS
* CERT-Bund ↔ actifs internes (CMDB)

---

## 3.5 Points de vigilance

* **Multi-langue** : contenu principal en allemand (`de-DE`) mais sources possibles en anglais (`source_lang`).
* **Sévérité textuelle** : mapping nécessaire vers un score interne.
* **Product IDs** : indispensables pour relier vuln → produits. Toujours résoudre via `product_tree`.
* **Versioning** : gérer `tracking.version` + `revision_history`.
* **TLP** : appliquer la gouvernance de redistribution.

# EXEMPLE bid:
``` json
{
  "document": {
    "aggregate_severity": {
      "text": "mittel"
    },
    "category": "csaf_base",
    "csaf_version": "2.0",
    "distribution": {
      "tlp": {
        "label": "WHITE",
        "url": "https://www.first.org/tlp/"
      }
    },
    "lang": "de-DE",
    "notes": [
      {
        "category": "legal_disclaimer",
        "text": "Das BSI ist als Anbieter für die eigenen, zur Nutzung bereitgestellten Inhalte nach den allgemeinen Gesetzen verantwortlich. Nutzerinnen und Nutzer sind jedoch dafür verantwortlich, die Verwendung und/oder die Umsetzung der mit den Inhalten bereitgestellten Informationen sorgfältig im Einzelfall zu prüfen."
      },
      {
        "category": "description",
        "text": "Gitea ist ein quelloffener Github-Klon.",
        "title": "Produktbeschreibung"
      },
      {
        "category": "summary",
        "text": "Ein entfernter, anonymer Angreifer kann eine Schwachstelle in Gitea ausnutzen, um Informationen offenzulegen.",
        "title": "Angriff"
      },
      {
        "category": "general",
        "text": "- Linux\n- Sonstiges\n- UNIX\n- Windows",
        "title": "Betroffene Betriebssysteme"
      }
    ],
    "publisher": {
      "category": "other",
      "contact_details": "csaf-provider@cert-bund.de",
      "name": "Bundesamt für Sicherheit in der Informationstechnik",
      "namespace": "https://www.bsi.bund.de"
    },
    "references": [
      {
        "category": "self",
        "summary": "WID-SEC-W-2026-0001 - CSAF Version",
        "url": "https://wid.cert-bund.de/.well-known/csaf/white/2026/wid-sec-w-2026-0001.json"
      },
      {
        "category": "self",
        "summary": "WID-SEC-2026-0001 - Portal Version",
        "url": "https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0001"
      },
      {
        "category": "external",
        "summary": "Red Hat Bugtracker vom 2026-01-01",
        "url": "https://bugzilla.redhat.com/show_bug.cgi?id=2426570"
      },
      {
        "category": "external",
        "summary": "GitHub Advisory Database vom 2026-01-01",
        "url": "https://github.com/advisories/GHSA-pc73-rj2c-wvf9"
      }
    ],
    "source_lang": "en-US",
    "title": "Gitea: Schwachstelle ermöglicht Offenlegung von Informationen",
    "tracking": {
      "current_release_date": "2026-01-01T23:00:00.000+00:00",
      "generator": {
        "date": "2026-01-02T08:50:19.767+00:00",
        "engine": {
          "name": "BSI-WID",
          "version": "1.5.0"
        }
      },
      "id": "WID-SEC-W-2026-0001",
      "initial_release_date": "2026-01-01T23:00:00.000+00:00",
      "revision_history": [
        {
          "date": "2026-01-01T23:00:00.000+00:00",
          "number": "1",
          "summary": "Initiale Fassung"
        }
      ],
      "status": "final",
      "version": "1"
    }
  },
  "product_tree": {
    "branches": [
      {
        "branches": [
          {
            "branches": [
              {
                "category": "product_version_range",
                "name": "<1.25.2",
                "product": {
                  "name": "Open Source Gitea <1.25.2",
                  "product_id": "F01D343C-598A-4AFF-AC65-271C2F572704"
                }
              },
              {
                "category": "product_version",
                "name": "1.25.2",
                "product": {
                  "name": "Open Source Gitea 1.25.2",
                  "product_id": "F01D343C-598A-4AFF-AC65-271C2F572704-fixed",
                  "product_identification_helper": {
                    "cpe": "cpe:/a:gitea:gitea:1.25.2"
                  }
                }
              }
            ],
            "category": "product_name",
            "name": "Gitea"
          }
        ],
        "category": "vendor",
        "name": "Open Source"
      }
    ]
  },
  "vulnerabilities": [
    {
      "cve": "CVE-2025-69413",
      "product_status": {
        "known_affected": [
          "F01D343C-598A-4AFF-AC65-271C2F572704"
        ]
      },
      "release_date": "2026-01-01T23:00:00.000+00:00",
      "title": "CVE-2025-69413"
    }
  ]
}
```
# EXEMPLE bid-wid:
``` json
{
  "document": {
    "aggregate_severity": {
      "text": "mittel"
    },
    "category": "csaf_base",
    "csaf_version": "2.0",
    "distribution": {
      "tlp": {
        "label": "WHITE",
        "url": "https://www.first.org/tlp/"
      }
    },
    "lang": "de-DE",
    "notes": [
      {
        "category": "legal_disclaimer",
        "text": "Das BSI ist als Anbieter für die eigenen, zur Nutzung bereitgestellten Inhalte nach den allgemeinen Gesetzen verantwortlich. Nutzerinnen und Nutzer sind jedoch dafür verantwortlich, die Verwendung und/oder die Umsetzung der mit den Inhalten bereitgestellten Informationen sorgfältig im Einzelfall zu prüfen."
      },
      {
        "category": "description",
        "text": "Gitea ist ein quelloffener Github-Klon.",
        "title": "Produktbeschreibung"
      },
      {
        "category": "summary",
        "text": "Ein entfernter, anonymer Angreifer kann eine Schwachstelle in Gitea ausnutzen, um Informationen offenzulegen.",
        "title": "Angriff"
      },
      {
        "category": "general",
        "text": "- Linux\n- Sonstiges\n- UNIX\n- Windows",
        "title": "Betroffene Betriebssysteme"
      }
    ],
    "publisher": {
      "category": "other",
      "contact_details": "csaf-provider@cert-bund.de",
      "name": "Bundesamt für Sicherheit in der Informationstechnik",
      "namespace": "https://www.bsi.bund.de"
    },
    "references": [
      {
        "category": "self",
        "summary": "WID-SEC-W-2026-0001 - CSAF Version",
        "url": "https://wid.cert-bund.de/.well-known/csaf/white/2026/wid-sec-w-2026-0001.json"
      },
      {
        "category": "self",
        "summary": "WID-SEC-2026-0001 - Portal Version",
        "url": "https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0001"
      },
      {
        "category": "external",
        "summary": "Red Hat Bugtracker vom 2026-01-01",
        "url": "https://bugzilla.redhat.com/show_bug.cgi?id=2426570"
      },
      {
        "category": "external",
        "summary": "GitHub Advisory Database vom 2026-01-01",
        "url": "https://github.com/advisories/GHSA-pc73-rj2c-wvf9"
      }
    ],
    "source_lang": "en-US",
    "title": "Gitea: Schwachstelle ermöglicht Offenlegung von Informationen",
    "tracking": {
      "current_release_date": "2026-01-01T23:00:00.000+00:00",
      "generator": {
        "date": "2026-01-02T08:50:19.767+00:00",
        "engine": {
          "name": "BSI-WID",
          "version": "1.5.0"
        }
      },
      "id": "WID-SEC-W-2026-0001",
      "initial_release_date": "2026-01-01T23:00:00.000+00:00",
      "revision_history": [
        {
          "date": "2026-01-01T23:00:00.000+00:00",
          "number": "1",
          "summary": "Initiale Fassung"
        }
      ],
      "status": "final",
      "version": "1"
    }
  },
  "product_tree": {
    "branches": [
      {
        "branches": [
          {
            "branches": [
              {
                "category": "product_version_range",
                "name": "<1.25.2",
                "product": {
                  "name": "Open Source Gitea <1.25.2",
                  "product_id": "F01D343C-598A-4AFF-AC65-271C2F572704"
                }
              },
              {
                "category": "product_version",
                "name": "1.25.2",
                "product": {
                  "name": "Open Source Gitea 1.25.2",
                  "product_id": "F01D343C-598A-4AFF-AC65-271C2F572704-fixed",
                  "product_identification_helper": {
                    "cpe": "cpe:/a:gitea:gitea:1.25.2"
                  }
                }
              }
            ],
            "category": "product_name",
            "name": "Gitea"
          }
        ],
        "category": "vendor",
        "name": "Open Source"
      }
    ]
  },
  "vulnerabilities": [
    {
      "cve": "CVE-2025-69413",
      "product_status": {
        "known_affected": [
          "F01D343C-598A-4AFF-AC65-271C2F572704"
        ]
      },
      "release_date": "2026-01-01T23:00:00.000+00:00",
      "title": "CVE-2025-69413"
    }
  ]
}
```
# EXEMPLE bid-cvd:
``` json
{
  "document": {
    "acknowledgments": [
      {
        "organization": "E.ON Pentesting",
        "summary": "discovering and reporting this vulnerability and providing a proof of concept."
      }
    ],
    "aggregate_severity": {
      "text": "High"
    },
    "category": "csaf_security_advisory",
    "csaf_version": "2.0",
    "distribution": {
      "tlp": {
        "label": "WHITE",
        "url": "https://www.first.org/tlp/"
      }
    },
    "lang": "en-US",
    "notes": [
      {
        "category": "legal_disclaimer",
        "text": "As a content provider, BSI is responsible under general law for its own content distributed for use. However, it remains your responsibility to carefully check usage and/or implementation of information provided with the content.",
        "title": "Legal disclaimer"
      },
      {
        "category": "summary",
        "text": "An attacker can exploit multiple vulnerabilities in VibroLine and AvibiaLine devices to gain unauthorized access or execute a denial of service attack.",
        "title": "Summary"
      },
      {
        "category": "description",
        "text": "The VibroLine and AvibiaLine devices are a condition monitoring solution for industrial applications",
        "title": "Product description"
      }
    ],
    "publisher": {
      "category": "coordinator",
      "name": "Bundesamt für Sicherheit in der Informationstechnik",
      "namespace": "https://www.bsi.bund.de"
    },
    "references": [
      {
        "category": "external",
        "summary": "IDS-2026-0001 - CSAF version",
        "url": "https://www.innomic.com/.well-known/csaf/white/2026/ids-2026-0001.json"
      },
      {
        "category": "external",
        "summary": "IDS-2026-0001 - HTML version",
        "url": "https://www.innomic.com/.well-known/csaf/white/2026/ids-2026-0001.html"
      },
      {
        "category": "external",
        "summary": "AVIBIA-2026-0001 - CSAF version",
        "url": "https://www.avibia.de/.well-known/csaf/white/2026/avibia-2026-0001.json"
      },
      {
        "category": "external",
        "summary": "AVIBIA-2026-0001 - HTML version",
        "url": "https://www.avibia.de/.well-known/csaf/white/2026/avibia-2026-0001.html"
      },
      {
        "category": "self",
        "summary": "BSI-2026-0001 - CSAF Version",
        "url": "https://wid.cert-bund.de/.well-known/csaf/white/2026/bsi-2026-0001.json"
      }
    ],
    "title": "Unauthorized access affects VibroLine and AvibiaLine devices",
    "tracking": {
      "aliases": [
        "IDS-2026-0001",
        "AVIBIA-2026-0001"
      ],
      "current_release_date": "2026-02-02T13:00:00.000Z",
      "generator": {
        "date": "2026-01-29T13:36:39.007Z",
        "engine": {
          "name": "Secvisogram",
          "version": "2.5.42"
        }
      },
      "id": "BSI-2026-0001",
      "initial_release_date": "2026-02-02T13:00:00.000Z",
      "revision_history": [
        {
          "date": "2026-02-02T13:00:00.000Z",
          "number": "1",
          "summary": "Initial publication"
        }
      ],
      "status": "final",
      "version": "1"
    }
  },
  "product_tree": {
    "branches": [
      {
        "branches": [
          {
            "branches": [
              {
                "branches": [
                  {
                    "category": "product_name",
                    "name": "VLE1 HD 4.0",
                    "product": {
                      "name": "VibroLine VLE1 HD 4.0",
                      "product_id": "CSAFPID-0101",
                      "product_identification_helper": {
                        "skus": [
                          "i8005"
                        ]
                      }
                    }
                  },
                  {
                    "category": "product_name",
                    "name": "VLE2 HD 4.0",
                    "product": {
                      "name": "VibroLine VLE2 HD 4.0",
                      "product_id": "CSAFPID-0102",
                      "product_identification_helper": {
                        "skus": [
                          "i8006"
                        ]
                      }
                    }
                  },
                  {
                    "category": "product_name",
                    "name": "VLE4 HD 4.0",
                    "product": {
                      "name": "VibroLine VLE4 HD 4.0",
                      "product_id": "CSAFPID-0103",
                      "product_identification_helper": {
                        "skus": [
                          "i8007"
                        ]
                      }
                    }
                  },
                  {
                    "category": "product_name",
                    "name": "VLE6 HD 4.0",
                    "product": {
                      "name": "VibroLine VLE6 HD 4.0",
                      "product_id": "CSAFPID-0104",
                      "product_identification_helper": {
                        "skus": [
                          "i8008"
                        ]
                      }
                    }
                  },
                  {
                    "category": "product_name",
                    "name": "VLE8 HD 4.0",
                    "product": {
                      "name": "VibroLine VLE8 HD 4.0",
                      "product_id": "CSAFPID-0105",
                      "product_identification_helper": {
                        "skus": [
                          "i8009"
                        ]
                      }
                    }
                  }
                ],
                "category": "product_family",
                "name": "VLE"
              },
              {
                "branches": [
                  {
                    "category": "product_name",
                    "name": "VLX1 HD 4.0",
                    "product": {
                      "name": "VibroLine VLX1 HD 4.0",
                      "product_id": "CSAFPID-0106",
                      "product_identification_helper": {
                        "skus": [
                          "i80015"
                        ]
                      }
                    }
                  },
                  {
                    "category": "product_name",
                    "name": "VLX2 HD 4.0",
                    "product": {
                      "name": "VibroLine VLX2 HD 4.0",
                      "product_id": "CSAFPID-0107",
                      "product_identification_helper": {
                        "skus": [
                          "i80016"
                        ]
                      }
                    }
                  },
                  {
                    "category": "product_name",
                    "name": "VLX4 HD 4.0",
                    "product": {
                      "name": "VibroLine VLX4 HD 4.0",
                      "product_id": "CSAFPID-0108",
                      "product_identification_helper": {
                        "skus": [
                          "i80017"
                        ]
                      }
                    }
                  },
                  {
                    "category": "product_name",
                    "name": "VLX6 HD 4.0",
                    "product": {
                      "name": "VibroLine VLX6 HD 4.0",
                      "product_id": "CSAFPID-0109",
                      "product_identification_helper": {
                        "skus": [
                          "i80018"
                        ]
                      }
                    }
                  },
                  {
                    "category": "product_name",
                    "name": "VLX8 HD 4.0",
                    "product": {
                      "name": "VibroLine VLX8 HD 4.0",
                      "product_id": "CSAFPID-0110",
                      "product_identification_helper": {
                        "skus": [
                          "i80019"
                        ]
                      }
                    }
                  }
                ],
                "category": "product_family",
                "name": "VLX"
              },
              {
                "branches": [
                  {
                    "branches": [
                      {
                        "category": "product_version_range",
                        "name": "vers:intdot/>=1.4.1074|<=1.4.1116",
                        "product": {
                          "name": "VibroLine 4.0 VLE Firmware 1.4.1074 - 1.4.1116",
                          "product_id": "CSAFPID-0111"
                        }
                      }
                    ],
                    "category": "product_name",
                    "name": "VibroLine 4.0 VLE Firmware"
                  },
                  {
                    "branches": [
                      {
                        "category": "product_version_range",
                        "name": "vers:intdot/>=1.5.1074|<=1.5.1116",
                        "product": {
                          "name": "VibroLine 4.0 VLX Firmware 1.5.1074 - 1.5.1116",
                          "product_id": "CSAFPID-0099"
                        }
                      }
                    ],
                    "category": "product_name",
                    "name": "VibroLine 4.0 VLX Firmware"
                  }
                ],
                "category": "product_family",
                "name": "VibroLine 4.0 Firmware"
              },
              {
                "branches": [
                  {
                    "category": "product_version_range",
                    "name": "vers:intdot/>=4.0.1931|<=4.0.2406",
                    "product": {
                      "name": "VibroLine Configurator 4.0.1931 - 4.0.2406",
                      "product_id": "CSAFPID-0114"
                    }
                  }
                ],
                "category": "product_name",
                "name": "VibroLine 4.0 Configurator"
              }
            ],
            "category": "product_family",
            "name": "VibroLine 4.0"
          },
          {
            "branches": [
              {
                "branches": [
                  {
                    "category": "product_name",
                    "name": "VLE1 HD 5.0",
                    "product": {
                      "name": "VibroLine VLE1 HD 5.0",
                      "product_id": "CSAFPID-0001",
                      "product_identification_helper": {
                        "skus": [
                          "i8005-5.0"
                        ]
                      }
                    }
                  },
                  {
                    "category": "product_name",
                    "name": "VLE2 HD 5.0",
                    "product": {
                      "name": "VibroLine VLE2 HD 5.0",
                      "product_id": "CSAFPID-0002",
                      "product_identification_helper": {
                        "skus": [
                          "i8006-5.0"
                        ]
                      }
                    }
                  },
                  {
                    "category": "product_name",
                    "name": "VLE4 HD 5.0",
                    "product": {
                      "name": "VibroLine VLE4 HD 5.0",
                      "product_id": "CSAFPID-0003",
                      "product_identification_helper": {
                        "skus": [
                          "i8007-5.0"
                        ]
                      }
                    }
                  },
                  {
                    "category": "product_name",
                    "name": "VLE6 HD 5.0",
                    "product": {
                      "name": "VibroLine VLE6 HD 5.0",
                      "product_id": "CSAFPID-0004",
                      "product_identification_helper": {
                        "skus": [
                          "i8008-5.0"
                        ]
                      }
                    }
                  },
                  {
                    "category": "product_name",
                    "name": "VLE8 HD 5.0",
                    "product": {
                      "name": "VibroLine VLE8 HD 5.0",
                      "product_id": "CSAFPID-0005",
                      "product_identification_helper": {
                        "skus": [
                          "i8009-5.0"
                        ]
                      }
                    }
                  }
                ],
                "category": "product_family",
                "name": "VLE"
              },
              {
                "branches": [
                  {
                    "category": "product_name",
                    "name": "VLX1 HD 5.0",
                    "product": {
                      "name": "VibroLine VLX1 HD 5.0",
                      "product_id": "CSAFPID-0006",
                      "product_identification_helper": {
                        "skus": [
                          "i80015-5.0"
                        ]
                      }
                    }
                  },
                  {
                    "category": "product_name",
                    "name": "VLX2 HD 5.0",
                    "product": {
                      "name": "VibroLine VLX2 HD 5.0",
                      "product_id": "CSAFPID-0007",
                      "product_identification_helper": {
                        "skus": [
                          "i80016-5.0"
                        ]
                      }
                    }
                  },
                  {
                    "category": "product_name",
                    "name": "VLX4 HD 5.0",
                    "product": {
                      "name": "VibroLine VLX4 HD 5.0",
                      "product_id": "CSAFPID-0008",
                      "product_identification_helper": {
                        "skus": [
                          "i80017-5.0"
                        ]
                      }
                    }
                  },
                  {
                    "category": "product_name",
                    "name": "VLX6 HD 5.0",
                    "product": {
                      "name": "VibroLine VLX6 HD 5.0",
                      "product_id": "CSAFPID-0009",
                      "product_identification_helper": {
                        "skus": [
                          "i80018-5.0"
                        ]
                      }
                    }
                  },
                  {
                    "category": "product_name",
                    "name": "VLX8 HD 5.0",
                    "product": {
                      "name": "VibroLine VLX8 HD 5.0",
                      "product_id": "CSAFPID-0010",
                      "product_identification_helper": {
                        "skus": [
                          "i80019-5.0"
                        ]
                      }
                    }
                  }
                ],
                "category": "product_family",
                "name": "VLX"
              },
              {
                "branches": [
                  {
                    "category": "product_version_range",
                    "name": "vers:intdot/>=2.1.1340|<=2.1.1387",
                    "product": {
                      "name": "VibroLine 5.0 Firmware 2.1.1340 - 2.1.1387",
                      "product_id": "CSAFPID-0011"
                    }
                  },
                  {
                    "category": "product_version",
                    "name": "2.1.1866",
                    "product": {
                      "name": "VibroLine 5.0 Firmware 2.1.1866",
                      "product_id": "CSAFPID-0012",
                      "product_identification_helper": {
                        "hashes": [
                          {
                            "file_hashes": [
                              {
                                "algorithm": "sha256",
                                "value": "67DE7F19D9CC41030C82D30817FD4B95EA9C183F8482A7F325571AC709DD715F"
                              }
                            ],
                            "filename": "VLX_HD_20260202.vlfw"
                          }
                        ]
                      }
                    }
                  }
                ],
                "category": "product_name",
                "name": "VibroLine 5.0 Firmware"
              },
              {
                "branches": [
                  {
                    "category": "product_version_range",
                    "name": "vers:intdot/>=5.0.2416|<=5.1.2547",
                    "product": {
                      "name": "VibroLine Configurator 5.0.2416 - 5.0.2486",
                      "product_id": "CSAFPID-0014"
                    }
                  },
                  {
                    "category": "product_version",
                    "name": "5.1.2732",
                    "product": {
                      "name": "VibroLine Configurator 5.1.2730",
                      "product_id": "CSAFPID-0016",
                      "product_identification_helper": {
                        "hashes": [
                          {
                            "file_hashes": [
                              {
                                "algorithm": "sha256",
                                "value": "86D5007A3606ABF5385AFBD0BF3483728B78A978C641F09A5DEB49B5862D1F84"
                              }
                            ],
                            "filename": "VibroLine_Setup_5.1.2732.exe"
                          }
                        ]
                      }
                    }
                  }
                ],
                "category": "product_name",
                "name": "VibroLine 5.0 Configurator"
              }
            ],
            "category": "product_family",
            "name": "VibroLine 5.0"
          }
        ],
        "category": "vendor",
        "name": "IDS Innomic Schwingungsmesstechnik GmbH"
      },
      {
        "branches": [
          {
            "branches": [
              {
                "branches": [
                  {
                    "category": "product_name",
                    "name": "AVLE2",
                    "product": {
                      "name": "AvibiaLine AVLE2",
                      "product_id": "CSAFPID-0018",
                      "product_identification_helper": {
                        "skus": [
                          "AVIBIAline AVL2"
                        ]
                      }
                    }
                  },
                  {
                    "category": "product_name",
                    "name": "AVLE4",
                    "product": {
                      "name": "AvibiaLine AVLE4",
                      "product_id": "CSAFPID-0019",
                      "product_identification_helper": {
                        "skus": [
                          "AVIBIAline AVL4"
                        ]
                      }
                    }
                  },
                  {
                    "category": "product_name",
                    "name": "AVLE8",
                    "product": {
                      "name": "AvibiaLine AVLE8",
                      "product_id": "CSAFPID-0021",
                      "product_identification_helper": {
                        "skus": [
                          "AVIBIAline AVL8"
                        ]
                      }
                    }
                  }
                ],
                "category": "product_name",
                "name": "AVLE"
              },
              {
                "branches": [
                  {
                    "category": "product_name",
                    "name": "AVLX2",
                    "product": {
                      "name": "AvibiaLine AVLX2",
                      "product_id": "CSAFPID-0023",
                      "product_identification_helper": {
                        "skus": [
                          "AVIBIAline AVL-X2 V5.0"
                        ]
                      }
                    }
                  },
                  {
                    "category": "product_name",
                    "name": "AVLX4",
                    "product": {
                      "name": "AvibiaLine AVLX4",
                      "product_id": "CSAFPID-0024",
                      "product_identification_helper": {
                        "skus": [
                          "AVIBIAline AVL-X4 V5.0"
                        ]
                      }
                    }
                  },
                  {
                    "category": "product_name",
                    "name": "AVLX8",
                    "product": {
                      "name": "AvibiaLine AVLX8",
                      "product_id": "CSAFPID-0026",
                      "product_identification_helper": {
                        "skus": [
                          "AVIBIAline AVL-X8 V5.0"
                        ]
                      }
                    }
                  }
                ],
                "category": "product_name",
                "name": "AVLX"
              },
              {
                "branches": [
                  {
                    "category": "product_version_range",
                    "name": "vers:intdot/>=2.1.1340|<=2.1.1387",
                    "product": {
                      "name": "AvibiaLine Firmware 2.1.1340 - 2.1.1387",
                      "product_id": "CSAFPID-0027"
                    }
                  },
                  {
                    "category": "product_version",
                    "name": "2.1.1866",
                    "product": {
                      "name": "AvibiaLine Firmware 2.1.1866",
                      "product_id": "CSAFPID-0028",
                      "product_identification_helper": {
                        "hashes": [
                          {
                            "file_hashes": [
                              {
                                "algorithm": "sha256",
                                "value": "67DE7F19D9CC41030C82D30817FD4B95EA9C183F8482A7F325571AC709DD715F"
                              }
                            ],
                            "filename": "AVLX_HD_20260202.vlfw"
                          }
                        ]
                      }
                    }
                  }
                ],
                "category": "product_name",
                "name": "AvibiaLine Firmware"
              },
              {
                "branches": [
                  {
                    "category": "product_version_range",
                    "name": "vers:intdot/>=5.0.2416|<=5.0.2486",
                    "product": {
                      "name": "AvibiaLine Configurator 5.0.2416 - 5.0.2486",
                      "product_id": "CSAFPID-0030"
                    }
                  },
                  {
                    "category": "product_version",
                    "name": "5.1.2732",
                    "product": {
                      "name": "AvibiaLine Configurator 5.1.2730",
                      "product_id": "CSAFPID-0031",
                      "product_identification_helper": {
                        "hashes": [
                          {
                            "file_hashes": [
                              {
                                "algorithm": "sha256",
                                "value": "0161933D64226AAA79306A387097E5F2843C234F0E71ADB7ECA659F34DBE9A1A"
                              }
                            ],
                            "filename": "AvibiaLine_Setup_5.1.2732.exe"
                          }
                        ]
                      }
                    }
                  }
                ],
                "category": "product_name",
                "name": "AvibiaLine Configurator"
              }
            ],
            "category": "product_family",
            "name": "AvibiaLine"
          }
        ],
        "category": "vendor",
        "name": "avibia GmbH"
      }
    ],
    "relationships": [
      {
        "category": "installed_on",
        "full_product_name": {
          "name": "VibroLine 5.0 Firmware 2.1.1340 - 2.1.1387 installed on VibroLine VLE1 HD 5.0",
          "product_id": "CSAFPID-0032"
        },
        "product_reference": "CSAFPID-0011",
        "relates_to_product_reference": "CSAFPID-0001"
      },
      {
        "category": "installed_on",
        "full_product_name": {
          "name": "VibroLine 5.0 Firmware 2.1.1340 - 2.1.1387 installed on VibroLine VLE2 HD 5.0",
          "product_id": "CSAFPID-0033"
        },
        "product_reference": "CSAFPID-0011",
        "relates_to_product_reference": "CSAFPID-0002"
      },
      {
        "category": "installed_on",
        "full_product_name": {
          "name": "VibroLine 5.0 Firmware 2.1.1340 - 2.1.1387 installed on VibroLine VLE4 HD 5.0",
          "product_id": "CSAFPID-0034"
        },
        "product_reference": "CSAFPID-0011",
        "relates_to_product_reference": "CSAFPID-0003"
      },
      {
        "category": "installed_on",
        "full_product_name": {
          "name": "VibroLine 5.0 Firmware 2.1.1340 - 2.1.1387 installed on VibroLine VLE6 HD 5.0",
          "product_id": "CSAFPID-0035"
        },
        "product_reference": "CSAFPID-0011",
        "relates_to_product_reference": "CSAFPID-0004"
      },
      {
        "category": "installed_on",
        "full_product_name": {
          "name": "VibroLine 5.0 Firmware 2.1.1340 - 2.1.1387 installed on VibroLine VLE8 HD 5.0",
          "product_id": "CSAFPID-0036"
        },
        "product_reference": "CSAFPID-0011",
        "relates_to_product_reference": "CSAFPID-0005"
      },
      {
        "category": "installed_on",
        "full_product_name": {
          "name": "VibroLine 5.0 Firmware 2.1.1340 - 2.1.1387 installed on VibroLine VLX1 HD 5.0",
          "product_id": "CSAFPID-0037"
        },
        "product_reference": "CSAFPID-0011",
        "relates_to_product_reference": "CSAFPID-0006"
      },
      {
        "category": "installed_on",
        "full_product_name": {
          "name": "VibroLine 5.0 Firmware 2.1.1340 - 2.1.1387 installed on VibroLine VLX2 HD 5.0",
          "product_id": "CSAFPID-0038"
        },
        "product_reference": "CSAFPID-0011",
        "relates_to_product_reference": "CSAFPID-0007"
      },
      {
        "category": "installed_on",
        "full_product_name": {
          "name": "VibroLine 5.0 Firmware 2.1.1340 - 2.1.1387 installed on VibroLine VLX4 HD 5.0",
          "product_id": "CSAFPID-0039"
        },
        "product_reference": "CSAFPID-0011",
        "relates_to_product_reference": "CSAFPID-0008"
      },
      {
        "category": "installed_on",
        "full_product_name": {
          "name": "VibroLine 5.0 Firmware 2.1.1340 - 2.1.1387 installed on VibroLine VLX6 HD 5.0",
          "product_id": "CSAFPID-0040"
        },
        "product_reference": "CSAFPID-0011",
        "relates_to_product_reference": "CSAFPID-0009"
      },
      {
        "category": "installed_on",
        "full_product_name": {
          "name": "VibroLine 5.0 Firmware 2.1.1340 - 2.1.1387 installed on VibroLine VLX8 HD 5.0",
          "product_id": "CSAFPID-0041"
        },
        "product_reference": "CSAFPID-0011",
        "relates_to_product_reference": "CSAFPID-0010"
      },
      {
        "category": "installed_on",
        "full_product_name": {
          "name": "AvibiaLine Firmware 2.1.1340 - 2.1.1387 installed on AvibiaLine AVLE2 HD 5.0",
          "product_id": "CSAFPID-0043"
        },
        "product_reference": "CSAFPID-0027",
        "relates_to_product_reference": "CSAFPID-0018"
      },
      {
        "category": "installed_on",
        "full_product_name": {
          "name": "AvibiaLine Firmware 2.1.1340 - 2.1.1387 installed on AvibiaLine AVLE4 HD 5.0",
          "product_id": "CSAFPID-0044"
        },
        "product_reference": "CSAFPID-0027",
        "relates_to_product_reference": "CSAFPID-0019"
      },
      {
        "category": "installed_on",
        "full_product_name": {
          "name": "AvibiaLine Firmware 2.1.1340 - 2.1.1387 installed on AvibiaLine AVLE8 HD 5.0",
          "product_id": "CSAFPID-0046"
        },
        "product_reference": "CSAFPID-0027",
        "relates_to_product_reference": "CSAFPID-0021"
      },
      {
        "category": "installed_on",
        "full_product_name": {
          "name": "AvibiaLine Firmware 2.1.1340 - 2.1.1387 installed on AvibiaLine AVLX2 HD 5.0",
          "product_id": "CSAFPID-0048"
        },
        "product_reference": "CSAFPID-0027",
        "relates_to_product_reference": "CSAFPID-0023"
      },
      {
        "category": "installed_on",
        "full_product_name": {
          "name": "AvibiaLine Firmware 2.1.1340 - 2.1.1387 installed on AvibiaLine AVLX4 HD 5.0",
          "product_id": "CSAFPID-0049"
        },
        "product_reference": "CSAFPID-0027",
        "relates_to_product_reference": "CSAFPID-0024"
      },
      {
        "category": "installed_on",
        "full_product_name": {
          "name": "AvibiaLine Firmware 2.1.1340 - 2.1.1387 installed on AvibiaLine AVLX8 HD 5.0",
          "product_id": "CSAFPID-0051"
        },
        "product_reference": "CSAFPID-0027",
        "relates_to_product_reference": "CSAFPID-0026"
      },
      {
        "category": "installed_on",
        "full_product_name": {
          "name": "VibroLine 5.0 Firmware 2.1.1866 installed on VibroLine VLE1 HD 5.0",
          "product_id": "CSAFPID-0052"
        },
        "product_reference": "CSAFPID-0012",
        "relates_to_product_reference": "CSAFPID-0001"
      },
      {
        "category": "installed_on",
        "full_product_name": {
          "name": "VibroLine 5.0 Firmware 2.1.1866 installed on VibroLine VLE2 HD 5.0",
          "product_id": "CSAFPID-0053"
        },
        "product_reference": "CSAFPID-0012",
        "relates_to_product_reference": "CSAFPID-0002"
      },
      {
        "category": "installed_on",
        "full_product_name": {
          "name": "VibroLine 5.0 Firmware 2.1.1866 installed on VibroLine VLE4 HD 5.0",
          "product_id": "CSAFPID-0054"
        },
        "product_reference": "CSAFPID-0012",
        "relates_to_product_reference": "CSAFPID-0003"
      },
      {
        "category": "installed_on",
        "full_product_name": {
          "name": "VibroLine 5.0 Firmware 2.1.1866 installed on VibroLine VLE6 HD 5.0",
          "product_id": "CSAFPID-0055"
        },
        "product_reference": "CSAFPID-0012",
        "relates_to_product_reference": "CSAFPID-0004"
      },
      {
        "category": "installed_on",
        "full_product_name": {
          "name": "VibroLine 5.0 Firmware 2.1.1866 installed on VibroLine VLE8 HD 5.0",
          "product_id": "CSAFPID-0056"
        },
        "product_reference": "CSAFPID-0012",
        "relates_to_product_reference": "CSAFPID-0005"
      },
      {
        "category": "installed_on",
        "full_product_name": {
          "name": "VibroLine 5.0 Firmware 2.1.1866 installed on VibroLine VLX1 HD 5.0",
          "product_id": "CSAFPID-0057"
        },
        "product_reference": "CSAFPID-0012",
        "relates_to_product_reference": "CSAFPID-0006"
      },
      {
        "category": "installed_on",
        "full_product_name": {
          "name": "VibroLine 5.0 Firmware 2.1.1866 installed on VibroLine VLX2 HD 5.0",
          "product_id": "CSAFPID-0058"
        },
        "product_reference": "CSAFPID-0012",
        "relates_to_product_reference": "CSAFPID-0007"
      },
      {
        "category": "installed_on",
        "full_product_name": {
          "name": "VibroLine 5.0 Firmware 2.1.1866 installed on VibroLine VLX4 HD 5.0",
          "product_id": "CSAFPID-0059"
        },
        "product_reference": "CSAFPID-0012",
        "relates_to_product_reference": "CSAFPID-0008"
      },
      {
        "category": "installed_on",
        "full_product_name": {
          "name": "VibroLine 5.0 Firmware 2.1.1866 installed on VibroLine VLX6 HD 5.0",
          "product_id": "CSAFPID-0060"
        },
        "product_reference": "CSAFPID-0012",
        "relates_to_product_reference": "CSAFPID-0009"
      },
      {
        "category": "installed_on",
        "full_product_name": {
          "name": "VibroLine 5.0 Firmware 2.1.1866 installed on VibroLine VLX8 HD 5.0",
          "product_id": "CSAFPID-0061"
        },
        "product_reference": "CSAFPID-0012",
        "relates_to_product_reference": "CSAFPID-0010"
      },
      {
        "category": "installed_on",
        "full_product_name": {
          "name": "AvibiaLine Firmware 2.1.1866 installed on AvibiaLine AVLE2 HD 5.0",
          "product_id": "CSAFPID-0063"
        },
        "product_reference": "CSAFPID-0028",
        "relates_to_product_reference": "CSAFPID-0018"
      },
      {
        "category": "installed_on",
        "full_product_name": {
          "name": "AvibiaLine Firmware 2.1.1866 installed on AvibiaLine AVLE4 HD 5.0",
          "product_id": "CSAFPID-0064"
        },
        "product_reference": "CSAFPID-0028",
        "relates_to_product_reference": "CSAFPID-0019"
      },
      {
        "category": "installed_on",
        "full_product_name": {
          "name": "AvibiaLine Firmware 2.1.1866 installed on AvibiaLine AVLE8 HD 5.0",
          "product_id": "CSAFPID-0066"
        },
        "product_reference": "CSAFPID-0028",
        "relates_to_product_reference": "CSAFPID-0021"
      },
      {
        "category": "installed_on",
        "full_product_name": {
          "name": "AvibiaLine Firmware 2.1.1866 installed on AvibiaLine AVLX2 HD 5.0",
          "product_id": "CSAFPID-0068"
        },
        "product_reference": "CSAFPID-0028",
        "relates_to_product_reference": "CSAFPID-0023"
      },
      {
        "category": "installed_on",
        "full_product_name": {
          "name": "AvibiaLine Firmware 2.1.1866 installed on AvibiaLine AVLX4 HD 5.0",
          "product_id": "CSAFPID-0069"
        },
        "product_reference": "CSAFPID-0028",
        "relates_to_product_reference": "CSAFPID-0024"
      },
      {
        "category": "installed_on",
        "full_product_name": {
          "name": "AvibiaLine Firmware 2.1.1866 installed on AvibiaLine AVLX8 HD 5.0",
          "product_id": "CSAFPID-0071"
        },
        "product_reference": "CSAFPID-0028",
        "relates_to_product_reference": "CSAFPID-0026"
      },
      {
        "category": "installed_on",
        "full_product_name": {
          "name": "VibroLine 4.0 Firmware 1.4.1074 - 1.4.1116 installed on VibroLine VLE1 HD 4.0",
          "product_id": "CSAFPID-0132"
        },
        "product_reference": "CSAFPID-0111",
        "relates_to_product_reference": "CSAFPID-0101"
      },
      {
        "category": "installed_on",
        "full_product_name": {
          "name": "VibroLine 4.0 Firmware 1.4.1074 - 1.4.1116 installed on VibroLine VLE2 HD 4.0",
          "product_id": "CSAFPID-0133"
        },
        "product_reference": "CSAFPID-0111",
        "relates_to_product_reference": "CSAFPID-0102"
      },
      {
        "category": "installed_on",
        "full_product_name": {
          "name": "VibroLine 4.0 Firmware 1.4.1074 - 1.4.1116 installed on VibroLine VLE4 HD 4.0",
          "product_id": "CSAFPID-0134"
        },
        "product_reference": "CSAFPID-0111",
        "relates_to_product_reference": "CSAFPID-0103"
      },
      {
        "category": "installed_on",
        "full_product_name": {
          "name": "VibroLine 4.0 Firmware 1.4.1074 - 1.4.1116 installed on VibroLine VLE6 HD 4.0",
          "product_id": "CSAFPID-0135"
        },
        "product_reference": "CSAFPID-0111",
        "relates_to_product_reference": "CSAFPID-0104"
      },
      {
        "category": "installed_on",
        "full_product_name": {
          "name": "VibroLine 4.0 Firmware 1.4.1074 - 1.4.1116 installed on VibroLine VLE8 HD 4.0",
          "product_id": "CSAFPID-0136"
        },
        "product_reference": "CSAFPID-0111",
        "relates_to_product_reference": "CSAFPID-0105"
      },
      {
        "category": "installed_on",
        "full_product_name": {
          "name": "VibroLine 4.0 Firmware 1.5.1074 - 1.5.1116 installed on VibroLine VLX1 HD 4.0",
          "product_id": "CSAFPID-0137"
        },
        "product_reference": "CSAFPID-0099",
        "relates_to_product_reference": "CSAFPID-0106"
      },
      {
        "category": "installed_on",
        "full_product_name": {
          "name": "VibroLine 4.0 Firmware 1.5.1074 - 1.5.1116 installed on VibroLine VLX2 HD 4.0",
          "product_id": "CSAFPID-0138"
        },
        "product_reference": "CSAFPID-0099",
        "relates_to_product_reference": "CSAFPID-0107"
      },
      {
        "category": "installed_on",
        "full_product_name": {
          "name": "VibroLine 4.0 Firmware 1.5.1074 - 1.5.1116 installed on VibroLine VLX4 HD 4.0",
          "product_id": "CSAFPID-0139"
        },
        "product_reference": "CSAFPID-0099",
        "relates_to_product_reference": "CSAFPID-0108"
      },
      {
        "category": "installed_on",
        "full_product_name": {
          "name": "VibroLine 4.0 Firmware 1.5.1074 - 1.5.1116 installed on VibroLine VLX6 HD 4.0",
          "product_id": "CSAFPID-0140"
        },
        "product_reference": "CSAFPID-0099",
        "relates_to_product_reference": "CSAFPID-0109"
      },
      {
        "category": "installed_on",
        "full_product_name": {
          "name": "VibroLine 4.0 Firmware 1.5.1074 - 1.5.1116 installed on VibroLine VLX8 HD 4.0",
          "product_id": "CSAFPID-0141"
        },
        "product_reference": "CSAFPID-0099",
        "relates_to_product_reference": "CSAFPID-0110"
      }
    ]
  },
  "vulnerabilities": [
    {
      "cve": "CVE-2022-50975",
      "cwe": {
        "id": "CWE-346",
        "name": "Origin Validation Error"
      },
      "notes": [
        {
          "category": "summary",
          "text": "The ethernet and USB connections are not properly isolated allowing an attacker to configure and reset the device if configuration via ethernet is enabled and there is at least one legitimately authenticated connection active at the time of the attack.",
          "title": "Vulnerability summary"
        }
      ],
      "product_status": {
        "fixed": [
          "CSAFPID-0057",
          "CSAFPID-0058",
          "CSAFPID-0059",
          "CSAFPID-0060",
          "CSAFPID-0061",
          "CSAFPID-0068",
          "CSAFPID-0069",
          "CSAFPID-0071"
        ],
        "known_affected": [
          "CSAFPID-0037",
          "CSAFPID-0038",
          "CSAFPID-0039",
          "CSAFPID-0040",
          "CSAFPID-0041",
          "CSAFPID-0048",
          "CSAFPID-0049",
          "CSAFPID-0051"
        ],
        "known_not_affected": [
          "CSAFPID-0032",
          "CSAFPID-0033",
          "CSAFPID-0034",
          "CSAFPID-0035",
          "CSAFPID-0036",
          "CSAFPID-0043",
          "CSAFPID-0044",
          "CSAFPID-0046",
          "CSAFPID-0052",
          "CSAFPID-0053",
          "CSAFPID-0054",
          "CSAFPID-0055",
          "CSAFPID-0056",
          "CSAFPID-0063",
          "CSAFPID-0064",
          "CSAFPID-0066",
          "CSAFPID-0132",
          "CSAFPID-0133",
          "CSAFPID-0134",
          "CSAFPID-0135",
          "CSAFPID-0136",
          "CSAFPID-0137",
          "CSAFPID-0138",
          "CSAFPID-0139",
          "CSAFPID-0140",
          "CSAFPID-0141"
        ]
      },
      "remediations": [
        {
          "category": "vendor_fix",
          "details": "Update VibroLine VLX HD 5.0 devices to firmware version 2.1.1866 or later which includes a fix for this vulnerability.",
          "product_ids": [
            "CSAFPID-0037",
            "CSAFPID-0038",
            "CSAFPID-0039",
            "CSAFPID-0040",
            "CSAFPID-0041"
          ],
          "restart_required": {
            "category": "machine",
            "details": "VibroLine VLX HD 5.0 devices will be restarted during firmware update."
          },
          "url": "https://www.innomic.com/downloads/"
        },
        {
          "category": "vendor_fix",
          "details": "Update AvibiaLine AVLX devices to firmware version 2.1.1866 or later which includes a fix for this vulnerability.",
          "product_ids": [
            "CSAFPID-0048",
            "CSAFPID-0049",
            "CSAFPID-0051"
          ],
          "restart_required": {
            "category": "machine",
            "details": "AvibiaLine AVLX devices will be restarted during firmware update."
          },
          "url": "https://www.avibia.de/info-center/download/"
        }
      ],
      "scores": [
        {
          "cvss_v3": {
            "attackComplexity": "LOW",
            "attackVector": "NETWORK",
            "availabilityImpact": "HIGH",
            "baseScore": 8.8,
            "baseSeverity": "HIGH",
            "confidentialityImpact": "HIGH",
            "environmentalScore": 8.2,
            "environmentalSeverity": "HIGH",
            "exploitCodeMaturity": "FUNCTIONAL",
            "integrityImpact": "HIGH",
            "privilegesRequired": "NONE",
            "remediationLevel": "OFFICIAL_FIX",
            "reportConfidence": "CONFIRMED",
            "scope": "UNCHANGED",
            "temporalScore": 8.2,
            "temporalSeverity": "HIGH",
            "userInteraction": "REQUIRED",
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C",
            "version": "3.1"
          },
          "products": [
            "CSAFPID-0037",
            "CSAFPID-0038",
            "CSAFPID-0039",
            "CSAFPID-0040",
            "CSAFPID-0041",
            "CSAFPID-0048",
            "CSAFPID-0049",
            "CSAFPID-0051"
          ]
        }
      ],
      "title": "Unauthenticated Access To Device Configuration"
    },
    {
      "cve": "CVE-2022-50976",
      "cwe": {
        "id": "CWE-1288",
        "name": "Improper Validation of Consistency within Input"
      },
      "notes": [
        {
          "category": "summary",
          "text": "Resetting the device passwords using an invalid reset file causes a full device reset if the device is connected via USB.",
          "title": "Vulnerability summary"
        }
      ],
      "product_status": {
        "fixed": [
          "CSAFPID-0016",
          "CSAFPID-0031"
        ],
        "known_affected": [
          "CSAFPID-0014",
          "CSAFPID-0030"
        ],
        "known_not_affected": [
          "CSAFPID-0114"
        ]
      },
      "remediations": [
        {
          "category": "vendor_fix",
          "details": "Update VibroLine Configurator to version 5.1.2730 or later which includes a fix for this vulnerability.",
          "product_ids": [
            "CSAFPID-0014"
          ],
          "url": "https://www.innomic.com/downloads/"
        },
        {
          "category": "vendor_fix",
          "details": "Update AvibiaLine Configurator to version 5.1.2730 or later which includes a fix for this vulnerability.",
          "product_ids": [
            "CSAFPID-0030"
          ],
          "url": "https://www.avibia.de/info-center/download/"
        }
      ],
      "scores": [
        {
          "cvss_v3": {
            "attackComplexity": "LOW",
            "attackVector": "LOCAL",
            "availabilityImpact": "HIGH",
            "baseScore": 7.7,
            "baseSeverity": "HIGH",
            "confidentialityImpact": "NONE",
            "environmentalScore": 7.1,
            "environmentalSeverity": "HIGH",
            "exploitCodeMaturity": "FUNCTIONAL",
            "integrityImpact": "HIGH",
            "privilegesRequired": "NONE",
            "remediationLevel": "OFFICIAL_FIX",
            "reportConfidence": "CONFIRMED",
            "scope": "UNCHANGED",
            "temporalScore": 7.1,
            "temporalSeverity": "HIGH",
            "userInteraction": "NONE",
            "vectorString": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H/E:F/RL:O/RC:C",
            "version": "3.1"
          },
          "products": [
            "CSAFPID-0014",
            "CSAFPID-0030"
          ]
        }
      ],
      "title": "Unintended Device Reset"
    },
    {
      "cve": "CVE-2022-50977",
      "cwe": {
        "id": "CWE-306",
        "name": "Missing Authentication for Critical Function"
      },
      "notes": [
        {
          "category": "summary",
          "text": "The function to switch between multiple configuration presets via HTTP does not require authentication. An attacker with access to the network could use this functionality to disrupt normal operations if there is more than one configuration preset.",
          "title": "Vulnerability summary"
        }
      ],
      "product_status": {
        "known_affected": [
          "CSAFPID-0037",
          "CSAFPID-0038",
          "CSAFPID-0039",
          "CSAFPID-0040",
          "CSAFPID-0041",
          "CSAFPID-0048",
          "CSAFPID-0049",
          "CSAFPID-0051",
          "CSAFPID-0057",
          "CSAFPID-0058",
          "CSAFPID-0059",
          "CSAFPID-0060",
          "CSAFPID-0061",
          "CSAFPID-0068",
          "CSAFPID-0069",
          "CSAFPID-0071"
        ],
        "known_not_affected": [
          "CSAFPID-0032",
          "CSAFPID-0033",
          "CSAFPID-0034",
          "CSAFPID-0035",
          "CSAFPID-0036",
          "CSAFPID-0043",
          "CSAFPID-0044",
          "CSAFPID-0046",
          "CSAFPID-0052",
          "CSAFPID-0053",
          "CSAFPID-0054",
          "CSAFPID-0055",
          "CSAFPID-0056",
          "CSAFPID-0063",
          "CSAFPID-0064",
          "CSAFPID-0066",
          "CSAFPID-0132",
          "CSAFPID-0133",
          "CSAFPID-0134",
          "CSAFPID-0135",
          "CSAFPID-0136",
          "CSAFPID-0137",
          "CSAFPID-0138",
          "CSAFPID-0139",
          "CSAFPID-0140",
          "CSAFPID-0141"
        ]
      },
      "remediations": [
        {
          "category": "no_fix_planned",
          "details": "Isolate the network from the public internet and limit access to trustworthy devices (see section \"Network Security\" in the manual).\n\nIf only one configuration preset is required remove any other presets.",
          "product_ids": [
            "CSAFPID-0037",
            "CSAFPID-0038",
            "CSAFPID-0039",
            "CSAFPID-0040",
            "CSAFPID-0041",
            "CSAFPID-0048",
            "CSAFPID-0049",
            "CSAFPID-0051",
            "CSAFPID-0057",
            "CSAFPID-0058",
            "CSAFPID-0059",
            "CSAFPID-0060",
            "CSAFPID-0061",
            "CSAFPID-0068",
            "CSAFPID-0069",
            "CSAFPID-0071"
          ]
        }
      ],
      "scores": [
        {
          "cvss_v3": {
            "attackComplexity": "LOW",
            "attackVector": "NETWORK",
            "availabilityImpact": "HIGH",
            "baseScore": 7.5,
            "baseSeverity": "HIGH",
            "confidentialityImpact": "NONE",
            "environmentalScore": 7.1,
            "environmentalSeverity": "HIGH",
            "exploitCodeMaturity": "PROOF_OF_CONCEPT",
            "integrityImpact": "NONE",
            "privilegesRequired": "NONE",
            "remediationLevel": "UNAVAILABLE",
            "reportConfidence": "CONFIRMED",
            "scope": "UNCHANGED",
            "temporalScore": 7.1,
            "temporalSeverity": "HIGH",
            "userInteraction": "NONE",
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/E:P/RL:U/RC:C",
            "version": "3.1"
          },
          "products": [
            "CSAFPID-0037",
            "CSAFPID-0038",
            "CSAFPID-0039",
            "CSAFPID-0040",
            "CSAFPID-0041",
            "CSAFPID-0048",
            "CSAFPID-0049",
            "CSAFPID-0051",
            "CSAFPID-0057",
            "CSAFPID-0058",
            "CSAFPID-0059",
            "CSAFPID-0060",
            "CSAFPID-0061",
            "CSAFPID-0068",
            "CSAFPID-0069",
            "CSAFPID-0071"
          ]
        }
      ],
      "title": "Unauthenticated Configuration Switch Via HTTP"
    },
    {
      "cve": "CVE-2022-50978",
      "cwe": {
        "id": "CWE-306",
        "name": "Missing Authentication for Critical Function"
      },
      "notes": [
        {
          "category": "summary",
          "text": "The function to switch between multiple configuration presets via Modbus (TCP) does not require authentication. An attacker with access to the network could use this functionality to disrupt normal operations if there is more than one configuration preset.",
          "title": "Vulnerability summary"
        }
      ],
      "product_status": {
        "known_affected": [
          "CSAFPID-0037",
          "CSAFPID-0038",
          "CSAFPID-0039",
          "CSAFPID-0040",
          "CSAFPID-0041",
          "CSAFPID-0048",
          "CSAFPID-0049",
          "CSAFPID-0051",
          "CSAFPID-0057",
          "CSAFPID-0058",
          "CSAFPID-0059",
          "CSAFPID-0060",
          "CSAFPID-0061",
          "CSAFPID-0068",
          "CSAFPID-0069",
          "CSAFPID-0071"
        ],
        "known_not_affected": [
          "CSAFPID-0032",
          "CSAFPID-0033",
          "CSAFPID-0034",
          "CSAFPID-0035",
          "CSAFPID-0036",
          "CSAFPID-0043",
          "CSAFPID-0044",
          "CSAFPID-0046",
          "CSAFPID-0052",
          "CSAFPID-0053",
          "CSAFPID-0054",
          "CSAFPID-0055",
          "CSAFPID-0056",
          "CSAFPID-0063",
          "CSAFPID-0064",
          "CSAFPID-0066",
          "CSAFPID-0132",
          "CSAFPID-0133",
          "CSAFPID-0134",
          "CSAFPID-0135",
          "CSAFPID-0136",
          "CSAFPID-0137",
          "CSAFPID-0138",
          "CSAFPID-0139",
          "CSAFPID-0140",
          "CSAFPID-0141"
        ]
      },
      "remediations": [
        {
          "category": "no_fix_planned",
          "details": "Isolate the network from the public internet and limit access to trustworthy devices (see section \"Network Security\" in the manual).\n\nIf only one configuration preset is required remove any other presets.",
          "product_ids": [
            "CSAFPID-0037",
            "CSAFPID-0038",
            "CSAFPID-0039",
            "CSAFPID-0040",
            "CSAFPID-0041",
            "CSAFPID-0048",
            "CSAFPID-0049",
            "CSAFPID-0051",
            "CSAFPID-0057",
            "CSAFPID-0058",
            "CSAFPID-0059",
            "CSAFPID-0060",
            "CSAFPID-0061",
            "CSAFPID-0068",
            "CSAFPID-0069",
            "CSAFPID-0071"
          ]
        }
      ],
      "scores": [
        {
          "cvss_v3": {
            "attackComplexity": "LOW",
            "attackVector": "NETWORK",
            "availabilityImpact": "HIGH",
            "baseScore": 7.5,
            "baseSeverity": "HIGH",
            "confidentialityImpact": "NONE",
            "environmentalScore": 7.1,
            "environmentalSeverity": "HIGH",
            "exploitCodeMaturity": "PROOF_OF_CONCEPT",
            "integrityImpact": "NONE",
            "privilegesRequired": "NONE",
            "remediationLevel": "UNAVAILABLE",
            "reportConfidence": "CONFIRMED",
            "scope": "UNCHANGED",
            "temporalScore": 7.1,
            "temporalSeverity": "HIGH",
            "userInteraction": "NONE",
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/E:P/RL:U/RC:C",
            "version": "3.1"
          },
          "products": [
            "CSAFPID-0037",
            "CSAFPID-0038",
            "CSAFPID-0039",
            "CSAFPID-0040",
            "CSAFPID-0041",
            "CSAFPID-0048",
            "CSAFPID-0049",
            "CSAFPID-0051",
            "CSAFPID-0057",
            "CSAFPID-0058",
            "CSAFPID-0059",
            "CSAFPID-0060",
            "CSAFPID-0061",
            "CSAFPID-0068",
            "CSAFPID-0069",
            "CSAFPID-0071"
          ]
        }
      ],
      "title": "Unauthenticated Configuration Switch Via Modbus (TCP)"
    },
    {
      "cve": "CVE-2022-50979",
      "cwe": {
        "id": "CWE-306",
        "name": "Missing Authentication for Critical Function"
      },
      "notes": [
        {
          "category": "summary",
          "text": "The function to switch between multiple configuration presets via Modbus (RS485) does not require authentication. An attacker with access to the RS485 bus could use this functionality to disrupt normal operations if there is more than one configuration preset.",
          "title": "Vulnerability summary"
        }
      ],
      "product_status": {
        "known_affected": [
          "CSAFPID-0037",
          "CSAFPID-0038",
          "CSAFPID-0039",
          "CSAFPID-0040",
          "CSAFPID-0041",
          "CSAFPID-0048",
          "CSAFPID-0049",
          "CSAFPID-0051",
          "CSAFPID-0057",
          "CSAFPID-0058",
          "CSAFPID-0059",
          "CSAFPID-0060",
          "CSAFPID-0061",
          "CSAFPID-0068",
          "CSAFPID-0069",
          "CSAFPID-0071"
        ],
        "known_not_affected": [
          "CSAFPID-0032",
          "CSAFPID-0033",
          "CSAFPID-0034",
          "CSAFPID-0035",
          "CSAFPID-0036",
          "CSAFPID-0043",
          "CSAFPID-0044",
          "CSAFPID-0046",
          "CSAFPID-0052",
          "CSAFPID-0053",
          "CSAFPID-0054",
          "CSAFPID-0055",
          "CSAFPID-0056",
          "CSAFPID-0063",
          "CSAFPID-0064",
          "CSAFPID-0066",
          "CSAFPID-0132",
          "CSAFPID-0133",
          "CSAFPID-0134",
          "CSAFPID-0135",
          "CSAFPID-0136",
          "CSAFPID-0137",
          "CSAFPID-0138",
          "CSAFPID-0139",
          "CSAFPID-0140",
          "CSAFPID-0141"
        ]
      },
      "remediations": [
        {
          "category": "no_fix_planned",
          "details": "Limit access to the RS485 bus to trustworthy devices.\n\nIf only one configuration preset is required remove any other presets.",
          "product_ids": [
            "CSAFPID-0037",
            "CSAFPID-0038",
            "CSAFPID-0039",
            "CSAFPID-0040",
            "CSAFPID-0041",
            "CSAFPID-0048",
            "CSAFPID-0049",
            "CSAFPID-0051",
            "CSAFPID-0057",
            "CSAFPID-0058",
            "CSAFPID-0059",
            "CSAFPID-0060",
            "CSAFPID-0061",
            "CSAFPID-0068",
            "CSAFPID-0069",
            "CSAFPID-0071"
          ]
        }
      ],
      "scores": [
        {
          "cvss_v3": {
            "attackComplexity": "LOW",
            "attackVector": "ADJACENT_NETWORK",
            "availabilityImpact": "HIGH",
            "baseScore": 6.5,
            "baseSeverity": "MEDIUM",
            "confidentialityImpact": "NONE",
            "environmentalScore": 6.2,
            "environmentalSeverity": "MEDIUM",
            "exploitCodeMaturity": "PROOF_OF_CONCEPT",
            "integrityImpact": "NONE",
            "privilegesRequired": "NONE",
            "remediationLevel": "UNAVAILABLE",
            "reportConfidence": "CONFIRMED",
            "scope": "UNCHANGED",
            "temporalScore": 6.2,
            "temporalSeverity": "MEDIUM",
            "userInteraction": "NONE",
            "vectorString": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/E:P/RL:U/RC:C",
            "version": "3.1"
          },
          "products": [
            "CSAFPID-0037",
            "CSAFPID-0038",
            "CSAFPID-0039",
            "CSAFPID-0040",
            "CSAFPID-0041",
            "CSAFPID-0048",
            "CSAFPID-0049",
            "CSAFPID-0051",
            "CSAFPID-0057",
            "CSAFPID-0058",
            "CSAFPID-0059",
            "CSAFPID-0060",
            "CSAFPID-0061",
            "CSAFPID-0068",
            "CSAFPID-0069",
            "CSAFPID-0071"
          ]
        }
      ],
      "title": "Unauthenticated Configuration Switch Via Modbus (RS485)"
    },
    {
      "cve": "CVE-2022-50980",
      "cwe": {
        "id": "CWE-306",
        "name": "Missing Authentication for Critical Function"
      },
      "notes": [
        {
          "category": "summary",
          "text": "The function to switch between multiple configuration presets via CAN does not require authentication. An attacker with access to the RS485 bus could use this functionality to disrupt normal operations if there is more than one configuration preset.",
          "title": "Vulnerability summary"
        }
      ],
      "product_status": {
        "known_affected": [
          "CSAFPID-0037",
          "CSAFPID-0038",
          "CSAFPID-0039",
          "CSAFPID-0040",
          "CSAFPID-0041",
          "CSAFPID-0048",
          "CSAFPID-0049",
          "CSAFPID-0051",
          "CSAFPID-0057",
          "CSAFPID-0058",
          "CSAFPID-0059",
          "CSAFPID-0060",
          "CSAFPID-0061",
          "CSAFPID-0068",
          "CSAFPID-0069",
          "CSAFPID-0071"
        ],
        "known_not_affected": [
          "CSAFPID-0032",
          "CSAFPID-0033",
          "CSAFPID-0034",
          "CSAFPID-0035",
          "CSAFPID-0036",
          "CSAFPID-0043",
          "CSAFPID-0044",
          "CSAFPID-0046",
          "CSAFPID-0052",
          "CSAFPID-0053",
          "CSAFPID-0054",
          "CSAFPID-0055",
          "CSAFPID-0056",
          "CSAFPID-0063",
          "CSAFPID-0064",
          "CSAFPID-0066",
          "CSAFPID-0132",
          "CSAFPID-0133",
          "CSAFPID-0134",
          "CSAFPID-0135",
          "CSAFPID-0136",
          "CSAFPID-0137",
          "CSAFPID-0138",
          "CSAFPID-0139",
          "CSAFPID-0140",
          "CSAFPID-0141"
        ]
      },
      "remediations": [
        {
          "category": "no_fix_planned",
          "details": "Limit access to the CAN bus to trustworthy devices.\n\nIf only one configuration preset is required remove any other presets.",
          "product_ids": [
            "CSAFPID-0037",
            "CSAFPID-0038",
            "CSAFPID-0039",
            "CSAFPID-0040",
            "CSAFPID-0041",
            "CSAFPID-0048",
            "CSAFPID-0049",
            "CSAFPID-0051",
            "CSAFPID-0057",
            "CSAFPID-0058",
            "CSAFPID-0059",
            "CSAFPID-0060",
            "CSAFPID-0061",
            "CSAFPID-0068",
            "CSAFPID-0069",
            "CSAFPID-0071"
          ]
        }
      ],
      "scores": [
        {
          "cvss_v3": {
            "attackComplexity": "LOW",
            "attackVector": "ADJACENT_NETWORK",
            "availabilityImpact": "HIGH",
            "baseScore": 6.5,
            "baseSeverity": "MEDIUM",
            "confidentialityImpact": "NONE",
            "environmentalScore": 6.2,
            "environmentalSeverity": "MEDIUM",
            "exploitCodeMaturity": "PROOF_OF_CONCEPT",
            "integrityImpact": "NONE",
            "privilegesRequired": "NONE",
            "remediationLevel": "UNAVAILABLE",
            "reportConfidence": "CONFIRMED",
            "scope": "UNCHANGED",
            "temporalScore": 6.2,
            "temporalSeverity": "MEDIUM",
            "userInteraction": "NONE",
            "vectorString": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/E:P/RL:U/RC:C",
            "version": "3.1"
          },
          "products": [
            "CSAFPID-0037",
            "CSAFPID-0038",
            "CSAFPID-0039",
            "CSAFPID-0040",
            "CSAFPID-0041",
            "CSAFPID-0048",
            "CSAFPID-0049",
            "CSAFPID-0051",
            "CSAFPID-0057",
            "CSAFPID-0058",
            "CSAFPID-0059",
            "CSAFPID-0060",
            "CSAFPID-0061",
            "CSAFPID-0068",
            "CSAFPID-0069",
            "CSAFPID-0071"
          ]
        }
      ],
      "title": "Unauthenticated Configuration Switch Via CAN"
    },
    {
      "cve": "CVE-2022-50981",
      "cwe": {
        "id": "CWE-521",
        "name": "Weak Password Requirements"
      },
      "notes": [
        {
          "category": "summary",
          "text": "Devices are shipped without a password by default and setting a password is not enforced.",
          "title": "Vulnerability summary"
        }
      ],
      "product_status": {
        "known_affected": [
          "CSAFPID-0032",
          "CSAFPID-0033",
          "CSAFPID-0034",
          "CSAFPID-0035",
          "CSAFPID-0036",
          "CSAFPID-0037",
          "CSAFPID-0038",
          "CSAFPID-0039",
          "CSAFPID-0040",
          "CSAFPID-0041",
          "CSAFPID-0043",
          "CSAFPID-0044",
          "CSAFPID-0046",
          "CSAFPID-0048",
          "CSAFPID-0049",
          "CSAFPID-0051",
          "CSAFPID-0052",
          "CSAFPID-0053",
          "CSAFPID-0054",
          "CSAFPID-0055",
          "CSAFPID-0056",
          "CSAFPID-0057",
          "CSAFPID-0058",
          "CSAFPID-0059",
          "CSAFPID-0060",
          "CSAFPID-0061",
          "CSAFPID-0063",
          "CSAFPID-0064",
          "CSAFPID-0066",
          "CSAFPID-0068",
          "CSAFPID-0069",
          "CSAFPID-0071",
          "CSAFPID-0132",
          "CSAFPID-0133",
          "CSAFPID-0134",
          "CSAFPID-0135",
          "CSAFPID-0136",
          "CSAFPID-0137",
          "CSAFPID-0138",
          "CSAFPID-0139",
          "CSAFPID-0140",
          "CSAFPID-0141"
        ]
      },
      "remediations": [
        {
          "category": "no_fix_planned",
          "details": "Assign a password to the device on first use.",
          "product_ids": [
            "CSAFPID-0032",
            "CSAFPID-0033",
            "CSAFPID-0034",
            "CSAFPID-0035",
            "CSAFPID-0036",
            "CSAFPID-0037",
            "CSAFPID-0038",
            "CSAFPID-0039",
            "CSAFPID-0040",
            "CSAFPID-0041",
            "CSAFPID-0043",
            "CSAFPID-0044",
            "CSAFPID-0046",
            "CSAFPID-0048",
            "CSAFPID-0049",
            "CSAFPID-0051",
            "CSAFPID-0052",
            "CSAFPID-0053",
            "CSAFPID-0054",
            "CSAFPID-0055",
            "CSAFPID-0056",
            "CSAFPID-0057",
            "CSAFPID-0058",
            "CSAFPID-0059",
            "CSAFPID-0060",
            "CSAFPID-0061",
            "CSAFPID-0063",
            "CSAFPID-0064",
            "CSAFPID-0066",
            "CSAFPID-0068",
            "CSAFPID-0069",
            "CSAFPID-0071",
            "CSAFPID-0132",
            "CSAFPID-0133",
            "CSAFPID-0134",
            "CSAFPID-0135",
            "CSAFPID-0136",
            "CSAFPID-0137",
            "CSAFPID-0138",
            "CSAFPID-0139",
            "CSAFPID-0140",
            "CSAFPID-0141"
          ]
        }
      ],
      "scores": [
        {
          "cvss_v3": {
            "attackComplexity": "LOW",
            "attackVector": "NETWORK",
            "availabilityImpact": "HIGH",
            "baseScore": 9.8,
            "baseSeverity": "CRITICAL",
            "confidentialityImpact": "HIGH",
            "environmentalScore": 9,
            "environmentalSeverity": "CRITICAL",
            "exploitCodeMaturity": "PROOF_OF_CONCEPT",
            "integrityImpact": "HIGH",
            "privilegesRequired": "NONE",
            "remediationLevel": "WORKAROUND",
            "reportConfidence": "CONFIRMED",
            "scope": "UNCHANGED",
            "temporalScore": 9,
            "temporalSeverity": "CRITICAL",
            "userInteraction": "NONE",
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:W/RC:C",
            "version": "3.1"
          },
          "products": [
            "CSAFPID-0032",
            "CSAFPID-0033",
            "CSAFPID-0034",
            "CSAFPID-0035",
            "CSAFPID-0036",
            "CSAFPID-0037",
            "CSAFPID-0038",
            "CSAFPID-0039",
            "CSAFPID-0040",
            "CSAFPID-0041",
            "CSAFPID-0043",
            "CSAFPID-0044",
            "CSAFPID-0046",
            "CSAFPID-0048",
            "CSAFPID-0049",
            "CSAFPID-0051",
            "CSAFPID-0052",
            "CSAFPID-0053",
            "CSAFPID-0054",
            "CSAFPID-0055",
            "CSAFPID-0056",
            "CSAFPID-0057",
            "CSAFPID-0058",
            "CSAFPID-0059",
            "CSAFPID-0060",
            "CSAFPID-0061",
            "CSAFPID-0063",
            "CSAFPID-0064",
            "CSAFPID-0066",
            "CSAFPID-0068",
            "CSAFPID-0069",
            "CSAFPID-0071",
            "CSAFPID-0132",
            "CSAFPID-0133",
            "CSAFPID-0134",
            "CSAFPID-0135",
            "CSAFPID-0136",
            "CSAFPID-0137",
            "CSAFPID-0138",
            "CSAFPID-0139",
            "CSAFPID-0140",
            "CSAFPID-0141"
          ]
        }
      ],
      "title": "No Password By Default"
    }
  ]
}
```