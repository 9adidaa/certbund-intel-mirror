# Documentation technique — CERT-Bund (Warnungen, Security Advisories & Reports)

## Objectif

Cette documentation a pour objectif de fournir une référence technique sur les flux de veille du **CERT-Bund (Computer Emergency Response Team for the German Federal Government)**, opéré par le **BSI (Bundesamt für Sicherheit in der Informationstechnik)**.

Elle vise à permettre aux équipes techniques, CTI et SOC de comprendre, collecter et exploiter les publications CERT-Bund (warnungen, advisories, lageberichte, analyses) afin de :

* **contextualiser la menace**
* **prioriser la remédiation**
* enrichir les processus SOC (triage, détection, hunting)
* alimenter des workflows internes (dashboards, scoring, corrélation vulnérabilités)

## Audience

* Analystes CTI (Cyber Threat Intelligence)
* Ingénieurs sécurité / SOC (veille opérationnelle, triage, détection)
* Data Engineers / Data Analysts (ingestion RSS/Atom/API, scraping, parsing HTML/PDF, normalisation)
* Développeurs d’outils internes (corrélation vulnérabilités, scoring, dashboards)
* Responsables sécurité (RSSI) pour la priorisation et la communication interne

## Portée

* Compréhension de la **typologie CERT-Bund / BSI** :

  * *Cyber-Sicherheitswarnungen / Warnmeldungen*
  * *Sicherheitshinweise / Advisories*
  * *Lageberichte (situation reports)*
  * *Technische Analysen / Threat Intel Reports*
* Méthodes d’accès aux publications :

  * Portail web BSI / CERT-Bund
  * flux RSS disponibles
  * endpoints/JSON si accessibles
* Structure des données (HTML, PDF, metadata)
* Corrélation avec :

  * **CVE / NVD** (CVSS, CWE, references)
  * **CISA KEV**
  * **EPSS** (priorisation exploitation probable)
* Bonnes pratiques d’ingestion :

  * dédoublonnage
  * versioning
  * gestion des mises à jour / re-publications
* Exemples de normalisation vers un modèle interne :

  * IOC / TTP
  * CVE
  * vendors / produits / versions affectées
  * criticité (score interne)

## Table des matières

1. [Introduction et contexte CERT-Bund](./01-introduction.md)
2. [Typologie : Warnungen / Advisories / Lageberichte / Analyses](./02-typology.md)
3. [Structure des données et Parsing](./03-data-structure-parsing.md)
4. [Accès aux données (Portail, RSS, endpoints)](./04-data-access.md)
5. [Cycle de vie et Mises à jour](./05-lifecycle.md)

   ---

   <!-- STATUS:START -->
Last CI success: 2026-02-22 23:28 UTC

### Validation
| Check | Status |
|------|--------|
| Raw data present | ✅ |
| CVE index valid | ✅ |
| First-seen valid | ✅ |
| Tests executed | **11 passed** |

### Dataset size
- Advisories: **21225**
- Unique CVEs: **46702**

<!-- STATUS:END -->
