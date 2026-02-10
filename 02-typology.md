## Table des matières

1. [Introduction et contexte CERT-Bund](./01-introduction.md)
2. [Typologie : Warnungen / Advisories / Lageberichte / Analyses](./02-typology.md)
3. [Structure des données et Parsing](./03-data-structure-parsing.md)
4. [Accès aux données (Portail, RSS, endpoints)](./04-data-access.md)
5. [Cycle de vie et Mises à jour](./05-lifecycle.md)

---

# 2. Présentation générale — CERT-Bund / BSI / Publications

## 2.1 CERT-Bund (BSI)

Le **CERT-Bund** est l’équipe de réponse aux incidents et de coordination cyber dédiée principalement aux **administrations fédérales allemandes** et à l’écosystème critique associé. Il est opéré par le **BSI (Bundesamt für Sicherheit in der Informationstechnik)**.

Dans ce cadre, CERT-Bund joue un rôle de :

* **coordination opérationnelle** lors d’incidents majeurs,
* **diffusion d’alertes** et d’avertissements de sécurité,
* **production d’analyses techniques** sur les menaces,
* relais entre autorités, CSIRTs, partenaires européens/internationaux.

Les publications CERT-Bund sont à considérer comme une source **qualifiée** et **orientée action**, distincte de bases exhaustives ou purement documentaires.

## 2.2 Identifiants et typologie CERT-Bund

Contrairement à une **CVE** qui identifie une vulnérabilité unique, une publication CERT-Bund correspond à un **document de synthèse** qui peut regrouper :

* plusieurs vulnérabilités (multiples CVE),
* une famille de produits ou un éditeur,
* un contexte de menace (exploitation active, campagne en cours),
* des recommandations défensives (patch, mitigation, détection).

Selon le format, CERT-Bund / BSI utilisent des identifiants propres (ex. alertes, bulletins, avis techniques), qui servent de pivot documentaire et facilitent le suivi dans le temps.

Le contenu fournit généralement :

* description du risque / impact opérationnel,
* **CVE associées** (si applicables),
* périmètre technique : produits / versions / conditions,
* recommandations de remédiation,
* parfois des éléments actionnables (IoC, TTP, règles de détection, logs à surveiller).

## 2.3 Typologie des publications

### 2.3.1 Cyber-Sicherheitswarnungen / Warnmeldungen (Avertissements)

Publications courtes et orientées urgence visant à notifier un risque immédiat.

Caractéristiques :

* liées à une exploitation active ou à une vulnérabilité critique
* destinées à déclencher un traitement prioritaire (SOC + patch)
* peuvent inclure des recommandations rapides (workarounds)

**Usages SOC/CTI :**

* déclenchement d’un triage « fast track »
* création d’alertes internes / watchlists
* enrichissement du backlog patch management

### 2.3.2 Sicherheitshinweise / Security Advisories (Avis de sécurité)

Documents plus structurés, souvent centrés sur un produit, une faille ou un ensemble de failles.

Contenu typique :

* contexte et impact
* versions affectées
* correctifs disponibles
* mesures compensatoires
* références éditeurs / CVE

**Usages SOC/CTI :**

* analyse de l’exposition (assets ↔ produits ↔ versions)
* enrichissement vuln management
* corrélation CVE (NVD, CISA KEV, EPSS)

### 2.3.3 Lageberichte / Lageinformationen (Rapports de situation)

Synthèses périodiques (ou ad hoc) sur l’état de la menace.

Contenu typique :

* tendances globales (malware, ransomware, APT)
* événements récents
* vecteurs et TTP observés
* recommandations de posture

**Usages SOC/CTI :**

* briefings RSSI / direction
* amélioration posture de détection
* planification et priorisation (mesures techniques)

### 2.3.4 Technische Analysen / Threat Intelligence Reports

Analyses détaillées orientées renseignement technique : campagnes, tooling, exploitation.

Contenu typique :

* description de campagne
* chaîne d’infection / kill chain
* IoC (IP, URL, hash, domaines)
* TTP et mapping MITRE ATT&CK
* recommandations de détection

**Usages SOC/CTI :**

* ingestion IoC vers SIEM/EDR
* création de règles (Sigma / KQL / Splunk)
* threat hunting ciblé

## 2.4 Rôle du CERT-Bund dans la chaîne de veille

Le **CERT-Bund** ne vise pas l’exhaustivité (rôle de la **NVD**), mais la **qualification**, la **priorisation** et la **diffusion rapide** d’informations exploitables.

### Mission principale

* Filtrer le signal : sujets à impact réel et urgent
* Contextualiser la menace : exploitation active, vecteurs
* Diffuser des recommandations actionnables (patch, mitigation, détection)
* Faciliter la coordination entre entités (inter-administration / partenaires)

### Données qualifiées disponibles

* typologie de publication : Warnungen / Advisories / Lageberichte / Analysen
* mapping CVE : liens vers identifiants internationaux
* produits/versions affectés : portée technique exploitable
* mesures défensives : patch + workarounds
* éléments de détection : IoC / TTP (selon publications)

> Phrase de synthèse : **NVD = Base exhaustive (dictionnaire) ; CERT-Bund = Veille qualifiée (urgence / coordination / action).**

## 2.5 Cas d’usage

* Veille quotidienne SOC / CSIRT
* Priorisation « fast-track » des correctifs (exploitation active)
* Enrichissement CTI : campagne ↔ vulnérabilités ↔ TTP
* Support coordination / communication interne
* Gouvernance : suivi des avertissements et recommandations de l’autorité
