## Table des matières

1. [Introduction et contexte CERT-EU](./01-introduction.md)
2. [Typologie : Advisory / Vulnerability Note / Threat Intelligence](./02-typology.md)
3. [Structure des données et Parsing](./03-data-structure-parsing.md)
4. [Accès aux données (Portail & Flux)](./04-data-access.md)
5. [Cycle de vie et Mises à jour](./05-lifecycle.md)

---

# 1. Introduction

## Contexte

La gestion des vulnérabilités repose sur la capacité à identifier, qualifier et prioriser rapidement les failles affectant les actifs d’un système d’information.

Le **CERT-EU** (Computer Emergency Response Team for the EU Institutions) publie des contenus de veille et d’alerte visant à soutenir les institutions, organes et agences de l’Union européenne dans la prévention et la réponse aux incidents de cybersécurité.

Les publications CERT-EU (Advisories, Vulnerability Notes, Security Warnings/Alerts, analyses de menace) permettent notamment de :

* signaler des **vulnérabilités critiques** affectant des produits et services largement utilisés au sein des environnements IT,
* partager des informations sur des **campagnes actives** (exploitation de vulnérabilités, intrusions, ransomware, supply chain),
* fournir des **mesures de mitigation** et des recommandations de détection/remédiation.

Ces contenus constituent une source opérationnelle complémentaire aux bases exhaustives (ex. **NVD**) : ils fournissent du **contexte sectoriel (institutions UE)**, une **mise en perspective de la menace**, et parfois des éléments actionnables (vecteurs d’attaque, IoC, TTP) permettant de renforcer le triage SOC et la priorisation patch.

## Objectifs

* Comprendre le rôle et la typologie des publications du **CERT-EU** (Advisories, Vulnerability Notes, Threat Intelligence)
* Décrire la structure et la nature des données disponibles (pages web, PDF/HTML, métadonnées)
* Documenter l’accès et l’utilisation des canaux officiels (portail, flux RSS/Atom lorsqu’ils existent)
* Présenter les bonnes pratiques d’exploitation (priorisation patch, corrélation avec actifs, enrichissement CVE)
* Identifier les limites et points de vigilance (couverture, disponibilité machine-readable, mises à jour)

## Livrable

Documentation technique (Markdown), exploitable de manière autonome.
