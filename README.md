# 🚀 RecycleBinForensics - Analyseur Forensique de la Corbeille Windows


**Auteur** : Ayi NEDJIMI
**Licence** : MIT
**Plateforme** : Windows (Win32 GUI)

## 📋 Description

RecycleBinForensics est un outil forensique spécialisé dans l'analyse de la **Corbeille Windows** (`$Recycle.Bin`). Il parse les fichiers de métadonnées `$I` et les fichiers de contenu `$R` pour récupérer des informations critiques sur les fichiers supprimés : chemins originaux, timestamps de suppression, tailles, et permet la restauration forensique.


## Qu'est-ce que $Recycle.Bin ?

La Corbeille Windows (depuis Vista) fonctionne différemment de l'ancienne RECYCLER :

### Architecture
- **Emplacement** : `C:\$Recycle.Bin\{SID}\`
- **Séparation par utilisateur** : Chaque utilisateur a son propre SID
- **Double fichier** : Métadonnées ($I) + Contenu ($R)

### Structure des fichiers
```
C:\$Recycle.Bin\
└── S-1-5-21-123456789-987654321-111111111-1001\  <- SID utilisateur
    ├── $I6X2D8A.txt   <- Métadonnées (nom original, date, taille)
    └── $R6X2D8A.txt   <- Contenu réel du fichier
```

### Format du fichier $I (métadonnées)
```
Offset  Taille  Description
- -----  ------  -----------
0x00    8       Version (1 ou 2)
0x08    8       Taille originale du fichier (LONGLONG)
0x10    8       Timestamp de suppression (FILETIME)
0x18    Variable Chemin original (Unicode, null-terminated)
```


# 🚀 Exécuter en tant qu'administrateur

## ✨ Fonctionnalités principales

### Parsing de la corbeille
- **Scan automatique** : Énumération de tous les SID dans `C:\$Recycle.Bin\`
- **Parse fichiers $I** : Extraction des métadonnées
- **Vérification fichiers $R** : Contrôle de la restaurabilité
- **Multi-utilisateurs** : Support de multiples utilisateurs/SID

### Informations extraites
- **Nom original** : Nom du fichier avant suppression
- **Chemin original** : Emplacement complet d'origine
- **Taille** : Taille en octets du fichier original
- **Date de suppression** : Timestamp précis de la suppression
- **SID** : Identification de l'utilisateur ayant supprimé le fichier
- **Hash** : MD5/SHA-1 du contenu (calculable)
- **Restaurabilité** : Vérification si le fichier $R existe

### Restauration forensique
- **Extraction sélective** : Copie d'un fichier $R vers un emplacement choisi
- **Préservation** : Le fichier original reste dans la corbeille
- **Vérification** : Contrôle avant restauration

### Timeline de suppression
- **Tri chronologique** : Affichage par date de suppression
- **Reconstruction d'activité** : Vision de l'activité de suppression
- **Corrélation** : Croisement avec d'autres artefacts

### Hashing et identification
- **Calcul de hash** : MD5/SHA-1 des fichiers $R
- **Identification** : Comparaison avec des IOC connus
- **Vérification d'intégrité** : Détection de modifications


## Interface utilisateur

### Contrôles principaux
1. **Bouton "Scanner Corbeille"** : Lance l'analyse de `C:\$Recycle.Bin\`
2. **Bouton "Calculer Hash"** : Calcule le hash du fichier sélectionné
3. **Bouton "Restaurer Fichier"** : Copie le fichier $R vers un emplacement
4. **Bouton "Exporter"** : Sauvegarde en CSV
5. **Barre de progression** : Indicateur du scan
6. **ListView** : Résultats avec colonnes :
   - Nom Original (nom avant suppression)
   - Chemin Original (path complet)
   - Taille (en B/KB/MB/GB)
   - Date Suppression (timestamp)
   - SID (identifiant utilisateur)
   - Hash (MD5/SHA-1)
   - Restaurable (Oui/Non)
7. **Journal de log** : Messages et erreurs


## Compilation

### Prérequis
- Visual Studio 2019/2022 avec outils C++
- Windows SDK (10.0 ou supérieur)
- Support Unicode

### Compilation automatique
```batch
go.bat
```

### Compilation manuelle
```batch
cl.exe /nologo /W4 /EHsc /O2 /D_UNICODE /DUNICODE /FeRecycleBinForensics.exe RecycleBinForensics.cpp ^
    kernel32.lib user32.lib gdi32.lib comctl32.lib comdlg32.lib shlwapi.lib shell32.lib ole32.lib
```


## 🚀 Utilisation

### Lancement
**IMPORTANT** : L'outil doit être exécuté avec des privilèges administrateur pour accéder aux corbeilles de tous les utilisateurs.

```batch
RecycleBinForensics.exe
```

### Workflow basique
1. Lancez l'application en administrateur
2. Cliquez sur "Scanner Corbeille"
3. Consultez les fichiers supprimés trouvés
4. Sélectionnez un fichier et cliquez sur "Calculer Hash" si nécessaire
5. Cliquez sur "Restaurer Fichier" pour récupérer un fichier
6. Exportez les résultats en CSV

### Workflow forensique
```
1. Incident : Fichiers confidentiels supprimés le 2025-10-18
2. Lancer RecycleBinForensics en admin
3. Scanner la corbeille
4. Trier par date de suppression
5. Identifier les fichiers supprimés entre 14h00 et 15h00
6. Noter les SID (identifier l'utilisateur)
7. Calculer les hash des fichiers suspects
8. Restaurer les fichiers pour analyse
9. Exporter la timeline pour le rapport
10. Croiser avec :
    - Event Logs (4663 : Object Access)
    - USN Journal (FILE_DELETE)
    - Prefetch (CLEANMGR.EXE, CIPHER.EXE)
```


## Architecture technique

### Structure $Recycle.Bin

#### Hiérarchie
```
C:\$Recycle.Bin\
├── S-1-5-21-...-1001\  <- Utilisateur 1
│   ├── $I123ABC.docx
│   ├── $R123ABC.docx
│   ├── $I456DEF.pdf
│   └── $R456DEF.pdf
├── S-1-5-21-...-1002\  <- Utilisateur 2
│   ├── $I789GHI.exe
│   └── $R789GHI.exe
└── desktop.ini
```

#### Correspondance $I / $R
Le suffixe après `$I` et `$R` est identique pour un même fichier :
```
$I123ABC.txt <- Métadonnées
$R123ABC.txt <- Contenu
```

### Format du fichier $I (Windows Vista+)

#### Structure en mémoire
```cpp
#pragma pack(push, 1)
struct RecycleBinHeader {
    LONGLONG version;       // 1 ou 2 (généralement 2)
    LONGLONG fileSize;      // Taille originale en octets
    FILETIME deleteTime;    // Timestamp de suppression
    // Suivi par :
    // wchar_t originalPath[...];  // Chemin Unicode, null-terminated
};
#pragma pack(pop)
```

#### Exemple hexadécimal
```
Offset  Hex                               ASCII
- -----  --------------------------------  -----
0x00    02 00 00 00 00 00 00 00          Version = 2
0x08    00 40 00 00 00 00 00 00          Size = 16384 bytes
0x10    80 3B 5F E7 3A 9F DA 01          DeleteTime = FILETIME
0x18    43 00 3A 00 5C 00 55 00 ...     C:\Users\...
```

### Conversion FILETIME
```cpp
FILETIME -> SYSTEMTIME -> String
01DA9F3AE75F3B80 -> 2025-10-18 14:25:30
```

### Mapping SID vers Username
```cpp
// Méthode 1 : LookupAccountSid
ConvertStringSidToSid(L"S-1-5-21-...");
LookupAccountSid(...) -> "DOMAIN\\Username"

// Méthode 2 : Registre
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{SID}
- > ProfileImagePath -> C:\Users\Username
```


## 🚀 Cas d'usage forensiques

### 1. Investigation de suppression de données
```
Scénario : Fichiers confidentiels supprimés
Question : Qui a supprimé les fichiers et quand ?

Analyse :
- Scanner la corbeille
- Identifier : secret_projet.docx
  - Date suppression : 2025-10-18 14:30:00
  - SID : S-1-5-21-...-1003
  - Taille : 2.5 MB
- Résoudre SID : DOMAIN\JohnDoe
- Calculer hash : abc123def456...

Corrélation Event Logs :
- Event 4663 (Object Access) : JohnDoe a accédé au fichier à 14:29:50
- Event 4660 (Object Deleted) : Fichier supprimé à 14:30:00

Conclusion : JohnDoe a supprimé le fichier le 2025-10-18 à 14:30:00
```

### 2. Détection de sabotage
```
Scénario : Suppression massive de fichiers avant démission
Timeline corbeille :
14:00 - 50 fichiers .xlsx supprimés
14:15 - 30 fichiers .pdf supprimés
14:30 - 100 fichiers divers supprimés

Tous supprimés par SID : S-1-5-21-...-1005 (Employee X)

Actions :
1. Restaurer tous les fichiers
2. Calculer les hash pour vérification d'intégrité
3. Documenter dans le rapport RH
4. Notifier la direction
```

### 3. Récupération de preuves malware
```
Scénario : Malware supprimé par antivirus
Analyse corbeille :
- malware.exe (supprimé 2025-10-18 15:00:00)
- SID : S-1-5-18 (SYSTEM) <- Antivirus
- Taille : 512 KB

Actions :
1. Restaurer malware.exe
2. Calculer SHA-1 : abc123...
3. Rechercher IOC dans threat intel
4. Analyser dans sandbox
5. Remonter l'alerte SOC
```

### 4. Timeline d'attaque ransomware
```
Analyse post-incident :
14:20 - shadow_copy.vssadmin supprimé (SYSTEM)
14:25 - backup.zip supprimé (Utilisateur)
14:30 - 500+ fichiers .docx/.xlsx supprimés (Ransomware)

Pattern détecté :
- Suppression des sauvegardes
- Chiffrement puis suppression des originaux
- SID utilisateur compromis

Conclusion : Ransomware avec suppression de sauvegardes
```

### 5. Analyse anti-forensics
```
Détection de nettoyage :
- Corbeille vidée manuellement
- Tous fichiers $I/$R supprimés pour un SID
- Timestamp de suppression : 2025-10-18 16:00:00

Corrélation :
- Prefetch : CLEANMGR.EXE exécuté à 16:00:00
- Event Logs : Vider la corbeille (pas d'event spécifique)

Indication : Tentative d'effacement de traces
```


# 🚀 Lister les fichiers $I

# 🚀 Compter les fichiers par SID

# 🚀 Restaurer un fichier manuellement

## Valeur forensique de la Corbeille

### Avantages
- **Preuve de suppression** : Timestamp exact de la suppression
- **Attribution** : SID de l'utilisateur
- **Récupération possible** : Fichiers souvent récupérables
- **Chemins complets** : Emplacement original préservé
- **Peu modifié** : Moins ciblé par les attaquants que les logs

### Limitations
- **Vidage** : Les utilisateurs peuvent vider la corbeille
- **Pas permanent** : Fichiers supprimés définitivement (Shift+Delete) ne passent pas par la corbeille
- **Rotation** : Limite de taille (peut être configurée)
- **Pas de détail** : Pas d'informations sur QUI a fait la suppression (nécessite corrélation)

### Complémentarité avec autres artefacts
```
Corbeille    : Timestamp suppression + chemin original + SID
USN Journal  : FILE_DELETE avec FileReferenceNumber
Event Logs   : 4663 (Object Access) avant suppression
Prefetch     : Exécution de cleanmgr.exe / cipher.exe
MFT          : Entrées marquées comme supprimées

- > Investigation complète
```


## Limitations connues

### Limitations système
- **Privilèges** : Admin requis pour accéder aux SID d'autres utilisateurs
- **Fichiers gros** : La corbeille a une limite de taille (configurable)
- **Shift+Delete** : Les fichiers supprimés définitivement ne sont PAS dans la corbeille
- **Nettoyage automatique** : Peut être configuré pour vider automatiquement

### Limitations de l'outil
- **Hash non implémenté** : Calcul MD5/SHA-1 retourne "N/A" (placeholder)
- **Pas de résolution SID** : Le SID n'est pas converti en nom d'utilisateur
- **Un seul volume** : Scanne uniquement C:\$Recycle.Bin\
- **Pas de récupération avancée** : Pas de carving si fichier $R supprimé

### Limitations forensiques
- **Corbeille vidée** : Fichiers $I/$R supprimés = perte de métadonnées
- **Manipulation possible** : Un attaquant peut modifier les fichiers $I
- **Pas d'attribution directe** : Le SID indique le propriétaire, pas forcément l'auteur de la suppression
- **Timestamps modifiables** : Peuvent être altérés (rare)


# 🚀 Convertir SID en nom

# 🚀 SHA-1

# 🚀 MD5

## Améliorations futures

### Court terme
- **Implémentation hash** : MD5/SHA-1 réel avec CryptoAPI
- **Résolution SID** : Conversion automatique vers nom d'utilisateur
- **Multi-volumes** : Scan de D:\, E:\, etc.
- **Recherche/filtrage** : Par nom, date, SID

### Moyen terme
- **Récupération avancée** : Carving des fichiers $R supprimés
- **Timeline visuelle** : Graphique des suppressions
- **Détection de patterns** : Suppression massive, anti-forensics
- **Intégration IOC** : Comparaison hash avec threat intel

### Long terme
- **Corrélation automatique** : Lien avec USN Journal, Event Logs
- **Analyse comportementale** : Détection d'anomalies
- **Mode réseau** : Scan de corbeilles sur multiples machines
- **API REST** : Intégration SIEM


## Outils complémentaires

### Outils Windows natifs
```batch
REM Lister le contenu de la corbeille (PowerShell)
Get-ChildItem C:\$Recycle.Bin\ -Recurse -Force

REM Vider la corbeille (tous utilisateurs)
rd /s /q C:\$Recycle.Bin\

REM Voir la configuration de la corbeille
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\BitBucket"
```

### PowerShell
```powershell
Get-ChildItem C:\$Recycle.Bin\*\$I* -Recurse -Force

Get-ChildItem C:\$Recycle.Bin\ -Directory |
    ForEach-Object { [PSCustomObject]@{
        SID = $_.Name
        Count = (Get-ChildItem $_.FullName -Filter '$I*').Count
    }}

Copy-Item "C:\$Recycle.Bin\{SID}\$R123ABC.txt" -Destination "C:\Restored\file.txt"
```

### Outils forensiques
- **Rifiuti2** : Parseur en ligne de commande (Linux/Windows)
- **Autopsy** : Module Recycle Bin intégré
- **X-Ways Forensics** : Support complet de la corbeille
- **FTK** : Récupération et analyse


## Références techniques

### Documentation Microsoft
- [Recycle Bin Structure](https://docs.microsoft.com/en-us/windows/win32/shell/manage-the-recycle-bin)
- Pas de documentation officielle du format $I/$R (rétro-ingénierie communautaire)

### Recherches forensiques
- **SANS DFIR** : "Windows Recycle Bin Forensics"
- **Forensic Focus** : "$Recycle.Bin Analysis"
- **Digital Detective** : "Recycle Bin Structure Vista+"

### Spécifications communautaires
- Rifiuti2 source code : https://github.com/abelcheung/rifiuti2
- Forensics Wiki : Recycle Bin page


## Commandes forensiques utiles

### Extraction de métadonnées (hexdump)
```batch
REM Voir le contenu hexadécimal d'un fichier $I
certutil -encodehex "C:\$Recycle.Bin\{SID}\$I123ABC.txt" output.txt

REM Ou avec PowerShell
Format-Hex "C:\$Recycle.Bin\{SID}\$I123ABC.txt"
```

### Résolution de SID
```powershell
$SID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-21-...")
$User = $SID.Translate([System.Security.Principal.NTAccount])
Write-Host $User.Value
```

### Calcul de hash
```powershell
Get-FileHash "C:\$Recycle.Bin\{SID}\$R123ABC.exe" -Algorithm SHA1

certutil -hashfile "C:\$Recycle.Bin\{SID}\$R123ABC.exe" MD5
```


## Scénarios de récupération

### Récupération simple
```
1. Fichier supprimé accidentellement
2. Scanner la corbeille avec l'outil
3. Localiser le fichier par nom
4. Cliquer sur "Restaurer Fichier"
5. Choisir l'emplacement de restauration
6. Vérifier l'intégrité
```

### Récupération forensique
```
1. Incident de sécurité
2. Collecter C:\$Recycle.Bin\ complet (copie forensique)
3. Analyser sur station forensique
4. Parser tous les fichiers $I
5. Identifier les fichiers pertinents
6. Restaurer les fichiers $R
7. Calculer les hash
8. Comparer avec IOC
9. Documenter dans le rapport
10. Conserver les preuves
```


## Format d'export CSV

```csv
NomOriginal,CheminOriginal,Taille,DateSuppression,SID,Hash,Restaurable
"confidential.docx","C:\Users\John\Documents\confidential.docx",524288,"2025-10-18 14:30:00","S-1-5-21-...-1001","abc123def456...",Oui
"malware.exe","C:\Users\John\Downloads\malware.exe",245760,"2025-10-18 15:00:00","S-1-5-18","N/A",Non
```

**Encodage** : UTF-8 avec BOM
**Séparateur** : Virgule
**Format** : Standard CSV


## 🔧 Dépannage

### Erreur "Impossible d'accéder à C:\$Recycle.Bin"
**Cause** : Manque de privilèges administrateur
**Solution** : Exécutez en tant qu'administrateur

### Aucun fichier trouvé
**Cause** : Corbeille vide ou vidée récemment
**Solution** : Normal si aucune suppression récente

### Fichier non restaurable
**Cause** : Le fichier $R a été supprimé (corbeille vidée partiellement)
**Solution** : Utiliser des outils de récupération de fichiers (PhotoRec, etc.)

### Hash retourne "N/A"
**Cause** : Fonction de hashing non implémentée complètement
**Solution** : Utiliser certutil ou Get-FileHash en PowerShell


## 🔒 Sécurité et éthique

### Usage légal
- Utilisez uniquement sur des systèmes autorisés
- Respectez la vie privée des utilisateurs
- Documentez toute restauration
- Ne divulguez pas de fichiers confidentiels récupérés

### Protection des preuves
- Travaillez sur des copies forensiques
- Calculez les hash avant manipulation
- Documentez toute opération
- Conservez les logs

### Chain of custody
- Horodatez la collecte
- Documentez la source
- Signez les exports
- Conservez en lecture seule


## 📄 Licence MIT

```
Copyright (c) 2025 Ayi NEDJIMI

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

[Texte complet de la licence MIT]
```


## Support

### Ressources
- Documentation complète (ce README)
- Code source commenté
- Exemples de workflows

### Outils de la suite
- **NTFSJournalParser** : Timeline USN Journal
- **PrefetchAnalyzer** : Historique d'exécution
- **AmcacheForensics** : Analyse Amcache
- **AlternateDataStreamScanner** : ADS cachés

**Contact** : Ayi NEDJIMI

- --

**RecycleBinForensics** - Outil forensique professionnel pour l'analyse de la Corbeille Windows
Développé par **Ayi NEDJIMI** - 2025


- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

---

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>