# Literal - HackMyVM (Easy)

![Literal.png](Literal.png)

## Übersicht

*   **VM:** Literal
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Literal)
*   **Schwierigkeit:** Easy
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 2023-04-20
*   **Original-Writeup:** https://alientec1908.github.io/Literal_HackMyVM_Easy/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel dieser Challenge war es, Root-Rechte auf der Maschine "Literal" zu erlangen. Der Weg dorthin begann mit der Identifizierung zweier Webanwendungen auf verschiedenen virtuellen Hosts (`blog.literal.hmv` und `forumtesting.literal.hmv`). Beide Anwendungen waren anfällig für SQL-Injection, was das Auslesen von Benutzerdaten und Passwort-Hashes ermöglichte. Ein SHA512-Hash für den Benutzer `carlos` konnte geknackt werden. Mit dem (leicht modifizierten) Passwort wurde SSH-Zugriff als `carlos` erlangt. Die finale Rechteausweitung zu Root gelang durch die Ausnutzung einer unsicheren `sudo`-Regel, die es `carlos` erlaubte, ein Python-Skript mit beliebigen Argumenten als `root` ohne Passwort auszuführen.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `nikto`
*   `gobuster`
*   Web Browser
*   `wfuzz`
*   `sqlmap`
*   `ssh-keyscan`
*   `ssh-keygen`
*   Crackstation (Website)
*   `john`
*   `echo`
*   `vi` / Editor
*   `hydra` (versucht)
*   `awk`
*   `cut`
*   `ssh`
*   `sudo`
*   Standard Linux-Befehle (`whoami`, `bash`, `id`, `pwd`, `ls`, `cat`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Literal" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Web Enumeration:**
    *   IP-Adresse des Ziels (192.168.2.132) mit `arp-scan` identifiziert.
    *   `nmap`-Scan offenbarte SSH (Port 22) und HTTP (Port 80, Apache 2.4.41). Der HTTP-Titel zeigte einen Redirect auf `http://blog.literal.hmv`.
    *   Der Hostname `blog.literal.hmv` wurde in `/etc/hosts` eingetragen.
    *   `nikto` und `gobuster` auf `http://blog.literal.hmv/` fanden u.a. `/register.php`, `/login.php`, `/config.php` (leer) und `/next_projects_to_do.php`.

2.  **Vulnerability Analysis (SQL Injection):**
    *   `sqlmap` wurde auf `http://blog.literal.hmv/next_projects_to_do.php` (mit POST-Daten und Session-Cookie nach Registrierung/Login als Testbenutzer `ben`) angesetzt.
    *   Eine UNION-basierte SQL-Injection wurde im POST-Parameter `sentence-query` gefunden.
    *   Die Datenbank `blog` und die Tabelle `users` wurden gedumpt, was Benutzernamen und bcrypt-Passwort-Hashes (`$2y$10$...`) enthüllte.
    *   In den gedumpten E-Mail-Adressen wurde der Hostname `forumtesting.literal.hmv` entdeckt. Dieser wurde ebenfalls in `/etc/hosts` eingetragen.
    *   Manuelle Untersuchung von `http://forumtesting.literal.hmv/` führte zur Seite `/category.php?category_id=2`.
    *   `sqlmap` auf `http://forumtesting.literal.hmv/category.php?category_id=2` identifizierte eine SQL-Injection im GET-Parameter `category_id`.
    *   Die Datenbank `forumtesting` und die Tabelle `forum_owner` wurden gedumpt. Dies lieferte den Benutzer `carlos` und einen langen SHA512-Passwort-Hash (`6705...`).

3.  **Credential Cracking & Initial Access (SSH als `carlos`):**
    *   Der SHA512-Hash für `carlos` wurde mit Crackstation und `john` (`--format=Raw-SHA512`) geknackt. Das Passwort war `forum100889`.
    *   Die bcrypt-Hashes aus der `blog.users`-Tabelle wurden ebenfalls mit `john` geknackt und lieferten mehrere Passwörter, die aber für den direkten Zugriff nicht primär genutzt wurden.
    *   Der SSH-Login als `carlos` gelang mit dem leicht modifizierten/erratenen Passwort `ssh100889`.

4.  **Privilege Escalation (von `carlos` zu `root` via Sudo Exploit):**
    *   Als `carlos` wurde `sudo -l` ausgeführt.
    *   Die Regel `(root) NOPASSWD: /opt/my_things/blog/update_project_status.py *` wurde gefunden. Sie erlaubt `carlos`, das Python-Skript mit beliebigen Argumenten (`*`) als `root` ohne Passwort auszuführen.
    *   Durch Ausführen von `sudo /opt/my_things/blog/update_project_status.py '\!$ bash -p'` konnte eine Bash-Shell mit Root-Rechten (`euid=0(root)`) gestartet werden. Das `\!$` wird von `sudo` als auszuführender Befehl interpretiert, wenn die Regel mit `*` endet.
    *   Die User-Flag (`6d3c8a6c73cf4f89eea7ae57f6eb9222`) wurde in `/home/carlos/user.txt` gefunden.
    *   Die Root-Flag (`ca43cb966ef76475d9e0736feeb9f730`) wurde in `/root/root.txt` gefunden.

## Wichtige Schwachstellen und Konzepte

*   **SQL Injection (UNION-based & Blind):** Mehrere Webanwendungen auf verschiedenen virtuellen Hosts waren anfällig für SQL-Injection, was das Auslesen von Datenbankinhalten (Benutzernamen, Passwort-Hashes) ermöglichte.
*   **Schwache Passwort-Hashing-Algorithmen:** Verwendung von SHA512 (ohne Salt, oder Salt nicht im Hash enthalten) ermöglichte das Knacken mit Wörterbuchangriffen. Bcrypt-Hashes konnten ebenfalls geknackt werden, was auf schwache Passwörter hindeutet.
*   **Passwort-Wiederverwendung / Erratbarkeit:** Das für SSH verwendete Passwort (`ssh100889`) war eine leichte Variation des geknackten `forum100889`.
*   **Unsichere `sudo`-Regel:** Eine `sudo`-Regel erlaubte einem Benutzer, ein Skript mit beliebigen Argumenten (`*`) als `root` ohne Passwort auszuführen. Dies ist eine klassische Fehlkonfiguration, die oft zu direkter Root-Eskalation führt.
*   **Virtuelle Host Enumeration:** Entdeckung zusätzlicher Angriffsflächen durch Identifizierung von virtuellen Hosts aus Datenbankeinträgen.

## Flags

*   **User Flag (`/home/carlos/user.txt`):** `6d3c8a6c73cf4f89eea7ae57f6eb9222`
*   **Root Flag (`/root/root.txt`):** `ca43cb966ef76475d9e0736feeb9f730`

## Tags

`HackMyVM`, `Literal`, `Easy`, `SQL Injection`, `Password Cracking`, `SHA512`, `bcrypt`, `SSH`, `sudo Exploit`, `Virtual Host Enumeration`, `Linux`, `Web`, `Privilege Escalation`
