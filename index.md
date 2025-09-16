---
layout: default
title: "CTF Writeups"
---

# 🏴‍☠️ CTF Writeups

Welcome! This site hosts my CTF writeups and notes for the semester.  
I document step-by-step approaches, tools/commands, and lessons learned.

## 📂 Sections
- [TryHackMe]({{ site.baseurl }}/TryHackMe/)
- [HackTheBox]({{ site.baseurl }}/HackTheBox/)
- [Competitions]({{ site.baseurl }}/Competitions/)

## 📝 Latest (manually curated)
- [MetaCTF 2025 – Road to Cyber Bay]({{ site.baseurl }}/Competitions/MetaCTF-Road-To-CyberBay/)

## ⚙️ How I Work

My typical approach to CTF challenges and labs:

1. **Recon & Enumeration**  
   - Tools: `nmap`, `ffuf`/`gobuster`, `whatweb`, `nikto`  
   - Goal: Map the attack surface and identify open ports, services, and web directories.

2. **Web Exploitation**  
   - Tools: Burp Suite, crafted payloads, manual testing  
   - Goal: Find injection points, weak auth flows, or hidden functionality.

3. **Forensics & Analysis**  
   - Tools: `strings`, `binwalk`, Wireshark  
   - Goal: Extract hidden data, analyze PCAPs, and reverse engineer artifacts.

4. **Crypto & Reversing**  
   - Tools: Python scripts, Ghidra, `radare2`  
   - Goal: Break weak ciphers, unpack binaries, and understand custom logic.

5. **Scripting & Automation**  
   - Write quick Python snippets or Bash one-liners to automate repetitive tasks.  
   - Goal: Speed up testing and focus on insights over manual grunt work.


## ⚠️ Disclaimer
Educational use only. Techniques are for authorized CTF environments.
