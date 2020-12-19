![Awesome Glasses](https://cdn.rawgit.com/sindresorhus/awesome/master/media/logo.svg)

# Awesome Security Resources [![Awesome](https://awesome.re/badge.svg)](https://awesome.re)

A collection of tools, cheatsheets, operating systems, learning materials, and more all related to security. There will also be a section for other Awesome lists that relate to cybersecurity.

I seem to forget about all the tools and resources when attacking, defending, responding, or looking to learn about cyber security, the purpose of this is to help fix that.

## Table of Contents

* [Security Focused Operating Systems](#security-focused-operating-systems)
* [Penetration Testing Tools](#penetration-testing-tools)
  * [Enumeration](#Enumeration)
  * [Exploitation](#Exploitation)
  * [Privilege Escalation](#Privilege-Escalation)
  * [Miscellaneous](#miscellaneous)
* [Incident Response](#Incident-Response)
* [Malware Analysis](#Malware-Analysis)
* [Reverse Engineering](#Reverse-Engineering)
* [Networking](#networking)
* [Exploits](#Exploits)
* [Practice Sites](#Practice-Sites)
* [Learning Materials](#Learning-Materials)
* [Youtube Channels](#Youtube-Channels)
* [Awesome Repos](#Awesome-Repos)
* [Walkthroughs/Guides](#Walkthroughs-and-Guides)
* [Books and Cheatsheets](#books-and-cheatsheets)
* [Web Tools](#web-tools)

### Security Focused Operating Systems

Name | Description
---- | ----
[Commando VM](https://github.com/fireeye/commando-vm) | Virtual Machine dedicated to penetration testing using Windows 10 built by FireEye
[FLARE-VM](https://www.fireeye.com/blog/threat-research/2017/07/flare-vm-the-windows-malware.html) | Virtual Machine dedicated to malware analysis and reverse engineering using Windows 10 built by FireEye
[Kali Linux](https://www.kali.org) | Open source linux operating system. Lots of built in tools for penetration testing and offensive security.
[Parrot OS](https://parrotsec.org) | Debian-based linux operting system focused on security and privacy. Has lots of built in tools

### Penetration Testing Tools

These tools are broken up into 4 categories. Enumeration, Exploitation, Privilege Escalation, and Miscellaneous.

* Enumeration tools are any tools that help in the process of collecting more information about the target being attacked.

* Exploitation tools are any tools that help in exploiting the target after it has been enumerated.

* Privilege Escalation tools are the tools that will aid in vertical or horizontal permission change.

* Micscellaneous tools are any pentesting tools that don't fit in the 3 above categories.

Name | Description
---- | ----
**Enumeration** |
[Nmap](https://nmap.org) | A free and open source utility for network discovery and security auditing.
[LinEnum](https://github.com/rebootuser/LinEnum) | A scripted local linux enumeration tool.
[PSPY](https://github.com/DominicBreuker/pspy) | A command line tool designed to snoop on processes without need for root permissions.
**Exploitation** |
[ShellPop](https://github.com/0x00-0x00/ShellPop) | Generate easy and sophisticated reverse or bind shell commands to help you during penetration tests.
**Privilege Escalation** |
**Miscellaneous** |
[Kali Tools](https://tools.kali.org/tools-listing) | List of all the tools that are pre-installed on Kali linux and an explanation to what they do.
[Pentest Checklist](https://github.com/netbiosX/Checklists) | Different Checklists to run through durring a pentest engagement.
[CyberChef](http://icyberchef.com/) | Encoding and decoding tool for a variety of different ciphers.

### DFIR

Name | Description
---- | ----

### Malware Analysis

Name | Description
---- | ----

### Reverse Engineering

Name | Description
---- | ----
[GDB](http://www.gnu.org/software/gdb/download/) | The GNU Project Debugger
[IDA](https://www.hex-rays.com/products/ida/support/download_freeware/) | Dissassembler has been the golden standard for years
[Ghidra](https://ghidra-sre.org) | Ghidra is a software reverse engineering (SRE) framework created and maintained by the National Security Agency Research Directorate.
[OllyDbg](http://www.ollydbg.de/) | A 32-bit assembler level analysing debugger for Microsoft Windows.
[Radare2](https://www.radare.org/r/) | A portable reversing framework.

### Networking

Name | Description
---- | ----
[Wireshark](https://www.wireshark.org/download.html) | The world’s foremost and widely-used network protocol analyzer.

### Exploit Tools

Name | Description
---- | ----

### OSINT

Name | Description
---- | ----
[Bing Image Search](https://www.bing.com/visualsearch?FORM=ILPVIS) | Reverse image search.
[DeHashed](https://dehashed.com/) | A hacked-database search-engine.
[NameCheck](https://namechk.com/) | Search site for usernames across different platforms.
[NameCheckup](https://namecheckup.com/) | Search site for usernames across different platforms.
[HaveIBeenPwned](https://haveibeenpwned.com/) | Check to see if an account has been involved in a databreach.
[Scylla.sh](https://scylla.sh/api) | Database dumps search site.
[Sherlock](https://github.com/sherlock-project/sherlock) | Hunt down social media accounts by username acrross social networks.
[TinEye](https://tineye.com/) | Reverse image search.
[WhatsMyName](https://whatsmyname.app/) | Tool that allows you to enumerate usernames across many websites.
[Yandex](https://yandex.com/images/) | Reverse image search.

### Practice Sites

Name | Description
---- | ----
[Attack/Defense Labs](https://public.attackdefense.com) | Very well built security attack and defense labs.
[Certified Hacker](http://certifiedhacker.com) | Intentionally vulnerable website.
[Defend the Web](https://defendtheweb.net/?hackthis) | An interactive security platform where you can learn and challenge your skills.
[Enigma Group](https://www.enigmagroup.org) | Web application security training.
[Exploit Education](https://exploit.education) | Provides a variety of resources that can be used to learn about vulnerability analysis, exploit development, software debugging, binary analysis, and general cyber security issues.
[FLAWS](http://flaws.cloud) | AWS specific security challenge site.
[GameofHacks](https://www.gameofhacks.com) | This game was designed to test your application hacking skills.
[Gh0st Networks](http://www.gh0st.net) | CTF site for security practice.
[Google CTF](https://capturetheflag.withgoogle.com) | Yearly CTF hosted by Google.com.
[HackMe](https://hack.me) | Site to share vulnerable web applications for practice in web hacking.
[HackTheBox](https://www.hackthebox.eu) | Boot to root penetration testing practice site.
[HackThisSite](https://www.hackthissite.org) | Wargame prictice site and community forums.
[Hacking Lab](https://www.hacking-lab.com/index.html) | An online ethical hacking, computer network and security challenge platform, dedicated to finding and educating cyber security talents.
[Hellbound Hackers](https://www.hellboundhackers.org) | Hacking practice site.
[IO](http://io.netgarage.org) | Wargame site to practice hacking skills.
[OvertheWire](https://overthewire.org/wargames/) | Begniier wargames that teach the basics of security.
[Microcorruption](https://microcorruption.com/login) | Wargame to help in using a debugger and Assembly Language.
[PentestIt](https://lab.pentestit.ru) | Penetration Testing Laboratories.
[Pentest Practice](https://www.pentestpractice.com/challenges/tutorial) | Online security training environment.
[Pentest Training](https://pentest.training/index.php) | A simple website used as a hub for information revolving around the varies services we offer to help both experienced and new penetration testers practice and hone their skills.
[Permanent CTF List](https://captf.com/practice-ctf/) | List of CTFs that are always available online or able to be downloaded.
[Pwnable.kr](http://pwnable.kr) | Wargame site to help improve hacking skills.
[Pwnable.tw](https://pwnable.tw) | A wargame site for hackers to test and expand their binary exploiting skills.
[Reversing.kr](http://reversing.kr/index.php) | Site to test your Cracking and Reverse Engineering ability.
[Ring0CTF](https://ringzer0ctf.com) | Hacking practice site.
[RootMe](https://www.root-me.org/?lang=en) | Hacking practice site.
[SmashTheStack](http://smashthestack.org/wargames.html) | Site with various wargames available to practice.
[Try2Hack](http://www.try2hack.nl) | This site provides several security-oriented challenges.
[TryHackMe](https://tryhackme.com) | Room based site for hacking practice with good instruction.
[VulnHub](https://www.vulnhub.com) | Downloadable virtual machines to practice hacking.
[WeChall](https://www.wechall.net) | Security challenge site.
[WeChalls](https://w3challs.com) | Wargames to practice hacking.
**Practice Labs** |
[Metasploitable](https://information.rapid7.com/download-metasploitable-2017.html?LS=1631875&CS=web) | Intentionally vulnerable target machine for evaluating Metasploit
[Pentest Lab](https://github.com/Sliim/pentest-lab) | contains examples to deploy a penetration testing lab on OpenStack provisioned with Heat, Chef and Docker.
[SecGen](https://github.com/cliffe/SecGen) | Creates vulnerable virtual machines, lab environments, and hacking challenges, so students can learn security penetration testing techniques.
[WebGOAT](https://owasp.org/www-project-webgoat/) | A deliberately insecure application that allows interested developers just like you to test vulnerabilities commonly found in Java-based applications that use common and popular open source components.

### Learning Materials

Name | Description
---- | ----
[Building a Home Lab for Offensive Security](https://systemoverlord.com/2017/10/24/building-a-home-lab-for-offensive-security-basics.html) | Guide on how to build a home lab for security purposes.
[Pentesting Methodology](http://www.0daysecurity.com/pentest.html) | Step by step walkthough of a basic pentesting methodology.
[The Hacking Process](https://bitvijays.github.io) | Lots of information on the hacking process.

### Youtube Channels

Name | Description
---- | ----
[13Cubed](https://www.youtube.com/channel/UCy8ntxFEudOCRZYT1f7ya9Q) | This channel covers information security-related topics including Digital Forensics and Incident Response (DFIR) and Penetration Testing.
[Blackhat](https://www.youtube.com/c/BlackHatOfficialYT/videos) | This is the channel for the security conference, with lots of talks and demonstrations on different security topics.
[IppSec](https://www.youtube.com/c/BlackHatOfficialYT/videos) | This channel shows walkthroughs of different HackTheBox machines.
[John Hammond](https://www.youtube.com/channel/UCVeW9qkBjo3zosnqUbG7CFw) | This channel covers solving CTFs and programming.
[Learn Forensics](https://www.youtube.com/channel/UCZ7mQV3j4GNX-LU1IKPVQZg) | This channel is devoted to computer forensics.
[LiveOverflow](https://www.youtube.com/channel/UClcE-kVhqyiHCcjYwcpfj9w) | Just a wannabe hacker... making videos about various IT security topics and participating in hacking competitions.
[Stacksmashing](https://www.youtube.com/channel/UC3S8vxwRfqLBdIhgRlDRVzw) | This channel uses Ghidra to reverse engineer various things.

### Awesome Repos

Name | Description
---- | ----
[Awesome Hacking](https://github.com/vitalysim/Awesome-Hacking-Resources) | A collection of hacking / penetration testing resources.
[Awesome ICS Security](https://github.com/hslatman/awesome-industrial-control-system-security) | A curated list of resources related to Industrial Control System (ICS) security.
[Awesome Incident Response](https://github.com/meirwah/awesome-incident-response) | A curated list of tools and resources for security incident response, aimed to help security analysts and DFIR teams.
[Awesome Pentest](https://github.com/enaqx/awesome-pentest) | A collection of awesome penetration testing resources, tools, and other shiny things.

### Walkthroughs and Guides

Name | Description
---- | ----
[Hackso.me](https://hackso.me/categories/) | CTF, HacktheBox, and Vulnhub walkthroughs
[HackTheBox Guides](https://0xdf.gitlab.io/) | Guides/Walkthroughs for various retired HacktheBox machines.

### Web Tools

Name | Description
---- | ----
[Triage](https://tria.ge) | Malware sandbox or analysis.
[Hybrid Analysis](https://hybrid-analysis.com) | Free automated malware service
[Virus Total](https://www.virustotal.com/gui/) | Online malacious file analyzer
[Jeffrey's Image Metadata Viewer](http://exif.regex.info/exif.cgi) | Shows the data that might be inside a digital image file.

### Web Articles

Name | Description
---- | ----
[How to create a reverse Shell](https://www.businessinsider.com/how-to-create-a-reverse-shell-to-remotely-execute-root-commands-over-any-open-port-using-netcat-or-bash-2012-1) | Article detailing how to create a reverse shell and when to do it.
[Reverse Shell in Bash](https://incognitjoe.github.io/reverse-shells-for-dummies.html) | Reverse shells in bash for Dummies by a Dummy.

### Books and Cheatsheets

Name | Description
---- | ----
**Books** |
**Cheatsheets** |
[SANS DFIR](https://digital-forensics.sans.org/community/cheat-sheets) | Digital Forensics and Incident Response cheatsheets from SANS.
[SANS Pentest Posters](https://www.sans.org/security-resources/posters/pen-testing) | These are Pentesting Posters that SANS supplies.
[SANS Cheatsheets](https://www.danielowen.com/2017/01/01/sans-cheat-sheets/) | Various SANS cheatsheets.
[Pentesting Tools Cheatsheet](https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/) | A quick reference high level overview for typical penetration testing engagements from highon.coffee.
[Reverse Shell Cheatsheet](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) |  Several different types of reverse shells