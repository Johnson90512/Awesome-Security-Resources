![Awesome Glasses](https://cdn.rawgit.com/sindresorhus/awesome/master/media/logo.svg)

# Awesome Security Resources [![Awesome](https://awesome.re/badge.svg)](https://awesome.re)

A collection of tools, cheatsheets, operating systems, learning materials, and more all related to security. There will also be a section for other Awesome lists that relate to cybersecurity.

I seem to forget about all the tools and resources when attacking, defending, responding, or looking to learn about cyber security, the purpose of this is to help fix that.

## Table of Contents

* [Awesome Security Resources](#awesome-security-resources)
  * [Security Focused Operating Systems](#security-focused-operating-systems)
  * [Penetration Testing Tools](#penetration-testing-tools)
  * [Malware Analysis](#malware-analysis)
  * [Reverse Engineering](#reverse-engineering)
  * [Networking](#networking)
  * [Exploit Tools](#exploit-tools)
  * [OSINT](#osint)
  * [Practice Sites](#practice-sites)
  * [Youtube Channels](#youtube-channels)
  * [Awesome Repos](#awesome-repos)
  * [Walkthroughs](#walkthroughs)
  * [Learning Materials](#learning-materials)
  * [Books and Cheatsheets](#books-and-cheatsheets)
  * [Podcasts](#podcasts)
  * [Documentation](#documentation)
  * [Industrial Control System Info](#industrial-control-system-info)
* [Contributing](#contributing)

### Security Focused Operating Systems

Name | Description
---- | ----
[Commando VM](https://github.com/fireeye/commando-vm) | Virtual Machine dedicated to penetration testing using Windows 10 built by FireEye.
[FLARE-VM](https://www.fireeye.com/blog/threat-research/2017/07/flare-vm-the-windows-malware.html) | Virtual Machine dedicated to malware analysis and reverse engineering using Windows 10 built by FireEye.
[Kali Linux](https://www.kali.org) | Open source linux operating system. Lots of built in tools for penetration testing and offensive security.
[Parrot OS](https://parrotsec.org) | Debian-based linux operting system focused on security and privacy. Has lots of built in tools.
[SIFT Workstation](https://digital-forensics.sans.org/community/downloads) |  A group of free open-source incident response and forensic tools designed to perform detailed digital forensic examinations in a variety of settings.

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
[WPScan](https://github.com/wpscanteam/wpscan) | A free, for non-commercial use, black box WordPress security scanner written for security professionals and blog maintainers to test the security of their WordPress websites.
**Exploitation** |
[Exploit Suggester](https://github.com/wwong99/pentest-notes/blob/master/scripts/xploit_installer.py) | Python script to suggesst different exploits to run on different Linux and Windows machines.
[p0wny shell](https://github.com/flozz/p0wny-shell) | Single-file PHP shell.
[SharpCat](https://github.com/Cn33liz/SharpCat) | A Simple Reversed Command Shell which can be started using InstallUtil (Bypassing AppLocker)
[ShellPop](https://github.com/0x00-0x00/ShellPop) | Generate easy and sophisticated reverse or bind shell commands to help you during penetration tests.
[Shellcode tools](https://github.com/malware-unicorn/shellcode_tools) | About miscellaneous tools written in Python, mostly centered around shellcodes.
[ZackAttack!](https://github.com/urbanesec/ZackAttack) | A new Tool Set to do NTLM Authentication relaying unlike any other tool currently out there.
**Privilege Escalation** |
[DirtyCow POC](https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs) | Table listing the source code to several different variations of dirtycow.
[GTFOBins](https://gtfobins.github.io) | A curated list of Unix binaries that can used to bypass local security restrictions in misconfigured systems.
[Unix Privilege Escalation](https://github.com/pentestmonkey/unix-privesc-check) | Shell script to check for simple privilege escalation vectors on Unix systems.
**Miscellaneous** |
[CyberChef](http://icyberchef.com/) | Encoding and decoding tool for a variety of different ciphers.
[Kali Tools](https://tools.kali.org/tools-listing) | List of all the tools that are pre-installed on Kali linux and an explanation to what they do.
[Payload All the Things](https://github.com/swisskyrepo/PayloadsAllTheThings) | A list of useful payloads and bypass for Web Application Security and Pentest/CTF.
[Pentest Checklist](https://github.com/netbiosX/Checklists) | Different Checklists to run through durring a pentest engagement.
[PWNTools](https://github.com/Gallopsled/pwntools) | CTF framework and exploit development library.
[Red Team Toolkit](https://github.com/Johnson90512/Red-Teaming-Toolkit) | A collection of open source and commercial tools that aid in red team operations.
[Various Pentest Tools](https://github.com/trickster0?tab=repositories) | Pentesting tools from a pentester.
[Hack Tricks](https://book.hacktricks.xyz/welcome/readme) | Welcome to the page where you will find each hacking trick/technique/whatever I have learnt in CTFs, real life apps, and reading researches and news.

### DFIR

Name | Description
---- | ----
[Jeffrey's Image Metadata Viewer](http://exif.regex.info/exif.cgi) | Shows the data that might be inside a digital image file.
[Steganography Toolkit](https://github.com/DominicBreuker/stego-toolkit) | Collection of steganography tools - helps with CTF challenges.
[Volatility](https://github.com/volatilityfoundation/volatility) | An advanced memory forensics framework.
[VolUtility](https://github.com/kevthehermit/VolUtility) | Web App for Volatility framework

### Malware Analysis

Name | Description
---- | ----
[Triage](https://tria.ge) | Malware sandbox or analysis.
[Hybrid Analysis](https://hybrid-analysis.com) | Free automated malware service
[Virus Total](https://www.virustotal.com/gui/) | Online malacious file analyzer

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
[CCNA Subreddit](https://www.reddit.com/r/ccna/wiki/index) | Subreddit dedicated to the CCNA Exam.
[CCNA\CCENT Training Series](https://www.youtube.com/playlist?list=PLmdYg02XJt6QRQfYjyQcMPfS3mrSnFbRC) | A full course of 84 videos for CCNA and CCENT Routing and Switching taught by Cisco Instructor Andrew Crouthamel.
[CCNA Training Series](https://www.youtube.com/playlist?list=PLh94XVT4dq02frQRRZBHzvj2hwuhzSByN) | Youtube Series on CCNA information.
[Impacket](https://github.com/SecureAuthCorp/impacket) | A collection of Python classes for working with network protocols.
[SubnettingPractice](https://subnettingpractice.com) | The most extensive subnetting practice site on the web!
[Subnetting.net](https://www.subnetting.net/Subnetting.aspx?mode=practice) | Sunetting practice tools.
[Wireshark](https://www.wireshark.org/download.html) | The world’s foremost and widely-used network protocol analyzer.
[Wireshark Certified Network Analyst](https://www.youtube.com/watch?v=FaoheEdkqdc&index=10&list=PLTIJiKI4vOA37qUl-5ztWYcCE6zpscF6j) | Youtube series of 15 videos about the WCNA.
[Wireshark Training Documenation](https://www.wireshark.org/docs/) | In depth documentation on how to use wireshark.

### Exploit Tools

Name | Description
---- | ----

### OSINT

Name | Description
---- | ----
[Bing Image Search](https://www.bing.com/visualsearch?FORM=ILPVIS) | Reverse image search.
[DeHashed](https://dehashed.com/) | A hacked-database search-engine.
[DNSDumpster](https://dnsdumpster.com) | Free domain research tool that can discover hosts related to a domain.
[Jeffrey's Image Metadata Viewer](http://exif.regex.info/exif.cgi) | Simple and free tool that shows the Exif data on images.
[NameCheck](https://namechk.com/) | Search site for usernames across different platforms.
[NameCheckup](https://namecheckup.com/) | Search site for usernames across different platforms.
[HaveIBeenPwned](https://haveibeenpwned.com/) | Check to see if an account has been involved in a databreach.
[Scylla.sh](https://scylla.sh/api) | Database dumps search site.
[Sherlock](https://github.com/sherlock-project/sherlock) | Hunt down social media accounts by username acrross social networks.
[TinEye](https://tineye.com/) | Reverse image search.
[Online Traceroute](https://hackertarget.com/online-traceroute/) | Online Traceroute using MTR.
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

### Youtube Channels

Name | Description
---- | ----
[13Cubed](https://www.youtube.com/channel/UCy8ntxFEudOCRZYT1f7ya9Q) | This channel covers information security-related topics including Digital Forensics and Incident Response (DFIR) and Penetration Testing.
[Blackhat](https://www.youtube.com/c/BlackHatOfficialYT/videos) | This is the channel for the security conference, with lots of talks and demonstrations on different security topics.
[Guided Hacking](https://www.youtube.com/c/GuidedHacking/videos) |  A hacking and reverse engineering community with a focus on game hacking.
[IppSec](https://www.youtube.com/c/BlackHatOfficialYT/videos) | This channel shows walkthroughs of different HackTheBox machines.
[John Hammond](https://www.youtube.com/channel/UCVeW9qkBjo3zosnqUbG7CFw) | This channel covers solving CTFs and programming.
[Learn Forensics](https://www.youtube.com/channel/UCZ7mQV3j4GNX-LU1IKPVQZg) | This channel is devoted to computer forensics.
[LiveOverflow](https://www.youtube.com/channel/UClcE-kVhqyiHCcjYwcpfj9w) | Just a wannabe hacker... making videos about various IT security topics and participating in hacking competitions.
[Stacksmashing](https://www.youtube.com/channel/UC3S8vxwRfqLBdIhgRlDRVzw) | This channel uses Ghidra to reverse engineer various things.

### Awesome Repos

Name | Description
---- | ----
[Android Security](https://github.com/ashishb/android-security-awesome#readme) | A collection of android security related resources.
[Application Security](https://github.com/paragonie/awesome-appsec#readme) | A curated list of resources for learning about application security.
[CTF](https://github.com/apsdehal/awesome-ctf#readme) | A curated list of CTF frameworks, libraries, resources and softwares.
[Cybersecurity Blue Team](https://github.com/fabacab/awesome-cybersecurity-blueteam#readme) | A curated collection of awesome resources, tools, and other shiny things for cybersecurity blue teams.
[DevSecOps](https://github.com/TaptuIT/awesome-devsecops#readme) | Curating the best DevSecOps resources and tooling.
[Embedded and IoT Security](https://github.com/fkie-cad/awesome-embedded-and-iot-security#readme) | A curated list of awesome embedded and IoT security resources.
[Fuzzing](https://github.com/cpuu/awesome-fuzzing#readme) | A curated list of awesome Fuzzing(or Fuzz Testing) for software security.
[GDPR](https://github.com/bakke92/awesome-gdpr#readme) | Protection of natural persons with regard to the processing of personal data and on the free movement of such data.
[Hacking - carpedm20](https://github.com/carpedm20/awesome-hacking#readme) | A curated list of awesome Hacking tutorials, tools and resources.
[Hacking - Hack with Github](https://github.com/Hack-with-Github/Awesome-Hacking) | A collection of various awesome lists for hackers, pentesters and security researchers.
[Hacking - vitalysim](https://github.com/vitalysim/Awesome-Hacking-Resources) | A collection of hacking / penetration testing resources to make you better!
[Honeypots](https://github.com/paralax/awesome-honeypots#readme) | An awesome list of honeypot resources
[Industrial Control Systems Security](https://github.com/hslatman/awesome-industrial-control-system-security) | A curated list of resources related to Industrial Control System (ICS) security.
[ICS Writeups](https://github.com/neutrinoguy/awesome-ics-writeups) | Collection of writeups on ICS/SCADA security.
[Incident Response](https://github.com/meirwah/awesome-incident-response#readme) | A curated list of tools for incident response.
[Lockpicking](https://github.com/fabacab/awesome-lockpicking#readme) | A curated list of awesome guides, tools, and other resources related to the security and compromise of locks, safes, and keys.
[Malware Analysis](https://github.com/rshipp/awesome-malware-analysis#readme) | A collention of awesome malware analysis tools
[Pentest](https://github.com/enaqx/awesome-pentest) | A collection of awesome penetration testing resources, tools, and other shiny things.
[Pcap Tools](https://github.com/caesar0301/awesome-pcaptools) | A collection of tools developed by other researchers in the Computer Science area to process network traces. All the right reserved for the original authors.
[Reversing](https://github.com/tylerha97/awesome-reversing) | A curated list of awesome reversing resources.
[Security](https://github.com/sbilly/awesome-security#readme) | A collection of awesome software, libraries, documents, books, resources and cools stuffs about security.
[Vehicle Security and Car Hacking](https://github.com/jaredthecoder/awesome-vehicle-security#readme) | A curated list of resources for learning about vehicle security and car hacking.
[Web Security](https://github.com/qazbnm456/awesome-web-security#readme) | A curated list of Web Security materials and resources.
[Windows Exploitation](https://libraries.io/github/enddo/awesome-windows-exploitation) | A curated list of awesome Windows Exploitation resources, and shiny things.

### Walkthroughs

Name | Description
---- | ----
[Hackso.me](https://hackso.me/categories/) | CTF, HacktheBox, and Vulnhub walkthroughs
[HackTheBox Guides](https://0xdf.gitlab.io/) | Guides/Walkthroughs for various retired HacktheBox machines.

### Learning Materials

Name | Description
---- | ----
**Enumeration** |
[Advanced Nmap:Scanning Firewalls](https://www.opensourceforu.com/2011/02/advanced-nmap-scanning-firewalls/) | Advanced Nmap techniques for how to scann various types of firewalls.
[Learning Nmap: The Basics - Part 1](https://www.opensourceforu.com/2010/08/nmap-basics/) | The basics of how to use nmap.
[Advanced Nmap: Some Scan Types - Part 2](https://www.opensourceforu.com/2010/11/advanced-nmap-some-scan-types/) | Various Nmap scan types, and the practical use of these commands to scan various devices and networks.
[Advanced Nmap: Scanning Techniques Continued - Part 3](https://www.opensourceforu.com/2010/12/advanced-nmap-scanning-techniques-continued/) | More interesting scanning techniques.
[Advanced Nmap: Fin Scan & OS Detection](https://www.opensourceforu.com/2011/01/advanced-nmap-fin-scan-and-os-detection/) | Various other command-line options.
[db_nmap](https://machn1k.wordpress.com/tag/db_nmap/) | Running nmap from within metasploit.
[GoBuster Guide](https://www.hackingarticles.in/comprehensive-guide-on-gobuster-tool/) | Comprehensive guide on GoBuster tool.
[Parsing ls](http://mywiki.wooledge.org/ParsingLs) | Why you shouldn't parse the output of ls(1).
**Exploitation**|
[AppLocker Bypass](https://pentestlab.blog/2017/05/23/applocker-bypass-rundll32/) | Using Rundll32 to bypass Applocker.
[Attacking & Securing WordPress](https://hackertarget.com/attacking-wordpress/) | Tecniques for enumeration and exploitation of wordpress sites.
[Executing Meterpreter in Memory](https://www.n00py.io/2018/06/executing-meterpreter-in-memory-on-windows-10-and-bypassing-antivirus/) | technique for executing an obfuscated PowerShell payload using Invoke-CradleCrafter in memory.
[How to hack a Wordpress site](https://www.hackingloops.com/how-to-hack-wordpress/) | Hacking a wordpress sites using different techniques.
[How to pentest your WordPress site](https://hackertarget.com/attacking-wordpress/) | How to perform a pentest on you a wordpress site. More techniques and tools.
[Metasploit Tutorial](https://www.opentechinfo.com/metasploit-tutorials/) | Metasploit Tutorial for beginners: Master in 5 minutes.
[Practical guide to NTLM Relaying](https://byt3bl33d3r.github.io/practical-guide-to-ntlm-relaying-in-2017-aka-getting-a-foothold-in-under-5-minutes.html) | Practical guide to help clear up any confusion regarding NTLM relaying.
[WordPress plugin Vulneribilities](https://wpscan.com/plugins) | List of all vulnerabilities for WordPress plugins.
**Reverse Engineering** |
[Assembly Programming Tutorial](https://www.tutorialspoint.com/assembly_programming/index.htm) | A tutorial on programming in nasm Assembly.
[Beginners Guide to Assembly](https://www.unknowncheats.me/forum/programming-beginners/63947-reverse-engineering-beginners-guide-x86-assembly-and-debugging-windows-apps.html) | This guide will explain exactly what is necessary to begin cheat creation for generally any online computer game, including both fields to study, and tools to use.
[Beginner Reverse Engineering Info](https://www.reddit.com/r/ReverseEngineering/comments/hg0fx/a_modest_proposal_absolutely_no_babies_involved/) | Reddit collection of beginner information on getting into Reverse Engineering.
[Building a Home Lab for Offensive Security](https://systemoverlord.com/2017/10/24/building-a-home-lab-for-offensive-security-basics.html) | Guide on how to build a home lab for security purposes.
[Ghidra Simple Keygen Generation](https://www.youtube.com/watch?v=9SM4IvBFxK8) | From installing ghidra on ubuntu to writing a working keygen in python.
[Ghidra Tutorial](https://www.youtube.com/channel/UCzw-AibbXjw7gcdaeN3Y6kA) | Youtube playlist on how to use ghidra using different example files.
[Guide to x86 Assembly](http://www.cs.virginia.edu/~evans/cs216/guides/x86.html) | This guide describes the basics of 32-bit x86 assembly language programming, covering a small but useful subset of the available instructions and assembler directives.
[Guide to Assmebly in VS .NET](http://www.cs.virginia.edu/~evans/cs216/guides/vsasm.html)  | This tutorial explains how to use assembly code in a Visual Studio .NET project.
[How to start out in Reverse Engineering](https://www.reddit.com/r/ReverseEngineering/comments/12ajwc/how_to_start_out_in_reverse_engineering/) | Reddit post on the steps to get started in Reverse Engineering.
[IDA Pro Tutorial](https://www.youtube.com/playlist?list=PLt9cUwGw6CYG2kmL5n6dFgi4wKMhgLNd7) | Tutorial on how to reverse engineer with IDA Pro.
[Intel 64 and IA32 Software Manual](https://software.intel.com/sites/default/files/managed/39/c5/325462-sdm-vol-1-2abcd-3abcd.pdf) | This document contains all four volumes of the Intel 64 and IA-32 Architectures Software Developer's Manual.
[Intermediate x86](https://opensecuritytraining.info/IntermediateX86.html) | Intermediate Intel x86: Architecture, Assembly, Applications, & Alliteration. Part 2 to Into to x86.
[Intro to Malware Analysis and Reverse Engineering](https://www.cybrary.it/course/malware-analysis/) | Malware analysis course to learn how to perform dynamic and static analysis on all major files types, how to carve malicious executables from documents and how to recognize common malware tactics and debug and disassemble malicious binaries.
[Intro to x86](https://opensecuritytraining.info/IntroX86.html) | Introductory Intel x86: Architecture, Assembly, Applications, & Alliteration.
[Malware Analysis Tutorial](http://fumalwareanalysis.blogspot.com/p/malware-analysis-tutorials-reverse.html) | Malware Analysis Tutorials: a Reverse Engineering Approach.
[Mastering Ghidra](https://vimeo.com/335158460) | Video from Infiltrate 2019 on mastering Ghidra.
[Myne-US](http://www.myne-us.com/2010/08/from-0x90-to-0x4c454554-journey-into.html) | From 0x90 to 0x4c454554, a journey into exploitation.
[Reverse Engineering 101](https://vimeo.com/6764570) | Vimeo video by Dan Guido
[Reverse Engineering 101 - Malware Unicorn](https://malwareunicorn.org/workshops/re101.html#0) | Malwareunicorn.org provides workshops and resources for reverse engineering in the infosec space. Workshop content is now available.
[Reverse Engineering 102](https://vimeo.com/30594548) | Vimeo video by Dan Guido
[Reversing for Newbies](https://forum.tuts4you.com/files/file/1307-lenas-reversing-for-newbies/) | A collection of tutorials aimed particularly for newbie reverse engineers.
[RE Guide for beginners](https://0x00sec.org/t/re-guide-for-beginners-methodology-and-tools/2242) | Methodology and Tools of reverse engineering.
[So you want to be a Malware Analyst](https://blog.malwarebytes.com/security-world/2012/09/so-you-want-to-be-a-malware-analyst/) | Malwarebytes blog on becomming a malware analyst and what all is involved.
[Windows oneliners to download and execute code](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/) | Oneliners for executing arbitrary command lines and eventually compromising a system.
[Where to start in leaning reverse engineering](https://news.ycombinator.com/item?id=7143186) | Forum post detailing the process to start learning reverse engineering.
**Privilege Escalation** |
[Basic Linux Privilege Escalation](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/) | Blog teaching the basics of Linux Privelege Escalation.
[Linux Privilege Escalation Techniques](https://www.sans.org/reading-room/whitepapers/linux/paper/37562) | SANS papers on the linux privilege escalation.
[Linux Privilege Escalation tools/tactics](https://guif.re/linuxeop) | List of different linux privilege escalation tools and techniques as well as several scripts to download to automate the process.
[Windows Privilege Escalation](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/) | Guide on techniques for Windows Privilege Escalation.
[LXD Privilege Escalation](https://www.hackingarticles.in/lxd-privilege-escalation/) | Describes how an account on the system that is a member of the lxd group is able to escalate the root privilege by exploiting the features of LXD.
**Shells** |
[How to build a RAT](https://www.quora.com/How-can-I-build-a-RAT-Remote-Access-Trojan-from-scratch-For-educational-purposes-only) | Building a RAT from scratch for educational purposes.
[How to create a backdoor](https://null-byte.wonderhowto.com/how-to/hack-like-pro-create-nearly-undetectable-backdoor-with-cryptcat-0149264/) | Article on how to create a nearly undetectable backdoor with Cryptcat.
[How to create a remote command shell](https://www.sans.edu/student-files/presentations/ftp_nslookup_withnotes.pdf) | Creating a remote command shell using a default windows command line tools
[How to create a reverse Shell](https://www.businessinsider.com/how-to-create-a-reverse-shell-to-remotely-execute-root-commands-over-any-open-port-using-netcat-or-bash-2012-1) | Article detailing how to create a reverse shell and when to do it.
[Reverse Shell in Bash](https://incognitjoe.github.io/reverse-shells-for-dummies.html) | Reverse shells in bash for Dummies by a Dummy.
**Hacking and Pentesting** |
[Pentesting Methodology](http://www.0daysecurity.com/pentest.html) | Step by step walkthough of a basic pentesting methodology.
[The Hacking Process](https://bitvijays.github.io) | Lots of information on the hacking process.
[Guide to Penetration Testing](https://www.varonis.com/blog/varonis-six-part-guide-to-penetration-testing/) | Varonis Seven Part Guide to Penetration Testing.
**CTF** |
[CTF Field Guide](https://trailofbits.github.io/ctf/) | How to get started in CTFs

### Books and Cheatsheets

Name | Description
---- | ----
**Books** |
[Programming from the Ground Up](http://nongnu.askapache.com/pgubook/ProgrammingGroundUp-1-0-booksize.pdf) | Using Linux assembly language to teach new programmers the most important concepts in programming.
**Cheatsheets** |
[DFIR Infographics](https://www.dfir.training/infographics-cheats) | Infographics about various DFI topics including file info, volume info, attribute info.
[General DFIR](https://www.dfir.training/general-dfir) | Cheatsheets for general dfir info.
[Malware Analysis](https://www.dfir.training/malware-cheats) | Cheatsheets for different aspects of malware analysis.
[Memory Forensics](https://www.dfir.training/memory-cheats) | Cheatsheets for memory forensics. SANS memory forensics.
[OSINT](https://www.dfir.training/osint-cheats) | Cheatsheets for OSINT strategies and tools.
[Pentesting Tools Cheatsheet](https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/) | A quick reference high level overview.
[Radare2 Cheatsheet](https://scoding.de/uploads/r2_cs.pdf) | Cheatsheet of common commands for program Radare2
[Reverse Shell Cheatsheet](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) |  Several different types of reverse shells
[SANS DFIR](https://digital-forensics.sans.org/community/cheat-sheets) | Digital Forensics and Incident Response cheatsheets from SANS.
[SANS Pentest Posters](https://www.sans.org/security-resources/posters/pen-testing) | These are Pentesting Posters that SANS supplies.
[SANS Cheatsheets](https://www.danielowen.com/2017/01/01/sans-cheat-sheets/) | Various SANS cheatsheets.
[THC Favorite tips, tricks and hacks](https://github.com/hackerschoice/thc-tips-tricks-hacks-cheat-sheet) | Various tips & tricks for typical penetration testing engagements from highon.coffee.
[Volatility Command Reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference) | Quick reference command list for Volatility.
[Windows Post Exploitation Command List](http://www.handgrep.se/repository/cheatsheets/postexploitation/WindowsPost-Exploitation.pdf) | Quick Reference command list used in post-exploitation of windows machines.
[Windows Registry Forensics](https://www.dfir.training/registry-cheats) | Cheatsheets on windows registry for different tools and information.
[x86 and and64 instruction reference](https://www.felixcloutier.com/x86/) | Reference for instructions with included summary of each.

### Podcasts

Name | Description
---- | ----
[7 Minute Security](https://7ms.us) | A weekly infosec podcast about pentesting, blue teaming and building a career in security.
[Hackable?](https://hackablepodcast.com) | Hackable? gives us a front row seat to explore where we’re vulnerable in our daily routines, without even realizing it.
[InfoSec ICU](https://www.stitcher.com/show/infosec-icu) | The Health Information Security podcast from the Medical University of South Carolina.
[Malicious Life](https://malicious.life) | Malicious Life by Cybereason tells the unknown stories of the history of cybersecurity, with comments and reflections by real hackers, security experts, journalists, and politicians.
[Risky Business](https://risky.biz) | Risky Business podcast features news and in-depth commentary from security industry luminaries.
[SANS Internet Stormcenter Daily Network/Cyber Security and Information Security Stormcast](https://isc.sans.edu/podcast.html) | A brief daily summary of what is important in cyber security.
[Security Now!](https://twit.tv/shows/security-now) | Security podcast with Steve Gibson and Leo Laporte.
[The CyberWire Daily](https://thecyberwire.com/podcasts/daily-podcast) | The daily cybersecurity news and analysis industry leaders depend on.

### Documentation

Name | Description
---- | ----
[Security Policy Templates](https://www.sans.org/information-security-policy/) | SANS has developed and posted here a set of security policy templates for your use.

### Programming

Name | Description
---- | ----
**C**|
[Learn C](https://www.learn-c.org) | Free interactive C tutorial.
**Python**
[Learn Python](https://www.learnpython.org) | Free Python tutorial.

### Industrial Control System Info

Name | Description
---- | ----
**Learning Materials** |
[Getting Started in ICS](http://www.robertmlee.org/a-collection-of-resources-for-getting-started-in-icsscada-cybersecurity/) | A Collection of Resources for Getting Started in ICS/SCADA Cybersecurity.
[SCADA Hacking](https://www.hackers-arise.com/scada-hacking) | Information on how to hack ICS/SCADA devices.
**Tools** |
[Cronpot](https://github.com/mushorg/conpot) | ICS/SCADA honeypot.
[ICS Security Tools](https://github.com/iti/ics-security-tools) | Tools, tips, tricks, and more for exploring ICS Security.

# Contributing

Your contributions are always welcome! Please take a look at the [contribution guidelines](https://github.com/Johnson90512/Awesome-Security-Resources/blob/main/contributing.md) first.

- - -

If you have any question about this opinionated list, do not hesitate to contact me [@johnson90512](https://twitter.com/johnson90512) on Twitter or open an issue on GitHub.
