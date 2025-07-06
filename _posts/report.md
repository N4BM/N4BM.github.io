# WannaCry Ransomware: Full Technical Analysis Lab Report

*By [Your Name]*

WannaCry (WanaCrypt0r 2.0) shook the world in May 2017, leveraging the leaked EternalBlue exploit for rapid wormable spread. This post details my complete hands-on analysis of a WannaCry sample, with **every lab step and screenshot included**.

---

## Table of Contents

1. [Sample Acquisition and Verification](#sample-acquisition-and-verification)
2. [Initial Static Analysis](#initial-static-analysis)
3. [PE File Structure](#pe-file-structure)
4. [Strings and Resource Analysis](#strings-and-resource-analysis)
5. [Dynamic Analysis](#dynamic-analysis)
6. [Network Activity and Kill Switch](#network-activity-and-kill-switch)
7. [Ransom Note & File Impact](#ransom-note--file-impact)
8. [Persistence & Registry Changes](#persistence--registry-changes)
9. [Indicators of Compromise (IOCs)](#indicators-of-compromise-iocs)
10. [Conclusions & Lessons Learned](#conclusions--lessons-learned)

---

## 1. Sample Acquisition and Verification

The analysis began by acquiring a known WannaCry sample and verifying its hash.

**Sample hash and VirusTotal report:**  
![VirusTotal and Hash](wannacry_screenshots/varida.jpg)

---

## 2. Initial Static Analysis

Using various static tools, we confirmed the sample as a Windows PE32 executable.

**Detect It Easy, basic PE scan:**  
![Initial scan](wannacry_screenshots/1.jpg)  
![Section info](wannacry_screenshots/2.jpg)  
![Entropy check](wannacry_screenshots/3.jpg)  
![Optional headers](wannacry_screenshots/4.jpg)  
![File info](wannacry_screenshots/5.jpg)

**Timestamp Analysis:**  
The compile time field indicates a 2017 date, consistent with the outbreak.
![Timestamp](wannacry_screenshots/timestamp.jpg)

---

## 3. PE File Structure

### Section Analysis

A detailed review of PE sections was performed using Resource Hacker and similar tools.

- `.text`, `.rdata`, `.data` (standard)
- Suspicious extra or padded sections observed.

**Screenshots:**  
![PE sections](wannacry_screenshots/resourcehack.jpg)  
![Resource Hacker - icons, dialogs, etc.](wannacry_screenshots/6.jpg)  
![Resource Hacker - ransom message image](wannacry_screenshots/7.jpg)  
![Resource Hacker - language packs](wannacry_screenshots/8.jpg)  
![Resource entries](wannacry_screenshots/9.jpg)  
![More resources](wannacry_screenshots/10.jpg)

---

## 4. Strings and Resource Analysis

Strings analysis exposed key artifacts:

- Ransom message content
- Bitcoin addresses
- Kill switch domain
- List of encrypted file extensions

**Strings tool output:**  
![Strings 1](wannacry_screenshots/strings.jpg)  
![Strings 2](wannacry_screenshots/11.jpg)  
![Strings 3](wannacry_screenshots/12.jpg)  
![Strings 4](wannacry_screenshots/13.jpg)  
![Strings 5](wannacry_screenshots/14.jpg)

---

## 5. Dynamic Analysis

### Lab Setup

Sample executed inside a controlled Windows VM. Monitored with Process Explorer, Regshot, etc.

#### **Process Explorer / Running Processes**
- WannaCry injects into legitimate processes, spawns new instances.

![Process Explorer](wannacry_screenshots/procwxe.jpg)  
![Processes tree](wannacry_screenshots/15.jpg)  
![Child process](wannacry_screenshots/16.jpg)

#### **File Operations**

- Ransom notes dropped in multiple directories.
- Wallpaper changed by malware.

![Desktop wallpaper](wannacry_screenshots/17.jpg)  
![Ransom note 1](wannacry_screenshots/18.jpg)  
![Ransom note 2](wannacry_screenshots/19.jpg)  
![Ransom note 3](wannacry_screenshots/20.jpg)  
![Encrypted files](wannacry_screenshots/21.jpg)  
![File explorer - affected](wannacry_screenshots/22.jpg)  
![Hidden files revealed](wannacry_screenshots/23.jpg)  
![Shadow copies deleted](wannacry_screenshots/24.jpg)

#### **Regshot / Registry Analysis**
- Persistence via registry Run keys and service creation.

![Registry change](wannacry_screenshots/rechackero.png)  
![Regshot results](wannacry_screenshots/25.jpg)  
![Run keys](wannacry_screenshots/26.jpg)  
![Service created](wannacry_screenshots/27.jpg)

---

## 6. Network Activity and Kill Switch

- WannaCry attempts to contact the kill switch domain at startup.
- SMB scanning observed.
- DNS requests and network activity logged.

**Network/URL screenshots:**  
![Network activity](wannacry_screenshots/url.png)  
![Wireshark - DNS](wannacry_screenshots/28.jpg)  
![Wireshark - SMB](wannacry_screenshots/29.jpg)  
![TCPView](wannacry_screenshots/30.jpg)  
![Kill switch attempt](wannacry_screenshots/31.jpg)  
![Kill switch domain in action](wannacry_screenshots/32.jpg)

---

## 7. Ransom Note & File Impact

- `@Please_Read_Me@.txt` dropped in all user directories.
- Custom desktop background set.

**Screenshots:**  
![Ransom note - English](wannacry_screenshots/33.jpg)  
![Ransom note - more](wannacry_screenshots/34.jpg)  
![Multilanguage ransom notes](wannacry_screenshots/35.jpg)  
![Desktop background](wannacry_screenshots/36.jpg)  
![Lock screen](wannacry_screenshots/37.jpg)

---

## 8. Persistence & Registry Changes

- Adds itself to Startup via registry keys.
- Installs as a service.

**Screenshots:**  
![Startup entry](wannacry_screenshots/38.jpg)  
![Services](wannacry_screenshots/39.jpg)  
![Registry editor](wannacry_screenshots/40.jpg)  
![More registry](wannacry_screenshots/41.jpg)

---

## 9. Indicators of Compromise (IOCs)

**File hashes:**  
- See VirusTotal screenshot (`varida.jpg`)

**Bitcoin wallets, kill switch domain, ransom note paths:**  
- Extracted from `strings.jpg` and resource screenshots.

**Network:**  
- Outbound attempts to `iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com`
- Unusual SMB traffic (port 445)

**Registry:**  
- Persistence Run keys and custom service names.

---

## 10. Conclusions & Lessons Learned

WannaCry combined a wormable exploit with ransomware, creating a global incident. Key takeaways:

- Patch critical vulnerabilities immediately (EternalBlue/MS17-010 was patched before the outbreak!)
- Isolate and monitor network segments to limit wormable malware.
- Keep offline, secure backups to prevent ransomware impact.

---

## **Full List of All Screenshots Used**

For completeness, here’s every screenshot referenced (in order, including those not already shown above):

