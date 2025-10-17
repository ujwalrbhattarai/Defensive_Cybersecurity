# Task 2

**Target website:** https://preview.owasp-juice.shop  
**Tool:** Burp Suite Community Edition  
**Summary:** Captured and replayed the login request using Burp Repeater and tested several payloads manually. No vulnerabilities found in the documented attempts.

---

## Table of contents

1. [Overview](#overview)  
2. [What I did](#what-i-did)  
3. [Steps with screenshots and captions](#steps-with-screenshots-and-captions)  
   - [Step 1: Visiting Burp Suite website](#step-1-visiting-burp-suite-website)  
   - [Step 2: Downloading the installer](#step-2-downloading-the-installer)  
   - [Step 3: Running the installer](#step-3-running-the-installer)  
   - [Step 4: Burp Suite opened (main UI)](#step-4-burp-suite-opened-main-ui)  
   - [Step 5: Confirming proxy capture](#step-5-confirming-proxy-capture)  
   - [Step 6: Login request in Repeater (captured JSON)](#step-6-login-request-in-repeater-captured-json)  
   - [Step 7: Editing the password value (example payload)](#step-7-editing-the-password-value-example-payload)  
   - [Step 8: Repeater response view (after send)](#step-8-repeater-response-view-after-send)  
   - [Step 9: Additional attempts & payloads](#step-9-additional-attempts--payloads)  
   - [Step 10: Final response checks](#step-10-final-response-checks)  
4. [Payloads tried](#payloads-tried)  
5. [Observations](#observations)  
6. [Findings](#findings)  
7. [Suggestions](#suggestions)  
8. [Appendix — full screenshot list](#appendix---full-screenshot-list)

---

## Overview

This repository documents a manual testing session focused on the login flow of the Juice Shop preview. I captured the login POST (JSON), edited the password value in Burp Repeater, resent requests with a set of payloads, and inspected the responses. I recorded each step with screenshots — those are embedded below.

---

## What I did

- Installed Burp Suite Community Edition and opened it.  
- Configured the browser to proxy through Burp (127.0.0.1:8080).  
- Performed a test login on the Juice Shop demo so the login request would appear in Burp Proxy → HTTP history.  
- Sent the captured request to Repeater, edited the password field, and resent multiple times using different payloads.  
- Inspected responses for redirects, cookies, SQL error messages, reflected payloads, or other indicators.  
- Saved screenshots at each step.

---

## Steps with screenshots and captions

### Step 1: Visiting Burp Suite website

Visited the official site to download Burp Suite Community Edition.

![Visiting Burp Suite site](screenshots/Screenshot%202025-10-17%20193029.png)  
*Caption: Browser on the PortSwigger site before downloading the Community installer.*

---

### Step 2: Downloading the installer

Started the download for the Windows installer (Community Edition).

![Download started](screenshots/Screenshot%202025-10-17%20193102.png)  
![Download page](screenshots/Screenshot%202025-10-17%20193121.png)  
*Caption: Download page and installer download in progress.*

---

### Step 3: Running the installer

Ran the installer and completed the setup wizard.

![Installer progress 1](screenshots/Screenshot%202025-10-17%20193748.png)  
![Installer progress 2](screenshots/Screenshot%202025-10-17%20193803.png)  
![Installer progress 3](screenshots/Screenshot%202025-10-17%20193828.png)  
![Installer progress 4](screenshots/Screenshot%202025-10-17%20193926.png)  
*Caption: Installer progress screens and final installation steps.*

---

### Step 4: Burp Suite opened (main UI)

Launched Burp Suite — main window with tabs (Proxy, Repeater, Decoder, etc.) visible.

![Burp main window 1](screenshots/Screenshot%202025-10-17%20194024.png)  
![Burp main window 2](screenshots/Screenshot%202025-10-17%20194036.png)  
*Caption: Burp Suite main window after launch with Repeater and Proxy tabs visible.*

---

### Step 5: Confirming proxy capture

Visited the Juice Shop site while the browser was proxied and confirmed requests appeared in Burp Proxy → HTTP history.

![Captured traffic 1](screenshots/Screenshot%202025-10-17%20195721.png)  
![Captured traffic 2](screenshots/Screenshot%202025-10-17%20195743.png)  
![Captured traffic 3](screenshots/Screenshot%202025-10-17%20195706.png)  
![Captured traffic 4](screenshots/Screenshot%202025-10-17%20195816.png)  
*Caption: Example of captured HTTP requests shown in Burp Proxy/HTTP history — used to send to Repeater.*

---

### Step 6: Login request in Repeater (captured JSON)

Sent the login request to Repeater. The left pane shows the raw JSON body with `email` and `password` fields.

![Repeater left pane 1](screenshots/Screenshot%202025-10-17%20211740.png)  
![Repeater left pane 2](screenshots/Screenshot%202025-10-17%20212802.png)  
*Caption: Repeater left pane showing the captured JSON login request (ready to be edited).*

---

### Step 7: Editing the password value (example payload)

Edited only the `password` value in the JSON body to try a test payload and prepared to send.

![Edited request 1](screenshots/Screenshot%202025-10-17%20212902.png)  
![Edited request 2](screenshots/Screenshot%202025-10-17%20213400.png)  
*Caption: Repeater showing the edited request (password field changed). Only the password was modified; other fields were left intact.*

---

### Step 8: Repeater response view (after send)

Checked the Response pane for status, headers and body after sending the modified request.

![Repeater response 1](screenshots/Screenshot%202025-10-17%20213524.png)  
![Repeater response 2](screenshots/Screenshot%202025-10-17%20213524.png)  
*Caption: Repeater right pane showing response headers/body after a send. I inspected these for redirects, tokens, Set-Cookie or error messages.*

---

### Step 9: Additional attempts & payloads

Repeated the edit/send cycle with several payloads and recorded responses. The screenshots show a few different requests/responses captured during the session.

![Another Repeater view](screenshots/Screenshot%202025-10-17%20213748.png)  
*Caption: Another Repeater view after testing a different payload. Kept a record of each attempt to compare responses.*

---

### Step 10: Final response checks

Checked final responses for any evidence (login success token, redirects, SQL errors or reflected payloads). Nothing obvious was found in the captured screenshots.

![Final check](screenshots/Screenshot%202025-10-17%20214024.png)  
*Caption: Final verification — response bodies and headers were inspected for signs of vulnerability. All documented attempts showed normal failure behavior.*

---

## Payloads tried

I used the following payloads in the password field (one at a time) from Repeater:

