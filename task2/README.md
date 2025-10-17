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
<img width="926" height="199" alt="Screenshot 2025-10-17 193029" src="https://github.com/user-attachments/assets/935142d2-a623-4d19-bde8-a1bcd9754015" />

![Visiting Burp Suite site]
  
*Caption: Browser on the PortSwigger site before downloading the Community installer.*

---

### Step 2: Downloading the installer

Started the download for the Windows installer (Community Edition).
<img width="676" height="167" alt="Screenshot 2025-10-17 193102" src="https://github.com/user-attachments/assets/14259c81-2a00-4e03-b477-7019cbd04f54" />

<img width="1159" height="295" alt="Screenshot 2025-10-17 193121" src="https://github.com/user-attachments/assets/ffefeba5-d8d1-47b7-afa8-3eea521a9937" />

![Download page] 
![Download started] 

*Caption: Download page and installer download in progress.*

---

### Step 3: Running the installer

Ran the installer and completed the setup wizard.

<img width="621" height="521" alt="Screenshot 2025-10-17 193828" src="https://github.com/user-attachments/assets/b44134a0-96ef-45e0-8949-cc36ab6b1823" />
<img width="622" height="515" alt="Screenshot 2025-10-17 193846" src="https://github.com/user-attachments/assets/877968ef-78a6-43bd-91f1-329e756e6726" />
<img width="623" height="526" alt="Screenshot 2025-10-17 193926" src="https://github.com/user-attachments/assets/978f4528-902e-4d39-bbcb-b1773c7298b6" />

![Installer progress] 
*Caption: Installer progress screens and final installation steps.*

---

### Step 4: Burp Suite opened (main UI)

Launched Burp Suite — main window with tabs (Proxy, Repeater, Decoder, etc.) visible.
<img width="992" height="499" alt="Screenshot 2025-10-17 194024" src="https://github.com/user-attachments/assets/61e3d4cc-c8cf-4bbc-828a-09c23e4a3bf8" />
<img width="627" height="542" alt="Screenshot 2025-10-17 194036" src="https://github.com/user-attachments/assets/720046a5-009e-488b-a33f-1e89aecf0af5" />
<img width="938" height="706" alt="Screenshot 2025-10-17 194150" src="https://github.com/user-attachments/assets/5c4d44c8-dc77-4e07-9803-f384f39a22dc" />

![Burp main window].  
*Caption: Burp Suite main window after launch with Repeater and Proxy tabs visible.*

---

### Step 5: Confirming proxy capture

Visited the Juice Shop site while the browser was proxied and confirmed requests appeared in Burp Proxy → HTTP history.
<img width="939" height="884" alt="Screenshot 2025-10-17 195706" src="https://github.com/user-attachments/assets/36e90c09-cee3-4db2-afcc-206244a0927b" />

<img width="1919" height="1079" alt="Screenshot 2025-10-17 195721" src="https://github.com/user-attachments/assets/760023e5-9506-4f7d-84dc-72cc60248857" />
<img width="1467" height="926" alt="Screenshot 2025-10-17 195743" src="https://github.com/user-attachments/assets/f1b4c6c5-4f9b-4240-8720-f7a7d043988b" />
<img width="954" height="380" alt="Screenshot 2025-10-17 195816" src="https://github.com/user-attachments/assets/e462debf-4c0f-480c-9fd7-87b08c070989" />

![Captured traffic]. 
*Caption: Example of captured HTTP requests shown in Burp Proxy/HTTP history — used to send to Repeater.*

---

### Step 6: Login request in Repeater (captured JSON)

Sent the login request to Repeater. The left pane shows the raw JSON body with `email` and `password` fields.
<img width="902" height="865" alt="Screenshot 2025-10-17 211740" src="https://github.com/user-attachments/assets/13106036-ae4d-4e4d-9071-82f426314a05" />

![Repeater left pane] 
*Caption: Repeater left pane showing the captured JSON login request (ready to be edited).*

---

### Step 7: Editing the password value (example payload)

Edited only the `password` value in the JSON body to try a test payload and prepared to send.
<img width="908" height="639" alt="Screenshot 2025-10-17 212430" src="https://github.com/user-attachments/assets/8611bbe5-0543-481c-a2c3-cb3fa7e3fcdf" />
<img width="955" height="990" alt="Screenshot 2025-10-17 212802" src="https://github.com/user-attachments/assets/92aa326d-fe9b-4da8-b28d-89fe739eaf81" />

<img width="958" height="794" alt="Screenshot 2025-10-17 212902" src="https://github.com/user-attachments/assets/2b21ba60-6c12-4b28-baa6-4d8cd3c63e00" />

![Edited request].  
*Caption: Repeater showing the edited request (password field changed). Only the password was modified; other fields were left intact.*

---

### Step 8: Repeater response view (after send)

Checked the Response pane for status, headers and body after sending the modified request.
<img width="959" height="971" alt="Screenshot 2025-10-17 213400" src="https://github.com/user-attachments/assets/499cb346-5035-4de4-aa6e-edad0a837218" />

![Repeater response].
*Caption: Repeater right pane showing response headers/body after a send. I inspected these for redirects, tokens, Set-Cookie or error messages.*

---

### Step 9: Additional attempts & payloads

Repeated the edit/send cycle with several payloads and recorded responses. The screenshots show a few different requests/responses captured during the session.
<img width="952" height="987" alt="Screenshot 2025-10-17 213524" src="https://github.com/user-attachments/assets/171b99dc-44e2-4891-95ce-19ef9bfe7795" />

![Another Repeater view]. 
*Caption: Another Repeater view after testing a different payload. Kept a record of each attempt to compare responses.*

---

### Step 10: Final response checks

Checked final responses for any evidence (login success token, redirects, SQL errors or reflected payloads). Nothing obvious was found in the captured screenshots.

![Final check](screenshots/Screenshot%202025-10-17%20214024.png)  
*Caption: Final verification — response bodies and headers were inspected for signs of vulnerability. All documented attempts showed normal failure behavior.*

---

## Payloads tried

I used the following payloads in the password field (one at a time) from Repeater:
wrongpass
wrongpass'
' OR '1'='1
admin'--
') OR ('1'='1
"' OR "1"="1

<script>alert(1)</script> (tested where applicable)


---

## Observations

- The login request was a JSON POST with `email` and `password` fields (visible in Repeater).  
- Each edited payload was sent from Repeater and the responses were inspected for **status**, **Location**, **Set-Cookie**, and response body content.  
- From the screenshots and the tests I ran, I did not observe any authentication bypass, SQL error output, or reflected script execution. Responses looked like normal failure behavior.

---

## Findings

- **Tested:** manual edits of the login JSON using Burp Repeater.  
- **Vulnerabilities found:** none in the documented screenshots/attempts.

---

## Suggestions

Even though I didn’t find anything in these tests, these practices are good for login endpoints:

- Use prepared statements / parameterized queries (prevent SQLi).  
- Validate and sanitize user input server-side.  
- Use generic error messages to avoid account enumeration.  
- Set cookies with `HttpOnly` and `Secure` and regenerate session IDs on login.
 



