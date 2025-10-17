Task 2 

Target website i used : https://preview.owasp-juice.shop

Tool: Burp Suite Community Edition
Summary: Captured and replayed the login request using Burp Repeater and tested several payloads manually. No vulnerabilities found in the documented attempts.

Table of contents

Overview

What I did

Steps with screenshots & captions

Payloads tried

Observations

Findings

Suggestions

Appendix — full screenshot list

Overview

This repository documents a manual testing session focused on the login flow of the Juice Shop preview. I captured the login POST (JSON), edited the password value in Burp Repeater, resent requests with a set of payloads, and inspected the responses. I recorded each step with screenshots — those are embedded below.

What I did

Installed Burp Suite Community Edition and opened it.

Configured the browser to proxy through Burp (127.0.0.1:8080).

Performed a test login on the Juice Shop demo so the login request would appear in Burp Proxy → HTTP history.

Sent the captured request to Repeater, edited the password field, and resent multiple times using different payloads.

Inspected responses for redirects, cookies, SQL error messages, reflected payloads, or other indicators.

Saved screenshots at each step.

Steps with screenshots & captions
1) Visiting Burp Suite website

Visited the official site to download Burp Suite Community Edition.

<img width="926" height="199" alt="Screenshot 2025-10-17 193029" src="https://github.com/user-attachments/assets/98b1e0aa-725b-4a7c-b1a4-ea84c28fdc63" />

Caption: Browser window on the Burp/PortSwigger site before downloading the Community installer.

2) Downloading the installer

Started the download for the Windows installer (Community Edition).

<img width="676" height="167" alt="Screenshot 2025-10-17 193102" src="https://github.com/user-attachments/assets/ba4df58c-da2b-469f-b3b0-310cf3c74145" />

<img width="1159" height="295" alt="Screenshot 2025-10-17 193121" src="https://github.com/user-attachments/assets/49319b3c-747b-4896-8b73-b59da53543cf" />


Caption: Download page / download started — installer .exe is being downloaded.

3) Running the installer

Ran the installer and completed the setup wizard.

<img width="411" height="202" alt="Screenshot 2025-10-17 193748" src="https://github.com/user-attachments/assets/5a4dea5f-2cd2-4af3-b059-22eb9a78f31a" />

<img width="621" height="520" alt="Screenshot 2025-10-17 193803" src="https://github.com/user-attachments/assets/1e772fce-fb27-40a8-9485-a5dc2c8a6022" />

<img width="621" height="521" alt="Screenshot 2025-10-17 193828" src="https://github.com/user-attachments/assets/730856dd-58e1-4b5e-906a-f5bcb8be2c7d" />

<img width="623" height="526" alt="Screenshot 2025-10-17 193926" src="https://github.com/user-attachments/assets/648168e4-ebeb-46b5-9001-d6acd3371c0c" />

Caption: Installer progress / installation completed dialog (shows final stage of installing Burp).

4) Burp Suite opened (main UI)
<img width="992" height="499" alt="Screenshot 2025-10-17 194024" src="https://github.com/user-attachments/assets/de40f16e-52d2-4ed3-9c67-34d7d982c799" />

<img width="627" height="542" alt="Screenshot 2025-10-17 194036" src="https://github.com/user-attachments/assets/304ebf59-3bcf-423c-a935-68ccf02adec3" />

Launched Burp Suite — main window with tabs (Proxy, Repeater, Decoder, etc.) visible.


Caption: Burp Suite main window after launch. Repeater, Proxy and other tabs are visible.


5) Confirming proxy capture

   <img width="1919" height="1079" alt="Screenshot 2025-10-17 195721" src="https://github.com/user-attachments/assets/9fc9ff67-0085-4f99-9b73-c690d9fe947c" />

<img width="1467" height="926" alt="Screenshot 2025-10-17 195743" src="https://github.com/user-attachments/assets/5a2d69e4-afba-4a52-903a-dcd57cbe2cc7" />

<img width="939" height="884" alt="Screenshot 2025-10-17 195706" src="https://github.com/user-attachments/assets/8045e7c4-6297-4d83-a92a-677e800e653f" />

<img width="954" height="380" alt="Screenshot 2025-10-17 195816" src="https://github.com/user-attachments/assets/ca4f2d48-3d6f-426c-8d0c-dc8804fda553" />


Visited the Juice Shop site while browser was proxied and confirmed the request appeared in Burp Proxy → HTTP history.


Caption: Example of a captured HTTP request shown in Burp Proxy/HTTP history — this is what I used to send to Repeater.

6) Login request in Repeater (captured JSON)

   <img width="902" height="865" alt="Screenshot 2025-10-17 211740" src="https://github.com/user-attachments/assets/62088659-4c59-41a6-8bc4-75167713686b" />

<img width="955" height="990" alt="Screenshot 2025-10-17 212802" src="https://github.com/user-attachments/assets/310049bc-b0b5-48a6-aae1-da3b1816b6ae" />

Sent the login request to Repeater. The left pane shows the raw JSON body with email and password fields.


Caption: Repeater left pane showing the captured JSON login request (ready to be edited). This is the request I modified for testing.

7) Editing the password value (example payload)
   <img width="958" height="794" alt="Screenshot 2025-10-17 212902" src="https://github.com/user-attachments/assets/70558e24-eb27-4209-8bf3-81a1393f353f" />

<img width="959" height="971" alt="Screenshot 2025-10-17 213400" src="https://github.com/user-attachments/assets/fd4c16ae-b785-488b-8374-53882c27cd58" />

Edited only the password value in the JSON body to try a test payload and prepared to send.


Caption: Repeater showing the edited request (password field changed). I only changed the password value and left other fields intact (e.g., CSRF token if present).

8) Repeater response view (after send)

   <img width="959" height="971" alt="Screenshot 2025-10-17 213400" src="https://github.com/user-attachments/assets/fa6f5dc7-fa87-4763-8a99-15653693f348" />

<img width="952" height="987" alt="Screenshot 2025-10-17 213524" src="https://github.com/user-attachments/assets/c460c022-1408-402d-a3d6-b8fec4846895" />

Checked the Response pane for status, headers and body after sending the modified request.


#Repeater right pane showing response headers/body after a send. I inspected these fields for redirects, tokens, Set-Cookie or error messages.

9) Additional attempts & payloads (examples)

Repeated the edit/send cycle with several payloads and recorded responses. The screenshots show a few different requests/responses captured during the session.


#Another Repeater view after testing a different payload. Kept a record of each attempt to compare responses.

10) Final response checks

Checked final responses for any evidence (login success token, redirects, SQL errors or reflected payloads). Nothing obvious was found in the captured screenshots.


#Final verification — response bodies and headers were inspected for signs of vulnerability. All documented attempts showed normal failure behavior in the screenshots.

Payloads tried

I used the following payloads in the password field (one at a time) from Repeater:

wrongpass

wrongpass'

' OR '1'='1

admin'--

') OR ('1'='1

"' OR "1"="1

<script>alert(1)</script> (tested where applicable in text fields)

aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa (long string)

test%27%20OR%20%271%27%3D%271 (URL-encoded variant)

Observations

The login request was a JSON POST with email and password fields — visible in Repeater.

Each edited payload was sent from Repeater and the responses were inspected for status, Location, Set-Cookie, and response body content.

From the screenshots and the tests I ran, I did not observe any authentication bypass, SQL error output, or reflected script execution. Responses looked like normal failure behavior.

Findings

Tested: manual edits of the login JSON via Burp Repeater.

Vulnerabilities found: none in the documented screenshots/attempts.

