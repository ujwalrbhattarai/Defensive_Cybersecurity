# Phishing Simulation & Email Threat Analysis (Gophish)

---

## Table of Contents
1. [Overview](#overview)  
2. [Tools & Resources](#tools--resources)    
3. [Steps Performed](#steps-performed)  
   - [Visiting websites & downloading Gophish](#visiting-websites--downloading-gophish)  
   - [Unzipping & running the software](#unzipping--running-the-software)  
   - [Accessing the admin dashboard (localhost) and login](#accessing-the-admin-dashboard-localhost-and-login)  
   - [Setting up Sending Profile](#setting-up-sending-profile)  
   - [Creating Landing Page](#creating-landing-page)  
   - [Creating Email Template](#creating-email-template)  
   - [Creating User Groups and importing recipients](#creating-user-groups-and-importing-recipients)  
   - [Creating & launching Campaign](#creating--launching-campaign)  
4. [Observed Phishing Traits (learning outcome)](#observed-phishing-traits-learning-outcome)  
6. [Screenshots](#screenshots)  
7. [Conclusion & Security Notes](#conclusion--security-notes)  
8. [Appendix: Helpful commands & links](#appendix-helpful-commands--links)

---

## Overview
Gophish is an open-source phishing framework designed for security awareness training. This project documents a local setup and a controlled phishing campaign using Gophish to practice identifying phishing characteristics and configuring phishing simulations for training purposes.

---

## Tools & Resources
- Gophish (open-source) — https://github.com/gophish/gophish/releases or https://gophish.io  
- Your web browser (to access admin UI and the landing pages)   

---

## Steps Performed

### Visiting websites & downloading Gophish
1. Visited the official Gophish releases page: `https://github.com/gophish/gophish/releases` (or `https://gophish.io`).  
<img width="584" height="158" alt="Screenshot 2025-10-22 193705" src="https://github.com/user-attachments/assets/0b490903-852c-41d2-ad06-b0f37870b3a0" />

2. Downloaded the correct archive for the operating system (for example `gophish-vX.Y.Z-windows-64bit.zip`).
<img width="1918" height="891" alt="Screenshot 2025-10-22 193720" src="https://github.com/user-attachments/assets/98f3fc56-4783-450f-bf8d-d7ac965377d9" />
<img width="1918" height="999" alt="Screenshot 2025-10-22 193744" src="https://github.com/user-attachments/assets/a270bcc2-431e-4499-9350-af16c7bf8fa3" />
<img width="1133" height="545" alt="Screenshot 2025-10-22 193801" src="https://github.com/user-attachments/assets/da9f38eb-fd3f-4458-8840-9c9271a34ad1" />
<img width="413" height="135" alt="Screenshot 2025-10-22 193905" src="https://github.com/user-attachments/assets/4117c340-0cd3-4357-88f4-a6151616e2ae" />

_Reference screenshot:.



---

### Unzipping & running the software
1. Unzipped the downloaded archive into a local folder (for example, `C:\tools\gophish\` or `~/gophish/`).  
   - Example (Windows): Right-click → Extract All... or use `tar -xvf` / `unzip` on macOS/Linux.  
<img width="971" height="156" alt="Screenshot 2025-10-22 193840" src="https://github.com/user-attachments/assets/47bcd099-c993-4e54-bf6f-8303ed679bec" />

2. Ran the Gophish executable:
   - On Windows: `gophish.exe` (double-clicking the exe also opens a terminal window).  
   - On macOS/Linux: `./gophish` (ensure it has execute permissions: `chmod +x gophish`).
<img width="1466" height="742" alt="Screenshot 2025-10-22 193850" src="https://github.com/user-attachments/assets/ac1005c9-3c5c-4970-a083-142f7432bd93" />

When run for the first time, Gophish prints to the terminal that the admin server is available (typically `http://127.0.0.1:3333` or `http://localhost:3333`) and displays the generated admin username and password (or instructions to use the default credentials).

_Reference screenshot:_ See **Screenshot 3** — terminal window showing the first-time admin credentials and admin server URL.

---

### Accessing the admin dashboard (localhost) and login
1. Open a browser and navigate to the admin URL printed in the terminal (e.g., `http://127.0.0.1:3333`).  
2. Enter the provided admin username and password shown in the command window.  
3. On successful login, you see the Gophish admin dashboard.

_Referenc<img width="1919" height="972" alt="Screenshot 2025-10-22 193923" src="https://github.com/user-attachments/assets/bb6f2e09-1144-4d89-80d2-b9ef65795108" />
e screenshots:_ **Screenshot 4** and **Screenshot 5** — Admin login and dashboard view.

---

### Setting up Sending Profile
1. From the dashboard, navigate to **Sending Profiles**.  
2. Click **New Profile** and enter SMTP server details (for lab testing, you can use a controlled SMTP testing environment or a local SMTP stub).  
3. Save the sending profile and perform a test send to confirm connectivity.


<img width="883" height="970" alt="Screenshot 2025-10-22 194021" src="https://github.com/user-attachments/assets/15307f93-a90b-4906-9a66-bcdfea681659" />

---

### Creating Landing Page
1. Go to **Landing Pages** → **New Landing Page**.  
2. Create or paste the HTML content you want the test landing page to present (e.g., a mock login form for educational purposes).  
3. Save the landing page and note its URL (served by the local Gophish server).


<img width="871" height="934" alt="Screenshot 2025-10-22 194036" src="https://github.com/user-attachments/assets/83034e43-4c07-4bb0-9793-f4ed5e91d7d9" />

<img width="877" height="349" alt="Screenshot 2025-10-22 194055" src="https://github.com/user-attachments/assets/a707fde7-48ec-4ecd-93db-9c4ad0a68504" />

---

### Creating Email Template
1. Navigate to **Email Templates** → **New Template**.  
2. Compose the phishing email content, subject, and optionally include tags or placeholders (like `{{.FirstName}}`).  
3. Use the built-in preview to verify that template rendering looks correct and that the `click` links point to the intended landing page.  


<img width="1601" height="618" alt="Screenshot 2025-10-22 194107" src="https://github.com/user-attachments/assets/f8830c42-77d0-4dde-952c-3307ea8e16a3" />

---

### Creating User Groups and importing recipients
1. Go to **Users & Groups** (or **Targets / Groups**) → **New Group**.  
2. Import a CSV containing columns such as `First Name, Last Name, Email`.  
3. Confirm the imported recipients appear in the group.  

<img width="1597" height="468" alt="Screenshot 2025-10-22 194120" src="https://github.com/user-attachments/assets/b2d141b1-8c96-4702-8f62-456994664b19" />


---

### Creating & launching Campaign
1. From the dashboard, click **Campaigns** → **New Campaign**.  
2. Fill the campaign form: name, choose the email template, landing page, sending profile, and target group.  
3. Configure start date/time, tracking settings, and shortlink options.  
4. Launch the campaign and monitor progress; the dashboard will show metrics like emails sent, opened, clicked, and submitted data.  


<img width="1597" height="713" alt="Screenshot 2025-10-22 194136" src="https://github.com/user-attachments/assets/4d0da2c8-90b9-411b-8b5d-e2488127fa9c" />


---

## Observed Phishing Traits (learning outcome)
While configuring and testing phishing emails, we documented the common indicators attackers use. Use these to analyze suspicious emails in the wild:

- **Sender spoofing**: The `From` name may look legitimate while the real email address may be different (e.g., `support@company.com` vs `support@company-security.info`). Always check the full email address.  
- **Mismatched URLs**: Displayed link text may show a trusted domain while the real `href` points to a different domain or an IP address. Hover links to reveal destinations.  
- **Urgent or threatening language**: Messages that demand immediate action or threaten consequences to force clicks.  
- **Suspicious attachments**: Executables, archives, or macro-enabled documents that request enabling macros.  
- **Spelling/grammar errors**: Many phishing emails contain typos, odd phrasing, or poor grammar.  
- **Unusual sending infrastructure**: Mail headers showing relays from unexpected IP addresses or SPF/DKIM/DMARC failures. Use an online header analyzer to inspect headers.  
- **Short or obfuscated links**: URL shorteners or long query strings meant to hide the destination.  

These traits were investigated as part of the lab exercise and are documented here as a learning checklist for email threat analysis.

---

## Screenshots
Below are the extracted screenshots from the exercise. Each image has a short caption describing the step captured. Copy the `screenshots/` folder into your repo root so images render on GitHub.

1. **Screenshot 1** - Downloaded Gophish release (zip file) from GitHub.
   ![Screenshot 1](screenshots/Screenshot 2025-10-22 193705.png)

2. **Screenshot 2** - Extracted the archive into a local folder ready to run.
   ![Screenshot 2](screenshots/Screenshot 2025-10-22 193720.png)

3. **Screenshot 3** - Ran `gophish.exe` — terminal shows admin server URL and generated admin credentials for first-time login.
   ![Screenshot 3](screenshots/Screenshot 2025-10-22 193744.png)

4. **Screenshot 4** - Opened the admin URL in browser (admin login page).
   ![Screenshot 4](screenshots/Screenshot 2025-10-22 193801.png)

5. **Screenshot 5** - Logged in to the Gophish admin dashboard.
   ![Screenshot 5](screenshots/Screenshot 2025-10-22 193840.png)

6. **Screenshot 6** - Creating/testing a Sending Profile (SMTP settings).
   ![Screenshot 6](screenshots/Screenshot 2025-10-22 193850.png)

7. **Screenshot 7** - Creating a Landing Page with a mock/login form.
   ![Screenshot 7](screenshots/Screenshot 2025-10-22 193905.png)

8. **Screenshot 8** - Composing an Email Template (editor view).
   ![Screenshot 8](screenshots/Screenshot 2025-10-22 193923.png)

9. **Screenshot 9** - Email template preview showing personalization and link placeholders.
   ![Screenshot 9](screenshots/Screenshot 2025-10-22 194021.png)

10. **Screenshot 10** - Importing test recipients into a user group (CSV import).
    ![Screenshot 10](screenshots/Screenshot 2025-10-22 194036.png)

11. **Screenshot 11** - Campaign creation form: choose template, landing page, sending profile, and group.
    ![Screenshot 11](screenshots/Screenshot 2025-10-22 194055.png)

12. **Screenshot 12** - Launching the campaign and confirmation to start sending.
    ![Screenshot 12](screenshots/Screenshot 2025-10-22 194107.png)

13. **Screenshot 13** - Campaign dashboard showing live metrics (sent, opened, clicked).
    ![Screenshot 13](screenshots/Screenshot 2025-10-22 194120.png)

14. **Screenshot 14** - Campaign results / collected submissions (if any) and timeline.
    ![Screenshot 14](screenshots/Screenshot 2025-10-22 194136.png)

---

## Conclusion & Security Notes
This exercise demonstrates how phishing campaigns are created in a controlled environment and highlights the practical traits used by attackers. The hands-on setup improves the ability to spot phishing tactics and better prepare defensive measures such as:
- Enforcing SPF/DKIM/DMARC and monitoring header anomalies.  
- Training users to verify sender addresses and hover links before clicking.  
- Using safe browsing tools and sandboxed viewers for attachments.  
- Running phishing simulations ethically: only against consenting users or within an approved training environment.

---- How to Identify a Phishing Email

Suspicious Sender: Check the full email address — it may look similar to a trusted one but with small changes (e.g., support@paypa1.com).

Urgent or Threatening Language: Phrases like “Your account will be suspended!” push you to act fast without thinking.

Mismatched or Fake Links: Hover over links — if the real URL differs from the text shown or looks strange, it’s likely phishing.

Unexpected Attachments: Attachments you didn’t expect, especially .zip, .exe, or .docm files, are dangerous.

Poor Grammar or Design Errors: Many phishing emails contain spelling mistakes, odd phrasing, or low-quality logos.

Requests for Personal Info: Legitimate companies never ask for passwords, OTPs, or credit card details via email.

---- How to Avoid Phishing

Don’t click links or open attachments unless you trust the sender and were expecting the message.

Verify directly from official sources — visit websites manually instead of clicking links in emails.

Use strong passwords and enable MFA (multi-factor authentication) for all important accounts.

Keep your system, browser, and antivirus updated to block known phishing and malware sites.

---

## Appendix: Helpful commands & links
- Download Gophish: `https://github.com/gophish/gophish/releases` or `https://gophish.io`  
- Example unzip commands:  
  - Windows (PowerShell): `Expand-Archive -Path gophish.zip -DestinationPath .\gophish\`  
  - macOS/Linux: `unzip gophish-vX.Y.Z-linux-64bit.zip -d gophish`  
- Run Gophish:  
  - Windows: `.\gophish.exe`  
  - macOS/Linux: `./gophish` (may need `chmod +x gophish`)  
- Online header analyzer examples: MX Toolbox Header Analyzer, Google Messageheader tools, or other free header analyzers.

---

