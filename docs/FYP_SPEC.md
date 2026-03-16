# AuroraEdge Security — Final Project Spec (Jan 2026)

**Working Title**

AuroraEdge Security: Designing and Implementing an Automated Email Authentication and Cyber Defence System for Small Organisations

---

## Introduction

Email attacks like phishing and spoofing are still one of the biggest problems in cybersecurity. Even though systems like SPF, DKIM, and DMARC exist to protect email domains, most small businesses either don’t set them up correctly or don’t know how to maintain them. This usually happens because it’s confusing, time consuming, and very easy to make mistakes.

My project will focus on building a system called AuroraEdge Security that automates all of that. It checks a domain’s records, fixes errors, enforces proper settings, and keeps them monitored all without needing the user to understand the technical details.

I chose this topic because it combines two things I’m really interested in — cybersecurity and automation. It’s also relevant to the kind of work I want to do after the course, where simplifying security for small companies is a real challenge. Previous studies and reports (like the Verizon DBIR 2023 and Google Email Security Report 2022) have shown that most cyber-attacks still start with email, so this project aims to make a practical difference there.

---

## Aim

To design, build, and test an automated cybersecurity platform that can set up, monitor, and fix email authentication systems (SPF, DKIM, DMARC) automatically, reducing human error and improving domain security for small organisations.

---

## Objectives

- Research the main reasons why SPF/DKIM/DMARC records are often wrong or missing.
- Design a simple, secure system that can automatically manage DNS records and generate reports.
- Build a working prototype that can:
  - Check and validate DNS records.
  - Show a security score and suggestions.
  - Automatically fix incorrect records.
- Add security measures like HTTPS, authentication tokens, and basic logging.
- Test the system in a controlled lab setup and measure how fast and accurately it detects and fixes problems.
- Compare the results to similar existing tools (like OnDMARC and EasyDMARC) to see how effective it is.

---

## Methodology

This project will use a design-and-build approach. I’ll first research existing tools and best practices in email security and automation. Then I’ll design the system architecture and start implementing it in a small, safe test environment using open-source tools such as:

- FastAPI (Python) for the backend,
- Cloudflare API for DNS updates,
- OpenDMARC and Postfix for email validation and testing,
- SQLite for storing results.

Once the system is working, I’ll run tests by introducing deliberate errors such as invalid DKIM keys or missing SPF records and measure how long it takes the system to detect and fix them. Results will be compared against doing the same process manually.

The data will be analysed to show improvements in speed, accuracy, and reliability. Graphs and tables will be created from the collected logs and metrics.

---

## Problem Statement

Email is still one of the easiest and most common ways that companies get hacked. Attacks such as phishing and spoofing happen every day, and even though systems such as SPF, DKIM, and DMARC exist to stop it, most small businesses either don’t use them properly or don’t even know they are and why they need them. Small UK businesses simply don’t have the time, knowledge, or resources to manage things like DNS or security policies.

According to the UK Government’s Cyber Security Breaches Survey 2023, about 32% of UK businesses said they had some kind of cyber-attack or breach last year, but most small companies still only deal with it after something goes wrong. One of the quotes from that report sums it up perfectly:

“Spending is usually reactive. If there is a problem, then it is fixed. We don’t have budget set to go towards cyber security.”
(Department for Science, Innovation & Technology, 2023)

The same survey also explains that a lot of smaller firms rely on one IT person or an outside contractor to handle everything technical. If that person leaves, they’re often left with no access to key systems, especially DNS or email. They are saying

“Our IT guy left, and we can’t log into the DNS thing to fix email errors.”

Even though that’s not a formal quote from any government report, it’s the kind of problem that’s been described across many SME studies, including a 2025 paper called:

One Size Does Not Fit All: Exploring the Cybersecurity Needs of UK SMEs by Jones and Papadaki.

That study found that most small UK businesses struggle with applying even basic technical controls and tend to rely on external IT help instead of having security processes built in.

The National Cyber Security Centre also supports this. Their Suspicious Email Reporting Service received over 7.1 million reports of dodgy emails and links in 2022, proving how common email attacks are and how much of a problem this still is for UK businesses. The NCSC also said that a large number of UK domains still don’t enforce proper DMARC policies, meaning spoofing and impersonation attacks are still easy to pull off.

When you put all that together, the main problems are:

1. Lack of technical knowledge — Most small organisations have no one who understands DNS or email authentication.
2. Fear of breaking things — People are scared to touch DNS records in case they take their email offline; DNS records can be easily changed, misconfigured or deleted.
3. Over reliance on individuals — When an IT person leaves, access and knowledge go with them.
4. Compliance pressure — UK frameworks like Cyber Essentials Plus and the NCSC Mail Check program are now pushing DMARC enforcement, which small businesses are expected to meet but can’t manage manually.

---

## References

- Department for Science, Innovation and Technology (2023) *Cyber Security Breaches Survey 2023*. GOV.UK. Available at: https://www.gov.uk/government/statistics/cyber-security-breaches-survey-2023 (Accessed: 15 January 2026).

- National Cyber Security Centre (2023) *British business support crucial in removing scams*. Available at: https://www.ncsc.gov.uk/news/british-business-support-crucial-in-removing-scams (Accessed: 15 January 2026).

- Jones, R. and Papadaki, M. (2025) ‘One Size Does Not Fit All: Exploring the Cybersecurity Needs of UK SMEs’, *Journal of Cyber Policy*. Taylor & Francis. Available at: https://www.tandfonline.com/doi/full/10.1080/19393555.2024.2357310 (Accessed: 15 January 2026).

---

## Time Plan (24 Weeks)

- Finalise my title & plan, confirm my success criteria and set Drive structure.
- Start literature review and collect standards (SPF, DKIM, DMARC, MTA‑STS, TLS‑RPT, STARTTLS).
- Finish research design and ethics form (test domains & data handling).
- Build & test a manual email/DNS baseline on a test domain and record observations.
- Implement DNS query module (SPF, MX, DMARC, DKIM selector discovery).
- Add MTA‑STS and TLS‑RPT checks and normalise the results.
- Automation: command line scan for a domain list, CSV/Markdown output.
- Add misconfiguration rules (e.g., SPF >10 lookups, missing DMARC, weak DKIM). Unit tests.
- Dashboard: (Flask/FastAPI): local viewer for a table of results.
- I’ll add simple token auth in my (.env) file and export CSV/HTML, usability polish.
- Heuristics: alignment checks, DMARC policy scoring and STARTTLS grade notes.
- Controlled tests with synthetic misconfigs and capture datasets.
- Batch scans across 50–100 public domains and I’ll store the results.
- Data cleaning, summaries and begin figures/tables.
- Methods + evaluation draft and update roadmap based on my findings.
- Mid point supervisor review ? and adjust scope if needed.
- Results + discussion draft and then integrate figures/tables.
- Threat model, ethical considerations and limitations.
- Internal review, fix gaps and extend tests if needed.
- Near final dashboard & CLI, documentation screenshots for evidence.
- Finalise methods/appendices (CLI help, schemas, test cases).
- Full report draft freeze and proofreading round 1.
- Proofreading round 2 and reference checks as well as a figure polish.
- Final proofreading, produce submission PDF, backup my work.
- Buffer for slippage, viva/demo prep, stress testing and a final polish.
