# Automated Continuous TEVV Framework for DoD LLM Adoption

## The Task
Deploying LLMs in national security environments requires shifting from traditional static software compliance to dynamic, continuous validation. This project applies automated compliance engineering principles to bridge the gap between commercial frontier models and DoD Responsible AI guidelines. 

Rather than treating compliance as a gatekeeping hurdle at the end of development, this repository demonstrates a **Continuous Test, Evaluation, Verification, and Validation (TEVV)** framework that evaluates model outputs against defense-specific ethical and legal mandates in real time.

## Core Capabilities & Skills Matrix
This framework bridges complex defense regulations with automated software validation pipelines.

| Compliance & Governance | Technical & Engineering |
| :--- | :--- |
| **DoD Responsible AI (RAI) Alignment** | **Python Development** (Automated Log/Text Parsing) |
| **Risk-based Frameworks** (NIST AI RMF) | **Structured Data Management** (JSON/Config Architectures) |
| **Continuous TEVV Framework Design** | **Prompt Safety & Evaluation Harnesses** |
| **Federal Defense Strategy Synthesis** | **Agentic AI Workflow Orchestration** |

---

## Project Architecture
```text
├── README.md               <-- Executive overview and framework mapping
├── guidelines/             <-- Policy-to-rule translation matrices
├── evaluation_harness/     <-- Automated risk evaluation suite
│   ├── config.json         <-- Rule thresholds & criteria limits
│   ├── eval_rules.py       <-- Python core parsing model outputs
│   └── test_cases.json     <-- Mock LLM payloads with synthetic failure modes
└── documentation/          <-- Deep dives on ATO streamlining & TEVV parameters
```

## Advanced AI-Assisted Engineering Workflow

This framework was architected and executed using a multi-tiered, agentic AI engineering stack. Rather than manually writing compliance matrices or boilerplate validation scripts, frontier AI platforms were leveraged to maximize research fidelity, resolve complex policy contradictions, and accelerate engineering velocity.

### 1. Deep Research Policy Synthesis via NotebookLM
To establish an unassailable regulatory foundation, **NotebookLM** served as the primary knowledge synthesis engine. High-volume, unstructured federal defense strategies, mandates, and executive briefs were ingested into a closed, high-fidelity workspace:
* **The Pentagon’s January 2026 AI Strategy Memorandum:** Guidance on accelerated execution and removing bureaucratic data silos.
* **National Security Presidential Memorandum-11 (NSPM-11):** Directives for secure national security AI adoption and risk mitigation.
* **CDAO Task Force Lima Executive Summaries:** Frameworks for generative AI/LLM integration and continuous validation boundaries.
* **DoD Ethical Principles & ARMOR 2025:** Ethical benchmarks assessing models against the Law of War and Rules of Engagement.

* **Outcome:** NotebookLM resolved conflicting bureaucratic terminology across distinct defense agencies, mapped critical gaps between civilian safety filters and tactical military constraints, and extracted the precise, actionable data compliance requirements mandated by the FY26 National Defense Authorization Act (NDAA). These synthesized constraints were mapped directly into the code's evaluation criteria.

### 2. Autonomous Agentic Code Generation via Google Antigravity
The underlying Python validation engine (`eval_rules.py`) and JSON configuration layers were engineered using **Google Antigravity**, an agent-first development platform. By pairing with autonomous sub-agents within the Antigravity workspace, the engineering focus shifted from line-by-line coding to systems architecture, policy mapping, and code verification:
***Dynamic Pattern Matching:** Instructed Antigravity agents to write optimized regex patterns and contextual semantic checks targeted at catching operational security (OPSEC) data leaks.
***Artifact Auditing:** Utilized Antigravity's structured "Artifacts" ecosystem to systematically review, modify, and approve the agent’s implementation plans, dependency mappings, and logic flow before compilation.
***Isolated Testing:** Leveraged Antigravity's execution sandbox to autonomously run, test, and debug mock LLM payloads against our generated compliance configurations, removing standard development bottlenecks.

---

## Technical Implementation & TEVV Logic

The core validation engine (`eval_rules.py`) acts as a lightweight, continuous assessment pipeline. It ingests an LLM's response log and programmatically verifies compliance against the rules extracted during the policy synthesis phase.

### Execution Workflow:
1. **Rule Ingestion:** The harness parses threshold criteria and strict policy constraints defined within `config.json`.
2. **Contextual Evaluation:** Incoming text payloads are processed through standard parsing rules to evaluate safety compliance—specifically flagging deviations from defined Law of War boundaries, detecting unauthorized operational data leaks, or tracking systemic accuracy drift.
3. **Automated Flagging & Halting:** If any evaluation score drops below the defined compliance thresholds, the system flags a violation and triggers a build failure or system alert. This stops non-compliant model behaviors from moving forward in the deployment pipeline.

By moving away from static, manual document checklists and replacing them with this style of continuous, programmatic verification, defense organizations can dramatically condense their **Authority to Operate (ATO)** timelines from months to days.
