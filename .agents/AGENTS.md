# Falcon AI Copilot Project Custom Rules

This document outlines customization rules scoped specifically to this workspace (`c:\Users\us183046\OneDrive - Grant Thornton Advisors LLC\Desktop\Falcon LLM`).

## Workspace Directory Enforcement Rule

*   **Active Directory Requirement**: All artifacts, plans, checklists (`task.md`), and walkthrough reports relating to this project must be stored, updated, and accessed directly inside the root workspace folder rather than the agent's default `brain/` directory.
*   **Target Files**:
    *   Checklist: `./task.md`
    *   Implementation Plan: `./implementation_plan.md`
    *   Log Walkthrough: `./walkthrough.md`
*   **Behavior Constraint**: Ensure that any file modifications or reads reference the active workspace root as the absolute source of truth.

## Code Freeze Rule

*   **Behavior Constraint**: The configurations, programs, and agents in this project (including `policy_analyst.py`, `soc_analyst.py`, `report_generator.py`, etc.) have been finalized by the user. Do not modify or change these programs in future interactions unless explicitly instructed to break the freeze. Treat the current state as production-ready and locked.

## Walkthrough Report Synchronization Rule

*   **Behavior Constraint**: Whenever you modify the walkthrough report (`./walkthrough.md`), you MUST run the Python compiler script (`backend/.venv/Scripts/python.exe backend/generate_docx_walkthrough.py`) to automatically compile and synchronize the Word Document (`./walkthrough.docx`) with the updated contents. This ensures both files stay fully in sync.

