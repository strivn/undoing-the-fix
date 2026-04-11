# Undoing the Fix: Evaluating AI Control Against Security Regression Attacks

Achieved 4th place out of 126 submissions at the [AI Control Hackathon 2026](https://apartresearch.com/sprints/ai-control-hackathon-2026-03-20-to-2026-03-22), co-organized by [Apart Research](https://apartresearch.com) and [Redwood Research](https://www.redwoodresearch.org/).

Production codebases carry accumulated security fixes that can be lost when an AI agent modifies code, whether deliberately or by mistake. Existing control evaluations focus on additive attacks (inserting backdoors, exfiltrating data), but reverting a security fix looks like normal refactoring and removes protections rather than adding suspicious code.

We propose **CVE regression** as a control setting where the attack is removing existing security patches while performing other code work, using real vulnerabilities and real SWE-bench tasks. Our initial results suggest this is a viable direction and that further work is needed to ensure AI agents preserve important properties of the code they modify.

Main experiment notebook: [`experiment/run.ipynb`](experiment/run.ipynb)

This is a weekend hackathon prototype with various limitations (chat completions instead of agentic execution, no main task verification, single repository, disjoint file scope). See the [project page](https://apartresearch.com/project/undoing-the-fix-cve-regression-as-an-ai-control-setting-f855) and [paper](https://framerforms.s3.us-east-1.amazonaws.com/form-uploads/baf7aa79-8ab4-4310-b0d2-ad89838d1536-Undoing-the-Fix-Report.pdf) for details and future work.
