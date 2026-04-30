# Contributing to Vexa

First off, thanks for taking the time to contribute! 🎉

The following is a set of guidelines for contributing to Vexa. These are mostly guidelines, not rules. Use your best judgment, and feel free to propose changes to this document in a pull request.

## How Can I Contribute?

### Reporting Bugs

This section guides you through submitting a bug report for Vexa. Following these guidelines helps maintainers and the community understand your report, reproduce the behavior, and find related bugs.

Before creating bug reports, please check this list to see if the issue has already been reported. When you are creating a bug report, please include as many details as possible:

* **Use a clear and descriptive title** for the issue to identify the problem.
* **Describe the exact steps which reproduce the problem** in as many details as possible.
* **Describe the behavior you observed after following the steps** and point out what exactly is the problem with that behavior.
* **Explain which behavior you expected to see instead and why.**
* **Include screenshots or logs** if possible.

### Suggesting Enhancements

This section guides you through submitting an enhancement suggestion for Vexa, including completely new features and minor improvements to existing functionality.

* **Use a clear and descriptive title** for the suggestion.
* **Provide a step-by-step description of the suggested enhancement** in as many details as possible.
* **Describe the current behavior and explain which behavior you expected to see instead** and why.

### Your First Code Contribution

Unsure where to begin contributing to Vexa? You can start by looking through these `beginner` and `help-wanted` issues.

#### Local Development Setup

Vexa uses `uv` for workspace management.

1. Clone the repository:
   ```bash
   git clone https://github.com/noviqtechnologies/vexa-oss.git
   cd vexa-oss
   ```

2. Install dependencies:
   ```bash
   uv sync
   ```

3. Run tests:
   ```bash
   pytest
   ```

## Styleguides

### Python Styleguide

We follow PEP 8 and use `ruff` for formatting and linting.

### Commit Messages

* Use the present tense ("Add feature" not "Added feature")
* Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
* Limit the first line to 72 characters or less
* Reference issues and pull requests liberally after the first line
