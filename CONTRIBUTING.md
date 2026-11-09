# Contributing to SentinelAI

Thank you for your interest in contributing to SentinelAI! We welcome community contributions, bug fixes, performance improvements, and documentation enhancements.

---

## Code of Conduct

All contributors and participants are expected to adhere to our [Code of Conduct](CODE_OF_CONDUCT.md).

---

## Getting Started

### 1. Prerequisites
- Python 3.11, 3.12, or 3.13
- Git
- (Optional) Local Ollama instance for live proxy testing

### 2. Fork and Clone
```bash
git clone https://github.com/your-username/SentinelAI.git
cd SentinelAI
```

### 3. Setup Virtual Environment
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### 4. Configure Environment
```bash
cp .env.example .env
```

---

## Development Workflow

1. **Create a Feature Branch**:
   ```bash
   git checkout -b feat/your-feature-name
   ```
2. **Make Changes with Care**:
   - Adhere to PEP 8 standards and modern type annotations (`typing`, Pydantic models).
   - Ensure zero hardcoded credentials, API keys, or raw secrets are introduced.
   - Maintain defense-in-depth boundaries without breaking streaming or provider routing.
3. **Run the Test Suite**:
   ```bash
   pytest -v
   ```
   All existing and newly added tests must pass.
4. **Commit Convention**:
   We follow [Conventional Commits](https://www.conventionalcommits.org/):
   - `feat(...)`: New feature or protection rule
   - `fix(...)`: Bug fix or false positive remediation
   - `docs(...)`: Documentation updates
   - `test(...)`: Test additions or test refactoring
   - `chore(...)`: Maintenance or dependency updates

---

## Pull Request Guidelines

1. Ensure all tests pass locally.
2. Include unit or integration tests for any new threat detection rules or endpoints.
3. Update relevant documentation in `README.md` if adding or changing configuration options.
4. Fill out the [Pull Request Template](.github/pull_request_template.md).
5. Maintainers will review and provide feedback.
