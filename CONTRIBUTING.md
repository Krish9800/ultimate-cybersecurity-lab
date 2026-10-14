# Contributing to Ultimate Cybersecurity Lab

Thank you for your interest in contributing to the **Ultimate Cybersecurity Lab**!

## Development Guidelines

1. **Python Quality**:
   - Modern Python 3.12+ idioms.
   - 100% strict type hints enforced via `mypy --strict`.
   - PEP 8 compliance via `ruff format` and `ruff check` (maximum line length: 100).
   - Security audit verification via `bandit -r src/`.
2. **Testing**:
   - Every new feature, scenario, or engine component must include comprehensive unit and integration tests.
   - Code coverage must meet or exceed **90%** (`pytest --cov=src/cyberlab --cov-fail-under=90`).
3. **Commit Conventions**:
   - Use Conventional Commits:
     - `feat(...)`: New features
     - `fix(...)`: Bug fixes
     - `test(...)`: Test additions or improvements
     - `docs(...)`: Documentation updates
     - `chore(...)`: Maintenance and dependency updates

## Pull Request Checklist

- [ ] `ruff format --check .` passes
- [ ] `ruff check .` passes
- [ ] `mypy --strict src tests` reports 0 errors
- [ ] `bandit -r src/` reports 0 issues
- [ ] `pytest --cov=src/cyberlab --cov-fail-under=90` passes with $\ge 90\%$ coverage
