# Contributing to ClawGuard (openclaw-security)

Thank you for your interest in contributing! This document provides guidelines for contributing to the project.

## How to Contribute

### 1. Fork the Repository

1. Click the "Fork" button on [github.com/moltpill/openclaw-security](https://github.com/moltpill/openclaw-security)
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR-USERNAME/openclaw-security.git
   cd openclaw-security
   ```
3. Add the upstream remote:
   ```bash
   git remote add upstream https://github.com/moltpill/openclaw-security.git
   ```

### 2. Create a Feature Branch

```bash
git checkout -b feature/your-feature-name
```

Use descriptive branch names:
- `feature/add-authentication`
- `fix/memory-leak`
- `docs/update-readme`

### 3. Make Your Changes

- Write clear, readable code
- Follow existing code style and conventions
- Add comments for complex logic
- Update documentation if needed

### 4. Test Your Changes

- Ensure existing tests pass
- Add tests for new functionality
- Test edge cases

```bash
# Run tests (adjust based on project setup)
npm test  # or pytest, cargo test, etc.
```

### 5. Commit Your Changes

Write clear commit messages:

```bash
git commit -m "feat: add user authentication module

- Implement JWT token validation
- Add session management
- Include unit tests"
```

Follow [Conventional Commits](https://www.conventionalcommits.org/) when possible:
- `feat:` new features
- `fix:` bug fixes
- `docs:` documentation changes
- `test:` test additions/changes
- `refactor:` code refactoring

### 6. Submit a Pull Request

1. Push your branch:
   ```bash
   git push origin feature/your-feature-name
   ```
2. Open a Pull Request on GitHub
3. Fill out the PR template (if provided)
4. Link any related issues

## Code Style Guidelines

- **Consistency**: Match the existing code style
- **Clarity**: Write self-documenting code with clear variable/function names
- **Comments**: Explain *why*, not *what* (the code shows what)
- **Security**: Follow security best practices—this is a security project!

## Pull Request Requirements

All PRs must:

1. **Pass CI checks** (if configured)
2. **Be reviewed by a code owner** before merging
3. **Have a clear description** of changes
4. **Not break existing functionality**

Note: Direct pushes to `main` are not allowed. All changes must go through PR review.

## Security Considerations

Since this is a security-focused project:

- Never commit secrets, API keys, or credentials
- Report security vulnerabilities privately (see SECURITY.md)
- Follow secure coding practices
- Consider attack vectors in your changes

## Questions?

Open an issue for questions or discussions about potential contributions.

---

Thank you for helping make ClawGuard better! 🛡️
