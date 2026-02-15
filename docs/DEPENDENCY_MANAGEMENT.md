# Dependency Management Guide

## Overview

This project uses flexible versioning to balance stability with access to updates.

## Version Notation Explained

### NPM (package.json)
- `^2.1.1` - Allows updates to `2.x.x` (minor and patch updates)
- `~2.1.1` - Allows updates to `2.1.x` (patch updates only)
- `2.1.1` - Exact version (no updates)
- `latest` - Always use the latest version (risky)

### Python (requirements.txt)
- `>=2.6.0,<3.0.0` - Allows updates within major version 2
- `~=2.6.0` - Equivalent to `>=2.6.0,<2.7.0`
- `==2.6.0` - Exact version (no updates)
- `>=2.6.0` - Any version 2.6.0 or higher (very flexible)

## Current Strategy

### Frontend (NPM)
All dependencies use `^` notation, which allows:
- ✅ Patch updates (bug fixes): `2.1.1` → `2.1.2`
- ✅ Minor updates (new features): `2.1.1` → `2.2.0`
- ❌ Major updates (breaking changes): `2.1.1` ↛ `3.0.0`

### Backend (Python)
Dependencies use range notation (`>=x.y.z,<major+1.0.0`), which:
- ✅ Allows minor and patch updates
- ❌ Prevents major version updates
- ✅ Ensures compatibility

## Updating Dependencies

### Update to Latest Compatible Versions

**Frontend:**
```bash
# Check for outdated packages
npm outdated

# Update all packages within semver ranges
npm update

# Update to latest (including major versions) - use with caution
npm install <package>@latest
```

**Backend:**
```bash
# Check for outdated packages
pip list --outdated

# Update all packages to latest compatible versions
pip install --upgrade -r requirements.txt

# Update specific package to latest
pip install --upgrade <package>
```

### Update to Absolute Latest (Breaking Changes Possible)

**Frontend:**
```bash
# Update all dependencies to latest versions
npm install -g npm-check-updates
ncu -u
npm install
```

**Backend:**
```bash
# Update to latest versions (manually edit requirements.txt)
# Then run:
pip install --upgrade -r requirements.txt
```

## Testing After Updates

Always test after updating dependencies:

```bash
# Frontend tests
npm run lint
npm run build

# Backend tests
cd backend
pytest
python -m uvicorn app.main:app --reload --port 8000
```

## Recommended Update Schedule

- **Security patches**: Immediately
- **Patch updates**: Weekly or bi-weekly
- **Minor updates**: Monthly
- **Major updates**: Quarterly (with thorough testing)

## Pinning Versions for Production

For production deployments, consider using exact versions:

**Create lock files:**
```bash
# Frontend (already done automatically)
package-lock.json

# Backend
pip freeze > requirements-lock.txt
```

## Current Versions (as of last update)

### Frontend
- React: ^19.2.0
- Vite: ^7.2.4
- TailwindCSS: ^3.4.19
- Mermaid: ^11.12.2

### Backend
- FastAPI: >=0.115.0,<1.0.0
- Uvicorn: >=0.34.0,<1.0.0
- NetworkX: >=3.4.0,<4.0.0
- Pydantic: >=2.6.0,<3.0.0

## Security Considerations

### Automated Security Updates

**NPM:**
```bash
# Check for vulnerabilities
npm audit

# Fix vulnerabilities automatically
npm audit fix

# Force fix (may include breaking changes)
npm audit fix --force
```

**Python:**
```bash
# Install safety to check for vulnerabilities
pip install safety

# Check for known security issues
safety check
```

### Dependabot (GitHub)

Enable Dependabot in your repository to automatically:
- Detect outdated dependencies
- Create pull requests for updates
- Flag security vulnerabilities

## Best Practices

1. **Read changelogs** before major updates
2. **Test thoroughly** after any update
3. **Update regularly** to avoid falling too far behind
4. **Use lock files** in production
5. **Monitor security advisories** for your dependencies
6. **Keep CI/CD updated** to catch breaking changes early

## Quick Commands

```bash
# Update everything (safe)
npm update && cd backend && pip install --upgrade -r requirements.txt && cd ..

# Check what would be updated
npm outdated && cd backend && pip list --outdated && cd ..

# Full upgrade to latest (use with caution)
ncu -u && npm install && cd backend && pip install --upgrade -r requirements.txt && cd ..
```
