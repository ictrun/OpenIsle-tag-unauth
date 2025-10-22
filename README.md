# OpenIsle Tags Unauthorized Modification/Deletion

**Severity:** MEDIUM (Base CVSS 6.5) / HIGH (Environmental ~8.5 with DIRECT mode)

### Summary
A privilege escalation vulnerability in OpenIsle backend allows **authenticated regular users to perform administrative operations** on tag resources. Any logged-in user can modify arbitrary tags via PUT /api/tags/{id}, despite tag management being restricted to administrators. The vulnerability exists due to missing HTTP PUT method authorization in Spring Security configuration. Given OpenIsle's open registration system (DIRECT mode), attackers can obtain user credentials in under 30 seconds, making this a **high-severity privilege escalation** with near-zero authentication barrier in typical deployments.

### Technical Description

The vulnerability is caused by incomplete privilege enforcement in Spring Security configuration:

**Root Cause - Missing PUT Method Authorization:**
The Spring Security configuration in `SecurityConfig.java` properly restricts POST and DELETE operations to ADMIN role, but **completely omits PUT method configuration**:

```java
// SecurityConfig.java (Current Configuration)
.requestMatchers(HttpMethod.POST, "/api/tags/**").authenticated()     // ⚠️ Any authenticated user!
.requestMatchers(HttpMethod.DELETE, "/api/tags/**").hasAuthority("ADMIN")  // ✓ Correct

// PUT method is NOT configured, falls through to:
.anyRequest().authenticated()  // ⚠️ Any authenticated user can PUT!

// Should be:
.requestMatchers(HttpMethod.PUT, "/api/tags/**").hasAuthority("ADMIN")  // ❌ MISSING
```

**Security Configuration Analysis:**

| HTTP Method | Current Rule | Required Privilege | Actual Behavior | Vulnerable? |
|-------------|-------------|-------------------|----------------|-------------|
| GET | `.permitAll()` | None | ✓ Public access | No |
| POST | `.authenticated()` | Any user | ✓ Any user can create tags | No (intended feature) |
| PUT | *Not configured* | Falls to `.anyRequest().authenticated()` | ⚠️ **Any user can modify ANY tag** | **YES - HIGH** |
| DELETE | `.hasAuthority("ADMIN")` | Admin only | ✓ Admin required | No |

**Note:** POST allows any authenticated user to create tags - this is **intended business logic** for collaborative tagging. The vulnerability is that users can modify tags created by others via PUT.

**Defense-in-Depth Failure:**
The `TagController.java` also lacks security annotations, creating a single point of failure:

```java
// TagController.java:75-85 (Vulnerable Code)
@PutMapping("/{id}")
// Missing: @PreAuthorize("hasAuthority('ADMIN')")
public TagDto update(@PathVariable Long id, @RequestBody TagRequest req) {
    Tag tag = tagService.updateTag(id, req.getName(), ...);
    return tagMapper.toDto(tag, count);
}
```

**Registration Mode Context:**
OpenIsle supports two registration modes (enum `RegisterMode`):

```java
DIRECT    → user.setApproved(true)   // Auto-approve, immediate access
WHITELIST → user.setApproved(false)  // Requires admin review
```

In DIRECT mode (common default), an attacker can:
1. Register via `/api/auth/register` (< 30 seconds)
2. Receive JWT token immediately
3. Execute PUT requests with regular user token
4. Modify arbitrary administrative resources

### Affected Endpoints
- `PUT /api/tags/{id}` - **Privilege escalation: Regular user can modify ANY tag (including tags created by others or admins)**

## Proof of Concept

<img width="991" height="454" alt="image" src="https://github.com/user-attachments/assets/7ed30dbf-4386-4624-8dde-06d000f04176" />

<img width="1000" height="458" alt="image" src="https://github.com/user-attachments/assets/f9f57ac4-b6f9-45da-ac5b-bfaf0a57cfe1" />

<img width="325" height="165" alt="image" src="https://github.com/user-attachments/assets/a8b67eb0-2fd8-437e-98bb-a3c4ab0799c5" />
