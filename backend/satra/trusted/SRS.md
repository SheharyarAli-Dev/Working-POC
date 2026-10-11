# Invoice API security requirements (trusted)

This document is the human-readable authority for the SATRA trusted policy. It lives in Working-POC and is never read from the repository under analysis.

- **SRS-01 Object-level authorization.** A user may read an invoice only if they own it. A user with the admin role may read any invoice. A request by any other authenticated user is answered with HTTP 403 and discloses nothing about the invoice. (`POL-INV-READ`, CWE-639)
- **SRS-02 Authentication on state change.** Creating an invoice requires a valid bearer token. A request without one is answered with HTTP 401 and changes no stored data. (`POL-INV-CREATE`, CWE-306)
- **SRS-03 Parameterized queries.** Every SQL statement that incorporates request data must bind that data as a parameter. Search text such as `' OR 1=1 --` is treated as literal text, returns only the caller's own invoices and never causes a database error. (`POL-INV-SEARCH`, CWE-89)
- **SRS-04 Path containment.** Files are served only from the uploads directory. Requests containing dot-dot segments or absolute paths must not return any file outside that directory. (`POL-FILE-READ`, CWE-22)
- **SRS-05 Tests are evidence, not authority.** A repository's own tests never redefine what is secure. Weakening a security assertion is reported as a test-oracle weakness.
