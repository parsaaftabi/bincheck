# Security policy

## Reporting a problem

Report security problems privately through GitHub. Open the Security tab
of this repository and choose "Report a vulnerability" to file a private
security advisory. Do not open a public issue for a security problem.

Include the bincheck version, the operating system, and a sample file or
the steps that trigger the problem when you can.

## Scope

bincheck parses untrusted binary files, so parser crashes and out-of-bounds
reads count as security problems. Wrong verdicts on well-formed files are
regular bugs and belong in public issues.

## Supported versions

Only the latest release receives security fixes.
