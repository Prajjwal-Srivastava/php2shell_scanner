# php2shell_scanner
Scans a PHP host for CVE-2026-109619 (php2shell): fingerprints it, compares PHP version and build date against fixed releases, checks the advisory's producer and consumer preconditions, then prints a VULNERABLE, NOT VULNERABLE or UNKNOWN verdict with the evidence behind it.
