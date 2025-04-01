# sysadmin_scripts
Here, I store Bash and Python scripts that help automate manual tasks for beginner system administrators.
## Structure
- `00_education` - is my working directory where I experiment with new concepts and Bash syntax using examples
- `01_cve_check` - is a directory for scripts designed to evaluate pending package upgrades based on their CVE scores
  - `check_security_updates_basic.sh` 
    - A basic script that prints pending security updates to syslog (and to stdout when the [-v] option is used). 
    - **Usage** `bash check_security_updates_basic.sh [-v]` 
  - `check_security_updates_advanced.sh` 
    - A more robust script that does everything the basic script does, but also scans the pending upgrade changelog, fetches CVE numbers, and retrieves CVE scores from NVD.
    - Majority of code in this script was written by Gemini 2.5, but I consider it bloated and overwhelming
    - **Usage** `bash check_security_updates_advanced.sh`
  - `check_security_updates_superior.py`
    - The most powerful script, which does everything the advanced script does, but also provides structured output and caching to reduce the number of requests sent to the NVD API.
    - **Usage** `python3 check_security_updates_superior.py`