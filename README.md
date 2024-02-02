Drupal Username Enumeration Tool

Overview:

This tool is designed for enumerating usernames on websites running Drupal CMS that are vulnerable to username information disclosure. It uses a technique that takes advantage of a specific Drupal endpoint to retrieve usernames. The script supports scanning a single URL or multiple URLs concurrently.


Features:

Username Enumeration: Discovers usernames on Drupal websites vulnerable to information disclosure.

Multithreading: Concurrently scans multiple URLs for faster results.

Timeouts: Includes a timeout of 10 seconds for each request to improve efficiency.

Progress Bar: Displays a progress bar during the username scanning process.

Result Summary: Provides a summary of the results after scanning.

Network Status Check: Verifies the network status by attempting requests.

Vulnerability Details:

This tool exploits a vulnerability in Drupal's Views module, leading to username enumeration. The Views module, in certain versions, contains an information disclosure vulnerability that allows unauthorized access to user profile data. This tool leverages the vulnerability to expose actual usernames, including the Drupal super user account (id 1) and other accounts that might not be publicly visible. It's crucial to use this tool responsibly and only on systems with explicit permission.

Vulnerability Patch:

The Views module's vulnerability affects Drupal 6.16 with Views 6.x-2.9, 6.x-2.10, and 6.x-2.11. The impact includes information disclosure, potentially enabling malicious actors to harvest usernames for targeted attacks. Mitigating factors include the requirement for "Access content" permission, usually granted to anonymous users. The recommended mitigation involves applying a patch to the Views module. The provided patch addresses the access controls in the views_ajax_autocomplete_user() function, helping secure Drupal 6.16 with Views 6.x-2.8.

Usage:

Single URL Scan:

python drupal_enum.py -u example.com -s result.txt

Single URL Scan with proxy option:

python drupal_enum.py -u example.com -p 127.0.0.1:8080 -s results.txt

Multiple URLs Scan from a List:

python drupal_enum.py -l url_list.txt -p 127.0.0.1:8080 -s results.txt

Multiple URLs Scan from a List with proxy option:

python drupal_enum.py -l url_list.txt -p 127.0.0.1:8080 -s results.txt

Installation

pip install -r requirements.txt

Contributions

Contributions and suggestions are welcome! Feel free to fork the repository, open issues, or submit pull requests to enhance the tool.

Disclaimer

This tool is for educational purposes only. Use it responsibly and with proper authorization.
