import os
import urllib.request
import platform
import getpass

UNSAFE_JS_KEYWORDS = [
    "eval(", "new Function(", "chrome.runtime.sendMessage(",
    "chrome.tabs.executeScript(", "document.write(", "atob(",
    "btoa(", "XMLHttpRequest(", "fetch(", "WebSocket(",
    "setTimeout(", "setInterval(", "navigator.clipboard",
    "innerHTML", "outerHTML", "localStorage.setItem(",
    "sessionStorage.setItem(", "indexedDB.open(", "function anonymous"
]

my_dictionary = dict()

pathchar = '/'

def get_browser_basepath(browser):
    user = getpass.getuser()
    os_platform = platform.system().lower()
    browser = browser.lower()

    if os_platform == "windows":
        base_path = {
            "chrome": f"C:\\Users\\{user}\\AppData\\Local\\Google\\Chrome\\User Data",
            "edge": f"C:\\Users\\{user}\\AppData\\Local\\Microsoft\\Edge\\User Data",
            "brave": f"C:\\Users\\{user}\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data",
            "opera": f"C:\\Users\\{user}\\AppData\\Roaming\\Opera Software\\Opera Stable",
        }
        global pathchar
        pathchar = '\\'
    elif os_platform == "linux":
        base_path = {
            "chrome": f"/home/{user}/.config/google-chrome",
            "edge": f"/home/{user}/.config/microsoft-edge",
            "brave": f"/home/{user}/.config/BraveSoftware/Brave-Browser",
            "opera": f"/home/{user}/.config/opera",
        }
    elif os_platform == "darwin":
        base_path = {
            "chrome": f"/Users/{user}/Library/Application Support/Google/Chrome",
            "edge": f"/Users/{user}/Library/Application Support/Microsoft Edge",
            "brave": f"/Users/{user}/Library/Application Support/BraveSoftware/Brave-Browser",
            "opera": f"/Users/{user}/Library/Application Support/com.operasoftware.Opera",
        }
    else:
        return []

    return base_path.get(browser, [])

def id_to_name(ext_id):
    url = "https://chrome.google.com/webstore/detail/" + ext_id
    try:
        contents = urllib.request.urlopen(url).read().decode("utf-8")
        index = contents.find("class=\"Pa2dE\"")
        name = ext_id
        img = "N/A"
        if index != -1:
            name = contents[index:]
            name = name[name.find(">") + 1:]
            name = name[:name.find("<")]
            img_index = contents.find("class=\"KgGEHd\"")
            if img_index != -1:
                img = contents[img_index:]
                img = img[img.find(">") + 1:]
                img = img[img.find("\"") + 1:]
                img = img[:img.find("\"")]
        return name, img
    except:
        return ext_id, "N/A"

def file_checker(filepath):
    try:
        with open(filepath, 'r', errors="ignore") as file:
            text = file.read()
    except Exception:
        return

    # Extract extension and relative file path info
    trunc_path = filepath[:filepath.find("Extensions") - 1]
    profile = trunc_path[trunc_path.rfind(pathchar) + 1:]
    trunc_path = filepath[filepath.find("Extensions"):]
    trunc_path = trunc_path[trunc_path.find(pathchar) + 1:]
    ext_id = trunc_path[:trunc_path.find(pathchar)]
    trunc_path = filepath[filepath.find(ext_id):]
    trunc_path = trunc_path[trunc_path.find(pathchar) + 1:]

    if ext_id not in my_dictionary:
        my_dictionary[ext_id] = {
            "csp": [False, set()],
            "tabs": [False, set()],
            "all_urls": [False, set()],
            "webrequestblocking": [False, set()],
            "declarativenetrequest": [False, set()],
            "clipboardread": [False, set()],
            "unsafe_keywords": [False, set()],
        }

    csp_keywords = ["content-security-policy", "content-security-policy-report-only", "x-webkit-csp"]
    if any(keyword in text for keyword in csp_keywords):
        my_dictionary[ext_id]["csp"][0] = True
        my_dictionary[ext_id]["csp"][1].add(trunc_path)

    if filepath.endswith("manifest.json"):
        if "tabs" in text:
            my_dictionary[ext_id]["tabs"][0] = True
            my_dictionary[ext_id]["tabs"][1].add(trunc_path)
        if "<all_urls>" in text:
            my_dictionary[ext_id]["all_urls"][0] = True
            my_dictionary[ext_id]["all_urls"][1].add(trunc_path)
        if "webRequestBlocking" in text:
            my_dictionary[ext_id]["webrequestblocking"][0] = True
            my_dictionary[ext_id]["webrequestblocking"][1].add(trunc_path)
        if "declarativeNetRequest" in text:
            my_dictionary[ext_id]["declarativenetrequest"][0] = True
            my_dictionary[ext_id]["declarativenetrequest"][1].add(trunc_path)
        if "clipboardRead" in text:
            my_dictionary[ext_id]["clipboardread"][0] = True
            my_dictionary[ext_id]["clipboardread"][1].add(trunc_path)

    for keyword in UNSAFE_JS_KEYWORDS:
        if keyword in text:
            my_dictionary[ext_id]["unsafe_keywords"][0] = True
            my_dictionary[ext_id]["unsafe_keywords"][1].add((trunc_path, keyword))

def analyze_entry(entry_dict):
    score = 0
    if entry_dict["csp"][0]:
        score += 8
    if (entry_dict["webrequestblocking"][0] or entry_dict["declarativenetrequest"][0]) and entry_dict["all_urls"][0]:
        score += 3
    elif entry_dict["webrequestblocking"][0]:
        score += 1
    elif entry_dict["declarativenetrequest"][0]:
        score += 1
    if entry_dict["clipboardread"][0]:
        score += 2
    if entry_dict["tabs"][0]:
        score += 1
    if entry_dict["unsafe_keywords"][0]:
        unique_keywords = {kw for _, kw in entry_dict["unsafe_keywords"][1]}
        score += min(len(unique_keywords), 3)
    return score

def search_os_walk(directory):
    return [os.path.join(root, file) for root, _, files in os.walk(directory) for file in files]

def find_subdirs(base_path):
    if not os.path.exists(base_path):
        return []
    return [f.path for f in os.scandir(base_path) if f.is_dir()]

def filter_dirs(subdirs):
    return [os.path.join(path, "Extensions") for path in subdirs
            if os.path.basename(os.path.normpath(path)) in ["Default"] or
            os.path.basename(os.path.normpath(path)).startswith("Profile ")]

def main():
    browser_types = ["Chrome", "Edge", "Brave", "Opera"]
    verbose = False
    summary = []
    for browser in browser_types:
        base_path = get_browser_basepath(browser)
        subdirs = find_subdirs(base_path)
        directories = filter_dirs(subdirs)

        for directory in directories:
            profile = directory[:directory.find("Extensions") - 1]
            profile = profile[profile.rfind(pathchar) + 1:]
            print(f"  Now checking {browser} profile: {profile}...\n")

            for ext_id in next(os.walk(directory))[1]:

                if ext_id == "Temp": continue

                name, img = id_to_name(ext_id)
                print(f"  Checking extension: {name}...\n")

                ext_dir = os.path.join(directory, ext_id)
                versions = os.listdir(os.path.join(directory, ext_id))
                latest = os.path.join(ext_dir, sorted(versions)[-1])

                files = search_os_walk(latest)
                for file in files:
                    file_checker(file)

                if ext_id not in my_dictionary:
                    continue

                entry = my_dictionary[ext_id]
                if any(entry[key][0] for key in entry):
                    print(f"   FOUND ISSUES IN EXTENSION: {name}")
                    print(f"   Browser: {browser}, Profile: {profile}")
                    print(f"   Image URL: {img}")
                    score = analyze_entry(entry)
                    print(f"   Risk Score: {score}\n")
                    summary.append([score, name])

                    for key, (present, locations) in entry.items():
                        if present:
                            print(f"\t{key} found in:")
                            ukcount = 0
                            count = 0

                            for item in locations:
                                if isinstance(item, tuple):
                                    if verbose:
                                        print(f"\t\t{item[0]} – keyword: \"{item[1]}\"")
                                    else:
                                        ukcount += 1
                                else:
                                    if verbose:
                                        print(f"\t\t{item}")
                                    else:
                                        count += 1
                            if not verbose and key == "unsafe_keywords":
                                print(f"\t\tFound in {ukcount} places")
                            if not verbose and key != "unsafe_keywords":
                                print(f"\t\tFound in {count} places")
                            print()
                    print("-" * 60 + "\n")
    print(f"\n\nSUMMARY:\n")
    summary.sort(reverse=True)
    for entry in summary:
        print(f"{entry[1]}: Risk Score: {entry[0]}")

main()