import tkinter as tk
import zipfile
from tkinter import messagebox, ttk
from selenium import webdriver
from selenium.common import NoSuchElementException
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import os
import requests
import subprocess
import logging

DEFAULT_WAIT_TIME = 5  # Default waiting time in seconds
logging.basicConfig(filename="seleboy.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


def show_help():
    help_text = """
    Functionality Guide:
    --------------------
    - Check Type:
        * title: Check the title of the webpage.
        * element_exists: Check if a specified element exists on the webpage.
        * element_text: Get the text content of a specified element on the webpage.
        * element_click: Click on a specified element on the webpage.
        * element_input: Enter text into a specified input element on the webpage.
        * execute_js: Execute custom JavaScript code on the webpage.
        * login_check: Perform a login check with specified credentials and selectors.

    - Selector Type:
        * id: Select elements by their 'id' attribute.
        * name: Select elements by their 'name' attribute.
        * xpath: Select elements by XPath.
        * css selector: Select elements by CSS selector.
        * class name: Select elements by their class name.
        * tag name: Select elements by their HTML tag name.
        * link text: Select anchor elements by their visible text.
        * partial link text: Select anchor elements by a partial match of their visible text.

    For 'login_check', provide details such as username, password, selectors for username field, password field,
    submit button, and optionally error message selector if you want to check for login errors.

    For other checks, provide the URL, check type, selector type, and selector according to your requirement.
    """
    messagebox.showinfo("Help", help_text)


def get_chrome_version():
    try:
        version_output = subprocess.check_output(
            r'reg query "HKEY_CURRENT_USER\Software\Google\Chrome\BLBeacon" /v version',
            shell=True,
            text=True
        )
        version_line = [line for line in version_output.splitlines() if "version" in line.lower()]
        if version_line:
            version = version_line[0].split()[-1]
            return version
        else:
            return None
    except subprocess.CalledProcessError:
        return None


def save_to_driverlog(version, url):
    with open("driverlog.txt", "w") as f:
        f.write(f"Version: {version}\n")
        f.write(f"Download URL: {url}")


def read_driverlog():
    if os.path.exists("driverlog.txt"):
        with open("driverlog.txt", "r") as f:
            lines = f.readlines()
            if len(lines) >= 2:
                version_line = lines[0].strip()
                version = version_line.split(":")[-1].strip()
                return version
    return None


def download_webdriver(version, driver_download_path):
    saved_version = read_driverlog()
    if saved_version == version:
        return os.path.join(driver_download_path, "chromedriver.exe"), "WebDriver already downloaded."

    url = f"https://storage.googleapis.com/chrome-for-testing-public/{version}/win32/chrome-win32.zip"
    response = requests.get(url, stream=True)
    if response.status_code == 200:
        total_size = int(response.headers.get('content-length', 0))
        downloaded_size = 0
        webdriver_version = response.text.strip()
        webdriver_url = f"https://storage.googleapis.com/chrome-for-testing-public/{version}/win32/chrome-win32.zip"
        with open("temp.zip", "wb") as f:
            for data in response.iter_content(chunk_size=4096):
                f.write(data)
                downloaded_size += len(data)

        save_to_driverlog(version, webdriver_url)
        os.rename("temp.zip", os.path.join(driver_download_path, "chromedriver.zip"))
        with zipfile.ZipFile(os.path.join(driver_download_path, "chromedriver.zip"), 'r') as zip_ref:
            zip_ref.extractall(driver_download_path)
        os.remove(os.path.join(driver_download_path, "chromedriver.zip"))
        return os.path.join(driver_download_path, "chromedriver.exe"), "WebDriver downloaded successfully."
    return None, "Failed to download WebDriver."


def test_webpage_title(driver, url):
    driver.get(url)
    title = driver.title
    return "The Title is " + title


def check_element_exists(driver, url, selector_type, selector):
    driver.get(url)
    try:
        by_type = getattr(By, selector_type.upper())
        element = WebDriverWait(driver, DEFAULT_WAIT_TIME).until(
            EC.presence_of_element_located((by_type, selector))
        )
        result = f"Element with selector '{selector}' exists."
    except:
        result = f"Element with selector '{selector}' does not exist."
    return result


def get_element_text(driver, url, selector_type, selector):
    driver.get(url)
    by_type = getattr(By, selector_type.upper())
    element = driver.find_element(by_type, selector)
    text = element.text
    return text


def click_element(driver, url, selector_type, selector):
    driver.get(url)
    by_type = getattr(By, selector_type.upper())
    element = driver.find_element(by_type, selector)
    element.click()
    WebDriverWait(driver, DEFAULT_WAIT_TIME).until(EC.url_changes(url))
    new_url = driver.current_url
    return f"Element clicked successfully. New URL: '{new_url}'"


def enter_text_in_element(driver, url, selector_type, selector, text):
    driver.get(url)
    by_type = getattr(By, selector_type.upper())
    element = driver.find_element(by_type, selector)
    element.send_keys(text)
    return f"Text '{text}' entered successfully in the element."


def execute_javascript(driver, url, script):
    driver.get(url)
    driver.execute_script(script)
    return "JavaScript executed successfully."


def perform_regular_check(selected_check_type, url, selector_type, selector):
    chrome_version = get_chrome_version()
    if chrome_version:
        download_path = "drivers/chrome"
        os.makedirs(download_path, exist_ok=True)
        webdriver_path, alert_message = download_webdriver(chrome_version, download_path)

        if webdriver_path:
            options = webdriver.ChromeOptions()
            driver = webdriver.Chrome(options=options)

            try:
                if selected_check_type == "title":
                    result = test_webpage_title(driver, url)
                elif selected_check_type == "element_exists":
                    result = check_element_exists(driver, url, selector_type, selector)
                elif selected_check_type == "element_text":
                    result = get_element_text(driver, url, selector_type, selector)
                elif selected_check_type == "element_click":
                    result = click_element(driver, url, selector_type, selector)
                elif selected_check_type == "element_input":
                    text = text_entry.get()
                    result = enter_text_in_element(driver, url, selector_type, selector, text)
                elif selected_check_type == "execute_js":
                    script = script_entry.get()
                    result = execute_javascript(driver, url, script)
                else:
                    raise ValueError("Invalid check type.")
                messagebox.showinfo("Result", result)
                logging.info(result)
            except Exception as e:
                messagebox.showerror("Error", str(e))
                logging.error(f"Error performing check: {e}")
            finally:
                driver.quit()
        else:
            messagebox.showerror("Error", alert_message)
            logging.error(alert_message)
    else:
        messagebox.showerror("Error", "Google Chrome version not found.")
        logging.error("Google Chrome version not found.")


def login_check_function(driver, url, username_value, password_value,
                         username_selector_type, password_selector_type,
                         username_selector_value, password_selector_value,
                         submit_button_selector_type, submit_button_selector_value,
                         check_error_message, error_message_selector_type, error_message_selector_value):
    try:
        # Open the URL
        driver.get(url)

        # Locate the username and password fields using provided selectors
        username_element = driver.find_element(getattr(By, username_selector_type.upper()), username_selector_value)
        password_element = driver.find_element(getattr(By, password_selector_type.upper()), password_selector_value)

        # Enter the username and password values
        username_element.send_keys(username_value)
        password_element.send_keys(password_value)

        # Locate and click the submit button
        submit_button = driver.find_element(getattr(By, submit_button_selector_type.upper()),
                                            submit_button_selector_value)
        submit_button.click()

        # Wait for the page to fully load after clicking the submit button
        WebDriverWait(driver, DEFAULT_WAIT_TIME).until(EC.presence_of_element_located((By.TAG_NAME, "body")))

        # If error message check is enabled
        if check_error_message:
            try:
                # Look for error message element
                error_message_element = driver.find_element(getattr(By, error_message_selector_type.upper()),
                                                            error_message_selector_value)
                # If error message element found, return error message content and XPath
                return f"Error message: '{error_message_element.text}'\nXPath: '{error_message_selector_value}'"
            except NoSuchElementException:
                # If error message element not found, return a message indicating XPath is not present
                return f"Current page URL: {driver.current_url}\nError message XPath '{error_message_selector_value}' is not present."

        # Return previous URL before login and current open URL after successful login
        previous_url = driver.current_url
        return f"Login successful. Previous URL: {previous_url}, Current URL: {driver.current_url}"

    except Exception as e:
        # Handle any exceptions that occur during the login process
        return f"Error during login: {str(e)}"


def perform_login_check():
    url = url_entry.get()
    chrome_version = get_chrome_version()

    if chrome_version:
        download_path = "drivers/chrome"
        os.makedirs(download_path, exist_ok=True)
        webdriver_path, alert_message = download_webdriver(chrome_version, download_path)

        if webdriver_path:
            options = webdriver.ChromeOptions()
            driver = webdriver.Chrome(options=options)

            login_window = tk.Toplevel(app)
            login_window.title("Login Check")

            tk.Label(login_window, text="Username Value:").grid(row=0, column=0, sticky=tk.W)
            username_value_entry = tk.Entry(login_window)
            username_value_entry.grid(row=0, column=1, sticky=tk.W)

            tk.Label(login_window, text="Password Value:").grid(row=1, column=0, sticky=tk.W)
            password_value_entry = tk.Entry(login_window, show="*")
            password_value_entry.grid(row=1, column=1, sticky=tk.W)

            tk.Label(login_window, text="Username Selector Type:").grid(row=2, column=0, sticky=tk.W)
            username_selector_type_var = tk.StringVar()
            username_selector_type_combobox = ttk.Combobox(login_window, textvariable=username_selector_type_var,
                                                           values=[
                                                               "id", "name", "xpath", "css selector", "class name",
                                                               "tag name", "link text", "partial link text"],
                                                           state="readonly")
            username_selector_type_combobox.grid(row=2, column=1, sticky=tk.W)

            tk.Label(login_window, text="Password Selector Type:").grid(row=3, column=0, sticky=tk.W)
            password_selector_type_var = tk.StringVar()
            password_selector_type_combobox = ttk.Combobox(login_window, textvariable=password_selector_type_var,
                                                           values=[
                                                               "id", "name", "xpath", "css selector", "class name",
                                                               "tag name", "link text", "partial link text"],
                                                           state="readonly")
            password_selector_type_combobox.grid(row=3, column=1, sticky=tk.W)

            tk.Label(login_window, text="Username Selector Value:").grid(row=4, column=0, sticky=tk.W)
            username_selector_value_entry = tk.Entry(login_window)
            username_selector_value_entry.grid(row=4, column=1, sticky=tk.W)

            tk.Label(login_window, text="Password Selector Value:").grid(row=5, column=0, sticky=tk.W)
            password_selector_value_entry = tk.Entry(login_window)
            password_selector_value_entry.grid(row=5, column=1, sticky=tk.W)

            tk.Label(login_window, text="Submit Button Selector Type:").grid(row=6, column=0, sticky=tk.W)
            submit_button_selector_type_var = tk.StringVar()
            submit_button_selector_type_combobox = ttk.Combobox(login_window,
                                                                textvariable=submit_button_selector_type_var, values=[
                    "id", "name", "xpath", "css selector", "class name", "tag name", "link text", "partial link text"],
                                                                state="readonly")
            submit_button_selector_type_combobox.grid(row=6, column=1, sticky=tk.W)

            tk.Label(login_window, text="Submit Button Selector Value:").grid(row=7, column=0, sticky=tk.W)
            submit_button_selector_value_entry = tk.Entry(login_window)
            submit_button_selector_value_entry.grid(row=7, column=1, sticky=tk.W)

            error_message_check_var = tk.BooleanVar()
            error_message_check = tk.Checkbutton(login_window, text="Check for Error Message",
                                                 variable=error_message_check_var)
            error_message_check.grid(row=8, columnspan=2)

            tk.Label(login_window, text="Error Message Selector Type:").grid(row=9, column=0, sticky=tk.W)
            error_message_selector_type_var = tk.StringVar()
            error_message_selector_type_combobox = ttk.Combobox(login_window,
                                                                textvariable=error_message_selector_type_var, values=[
                    "id", "name", "xpath", "css selector", "class name", "tag name", "link text", "partial link text"],
                                                                state="readonly")
            error_message_selector_type_combobox.grid(row=9, column=1, sticky=tk.W)

            tk.Label(login_window, text="Error Message Selector Value:").grid(row=10, column=0, sticky=tk.W)
            error_message_selector_value_entry = tk.Entry(login_window)
            error_message_selector_value_entry.grid(row=10, column=1, sticky=tk.W)

            def perform_login():
                username_value = username_value_entry.get()
                password_value = password_value_entry.get()
                username_selector_type = username_selector_type_var.get()
                password_selector_type = password_selector_type_var.get()
                username_selector_value = username_selector_value_entry.get()
                password_selector_value = password_selector_value_entry.get()
                submit_button_selector_type = submit_button_selector_type_var.get()
                submit_button_selector_value = submit_button_selector_value_entry.get()
                check_error_message = error_message_check_var.get()
                error_message_selector_type = error_message_selector_type_var.get()
                error_message_selector_value = error_message_selector_value_entry.get()

                login_result = login_check_function(driver, url, username_value, password_value,
                                                    username_selector_type, password_selector_type,
                                                    username_selector_value, password_selector_value,
                                                    submit_button_selector_type, submit_button_selector_value,
                                                    check_error_message, error_message_selector_type,
                                                    error_message_selector_value)

                messagebox.showinfo("Login Check Result", login_result)
                login_window.destroy()

            tk.Button(login_window, text="Perform Login Check", command=perform_login).grid(row=11, columnspan=2)

        else:
            messagebox.showerror("Error", alert_message)
    else:
        messagebox.showerror("Error", "Google Chrome version not found.")


def perform_check():
    url = url_entry.get()
    selected_check_type = check_type_var.get()

    if not url or not selected_check_type:
        messagebox.showerror("Error", "Please fill in both URL and Check Type fields.")
        return
        # Prepend "http://" if the URL doesn't start with it
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    # Rest of the function remains unchanged
    selector_type = selector_type_var.get()
    selector = selector_entry.get()
    text = text_entry.get()
    script = script_entry.get()

    if selected_check_type == "login_check":
        perform_login_check()
    else:
        perform_regular_check(selected_check_type, url, selector_type, selector)


def update_debugging_info(version):
    debug_info_label.config(text=f"Browser: Google Chrome\nVersion: {version}\nWait Time: {DEFAULT_WAIT_TIME} seconds")


def change_wait_time():
    global DEFAULT_WAIT_TIME
    try:
        DEFAULT_WAIT_TIME = int(wait_time_entry.get())
        messagebox.showinfo("Success", f"Default Wait Time has been changed to {DEFAULT_WAIT_TIME} seconds.")
        update_debugging_info(get_chrome_version())
    except ValueError:
        messagebox.showerror("Error", "Please enter a valid integer value for Default Wait Time.")


def change_chrome_version():
    version = chrome_version_var.get()
    download_path = "drivers/chrome"
    os.makedirs(download_path, exist_ok=True)
    webdriver_path, alert_message = download_webdriver(version, download_path)

    if webdriver_path:
        update_debugging_info(version)
        messagebox.showinfo("Success", "Google Chrome version updated successfully.")
    else:
        messagebox.showerror("Error", alert_message)


app = tk.Tk()
app.title("The SeleBoy: Web Automation Tool")

# Disable window resizing
app.resizable(False, False)

# Fix window size
app.geometry("700x320")

app.grid_columnconfigure(0, weight=1)
app.grid_columnconfigure(1, weight=1)

# Adding border and title to Debugging Info and Settings sections
debugging_frame = tk.LabelFrame(app, text="Debugging Info", padx=10, pady=10, bd=2, relief=tk.GROOVE)
debugging_frame.grid(row=0, column=0, padx=10, pady=10, sticky=tk.W + tk.E)

settings_frame = tk.LabelFrame(app, text="Settings", padx=10, pady=10, bd=2, relief=tk.GROOVE)
settings_frame.grid(row=0, column=1, padx=10, pady=10, sticky=tk.W + tk.E)

# Debugging Info Section
debug_info_label = tk.Label(debugging_frame, text="Debugging Information")
debug_info_label.pack()

# Settings Section
chrome_version_label = tk.Label(settings_frame, text="Chrome Version:")
chrome_version_label.grid(row=0, column=0, sticky=tk.W)
chrome_version_var = tk.StringVar()
chrome_version_entry = tk.Entry(settings_frame, textvariable=chrome_version_var)
chrome_version_entry.grid(row=0, column=1)

chrome_version_button = tk.Button(settings_frame, text="Update Chrome Version", command=change_chrome_version)
chrome_version_button.grid(row=0, column=2, padx=5)

wait_time_label = tk.Label(settings_frame, text="Default Wait Time (in seconds):")
wait_time_label.grid(row=1, column=0, sticky=tk.W)
wait_time_entry = tk.Entry(settings_frame)
wait_time_entry.grid(row=1, column=1)

wait_time_button = tk.Button(settings_frame, text="Change Wait Time", command=change_wait_time)
wait_time_button.grid(row=1, column=2, padx=5)

# SeleBoy Section
seleboy_frame = tk.LabelFrame(app, text="SeleBoy by rS", padx=10, pady=10, bd=2, relief=tk.GROOVE)
seleboy_frame.grid(row=1, column=0, columnspan=2, padx=10, pady=10, sticky=tk.W + tk.E)

# Main Section within SeleBoy
url_label = tk.Label(seleboy_frame, text="URL:")
url_label.grid(row=0, column=0, sticky=tk.W)
url_entry = tk.Entry(seleboy_frame)
url_entry.grid(row=0, column=1)

check_type_label = tk.Label(seleboy_frame, text="Check Type:")
check_type_label.grid(row=1, column=0, sticky=tk.W)
check_type_var = tk.StringVar()
check_type_combobox = ttk.Combobox(seleboy_frame, textvariable=check_type_var,
                                   values=["title", "element_exists", "element_text", "element_click",
                                           "element_input", "execute_js", "login_check"],
                                   state="readonly")
check_type_combobox.grid(row=1, column=1)

selector_type_label = tk.Label(seleboy_frame, text="Selector Type:")
selector_type_label.grid(row=2, column=0, sticky=tk.W)
selector_type_var = tk.StringVar()
selector_type_combobox = ttk.Combobox(seleboy_frame, textvariable=selector_type_var,
                                      values=["id", "name", "xpath", "css selector", "class name",
                                              "tag name", "link text", "partial link text"],
                                      state="readonly")
selector_type_combobox.grid(row=2, column=1)

selector_label = tk.Label(seleboy_frame, text="Selector:")
selector_label.grid(row=3, column=0, sticky=tk.W)
selector_entry = tk.Entry(seleboy_frame)
selector_entry.grid(row=3, column=1)

text_label = tk.Label(seleboy_frame, text="Text (for 'element_input' check):")
text_label.grid(row=4, column=0, sticky=tk.W)
text_entry = tk.Entry(seleboy_frame)
text_entry.grid(row=4, column=1)

script_label = tk.Label(seleboy_frame, text="Script (for 'execute_js' check):")
script_label.grid(row=5, column=0, sticky=tk.W)
script_entry = tk.Entry(seleboy_frame)
script_entry.grid(row=5, column=1)

# Adjust buttons to be placed beside the last two input fields
check_button = tk.Button(seleboy_frame, text="Perform Check", command=perform_check, bg="#4CAF50", fg="white", width=15,
                         height=2)
check_button.grid(row=1, column=2, rowspan=2, padx=100, pady=5)

help_button = tk.Button(seleboy_frame, text="Help", command=show_help, bg="#2706FF", fg="white", width=15,
                        height=2)
help_button.grid(row=3, column=2, padx=100, pady=5, rowspan=2)
update_debugging_info(get_chrome_version())

app.mainloop()
