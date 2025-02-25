import csv
import tkinter as tk
import zipfile
from tkinter import messagebox, ttk, filedialog, simpledialog
from selenium import webdriver
from selenium.common import NoSuchElementException
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import os
import requests
import subprocess
import logging
from PIL import Image, ImageDraw, ImageTk, ImageFont

DEFAULT_WAIT_TIME = 5  # Default waiting time in seconds
local_app_data = os.getenv('LOCALAPPDATA')
log_folder = os.path.join(local_app_data, 'SeleBoy')
os.makedirs(log_folder, exist_ok=True)
log_file = os.path.join(log_folder, 'seleboy.log')

logging.basicConfig(filename=log_file, level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")


def check_driver_status():
    filename = "chrome.exe"
    local_app_data = os.getenv('LOCALAPPDATA')
    file_path = os.path.join(local_app_data, 'SeleBoy', "drivers", "chrome", "chrome-win32", filename)
    if os.path.isfile(file_path):
        return "OK"
    else:
        return "WebDriver Download Required !"


def driver_path():
    filename = "chrome.exe"
    try:
        local_app_data = os.getenv('LOCALAPPDATA')

        file_path = os.path.join(local_app_data, 'SeleBoy', "drivers", "chrome", "chrome-win32", filename)

        if not os.path.exists(file_path):
            raise FileNotFoundError(f"The WebDriver {filename} does not exist in {file_path}")

        return f"WebDriver Path: {file_path}"

    except Exception as e:
        return e


def log_file():
    filename = "seleboy.log"
    try:
        local_app_data = os.getenv('LOCALAPPDATA')

        file_path = os.path.join(local_app_data, 'SeleBoy', filename)

        if not os.path.exists(file_path):
            raise FileNotFoundError(f"The file {filename} does not exist in {file_path}")

        # Open the file
        os.startfile(file_path)

    except Exception as e:
        print(f"An error occurred: {e}")
        messagebox.showerror("Error", f"An error occurred: {e}")


def show_help():
    update_debugging_info(get_chrome_version())
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
    
    Created by github.com/rohit290554
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
    filename = "seleboyDriver.log"
    local_app_data = os.getenv('LOCALAPPDATA')
    file_path = os.path.join(local_app_data, 'SeleBoy', filename)
    print(file_path)
    with open(file_path, "w") as f:
        f.write(f"Version: {version}\n")
        f.write(f"Download URL: {url}")


def read_driverlog():
    filename = "seleboyDriver.log"
    local_app_data = os.getenv('LOCALAPPDATA')
    file_path = os.path.join(local_app_data, 'SeleBoy', filename)
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            lines = f.readlines()
            if len(lines) >= 2:
                version_line = lines[0].strip()
                version = version_line.split(":")[-1].strip()
                return version
    return None


def download_webdriver(version, driver_download_path):
    saved_version = read_driverlog()  # Assuming this function reads the saved version from a log file
    if saved_version == version:
        return os.path.join(driver_download_path, "chromedriver.exe"), "WebDriver already downloaded."

    url = f"https://storage.googleapis.com/chrome-for-testing-public/{version}/win32/chrome-win32.zip"
    response = requests.get(url, stream=True)

    if response.status_code == 200:
        total_size = int(response.headers.get('content-length', 0))
        downloaded_size = 0
        webdriver_url = url  # Store the exact URL for logging purposes

        # Download the file in chunks and save it as temp.zip
        temp_zip_path = os.path.join(driver_download_path, "temp.zip")
        with open(temp_zip_path, "wb") as f:
            for data in response.iter_content(chunk_size=4096):
                f.write(data)
                downloaded_size += len(data)

        # Log the version and URL to the driver log
        save_to_driverlog(version, webdriver_url)

        # Extract the downloaded zip file
        try:
            with zipfile.ZipFile(temp_zip_path, 'r') as zip_ref:
                zip_ref.extractall(driver_download_path)
        except Exception as e:
            return None, f"Failed to extract WebDriver zip file: {str(e)}"

        # Remove the temporary zip file
        os.remove(temp_zip_path)

        # Return the path to the downloaded WebDriver executable
        return os.path.join(driver_download_path, "chromedriver.exe"), "WebDriver downloaded successfully."

    else:
        return None, f"Failed to download WebDriver. Status code: {response.status_code}"


def test_webpage_title(driver, url):
    update_debugging_info(get_chrome_version())
    driver.get(url)
    title = driver.title
    return "The Title is " + title


def check_element_exists(driver, url, selector_type, selector):
    update_debugging_info(get_chrome_version())
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
    update_debugging_info(get_chrome_version())
    driver.get(url)
    by_type = getattr(By, selector_type.upper())
    element = driver.find_element(by_type, selector)
    text = element.text
    return text


def click_element(driver, url, selector_type, selector):
    update_debugging_info(get_chrome_version())
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
    update_debugging_info(get_chrome_version())
    chrome_version = get_chrome_version()
    if chrome_version:
        local_app_data = os.getenv('LOCALAPPDATA')
        download_path = os.path.join(local_app_data, "SeleBoy", "drivers", "chrome")
        os.makedirs(download_path, exist_ok=True)
        webdriver_path, alert_message = download_webdriver(chrome_version, download_path)

        if webdriver_path:
            options = webdriver.ChromeOptions()
            driver = webdriver.Chrome(options=options)

            try:
                if selected_check_type == "Title":
                    result = test_webpage_title(driver, url)
                elif selected_check_type == "Element Exists":
                    result = check_element_exists(driver, url, selector_type, selector)
                elif selected_check_type == "Element Text":
                    result = get_element_text(driver, url, selector_type, selector)
                elif selected_check_type == "Element Click":
                    result = click_element(driver, url, selector_type, selector)
                elif selected_check_type == "Element Input":
                    text = text_entry.get()
                    result = enter_text_in_element(driver, url, selector_type, selector, text)
                elif selected_check_type == "Execute JavaScript":
                    script = script_entry.get()
                    result = execute_javascript(driver, url, script)
                else:
                    raise ValueError("Invalid check type.")
                result_text.delete(1.0, tk.END)
                result_text.insert(tk.END, result)
                logging.info(result)
            except Exception as e:
                result_text.delete(1.0, tk.END)
                result_text.insert(tk.END, str(e))
                logging.error(f"Error performing check: {e}")
            finally:
                driver.quit()
        else:
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, alert_message)
            logging.error(alert_message)
    else:
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, "Google Chrome version not found.")
        logging.error("Google Chrome version not found.")


def login_check_function(driver, url, username_value, password_value,
                         username_selector_type, password_selector_type,
                         username_selector_value, password_selector_value,
                         submit_button_selector_type, submit_button_selector_value,
                         check_error_message, error_message_selector_type, error_message_selector_value):
    update_debugging_info(get_chrome_version())
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
    update_debugging_info(get_chrome_version())
    url = url_entry.get()
    chrome_version = get_chrome_version()

    if chrome_version:
        local_app_data = os.getenv('LOCALAPPDATA')
        download_path = os.path.join(local_app_data, "SeleBoy", "drivers", "chrome")
        os.makedirs(download_path, exist_ok=True)
        webdriver_path, alert_message = download_webdriver(chrome_version, download_path)

        if webdriver_path:
            options = webdriver.ChromeOptions()
            driver = webdriver.Chrome(options=options)

            login_window = tk.Toplevel(app)
            login_window.title("Perform Login Check")

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
                update_debugging_info(get_chrome_version())
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

                try:
                    login_result = login_check_function(driver, url, username_value, password_value,
                                                        username_selector_type, password_selector_type,
                                                        username_selector_value, password_selector_value,
                                                        submit_button_selector_type, submit_button_selector_value,
                                                        check_error_message, error_message_selector_type,
                                                        error_message_selector_value)
                    result_text.delete(1.0, tk.END)
                    result_text.insert(tk.END, login_result)
                except Exception as e:
                    result_text.delete(1.0, tk.END)
                    result_text.insert(tk.END, str(e))
                finally:
                    driver.quit()
                    login_window.destroy()

            tk.Button(login_window, text="Perform Login Check", command=perform_login).grid(row=11, columnspan=2)

        else:
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, alert_message)
    else:
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, "Google Chrome version not found.")


def perform_check():
    update_debugging_info(get_chrome_version())
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

    if selected_check_type == "Perform Login Check":
        perform_login_check()
    else:
        perform_regular_check(selected_check_type, url, selector_type, selector)


def update_debugging_info(version):
    debug_info_label.config(
        text=f"Browser: Google Chrome\nVersion: {version}\nWait Time: {DEFAULT_WAIT_TIME} seconds\nWebDriver Status: {check_driver_status()}\n{driver_path()}")


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
    local_app_data = os.getenv('LOCALAPPDATA')
    download_path = os.path.join(local_app_data, "SeleBoy", "drivers", "chrome")
    os.makedirs(download_path, exist_ok=True)
    webdriver_path, alert_message = download_webdriver(version, download_path)

    if webdriver_path:
        update_debugging_info(version)
        messagebox.showinfo("Success", "Google Chrome version updated successfully.")
    else:
        messagebox.showerror("Error", alert_message)


def fetch_selectors_from_webpage(url):
    update_debugging_info(get_chrome_version())
    chrome_version = get_chrome_version()
    if chrome_version:
        LocalAppData = os.getenv('LOCALAPPDATA')
        download_path = os.path.join(LocalAppData, "SeleBoy", "chrome")
        os.makedirs(download_path, exist_ok=True)
        webdriver_path, alert_message = download_webdriver(chrome_version, download_path)

        if webdriver_path:
            options = webdriver.ChromeOptions()
            driver = webdriver.Chrome(options=options)
            driver.get(url)

            selectors = set()

            elements = driver.find_elements(By.XPATH, "//*")
            for element in elements:
                if element.get_attribute("id"):
                    selectors.add(f"id={element.get_attribute('id')}")
                if element.get_attribute("name"):
                    selectors.add(f"name={element.get_attribute('name')}")
                if element.get_attribute("class"):
                    selectors.add(f"class={element.get_attribute('class')}")
                if element.tag_name:
                    selectors.add(f"tag_name={element.tag_name}")

            driver.quit()
            return selectors
        else:
            messagebox.showerror("Error", alert_message)
    else:
        messagebox.showerror("Error", "Google Chrome version not found !!!")


def export_to_csv(selectors):
    filepath = filedialog.asksaveasfilename(defaultextension=".csv",
                                            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
    if filepath:
        with open(filepath, "w", newline="") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["Selector"])
            for selector in selectors:
                writer.writerow([selector])
        messagebox.showinfo("Success", f"Selectors exported to {filepath}")


def fetch_selectors():
    url = simpledialog.askstring("Fetch Selectors", "Enter the URL:", initialvalue="http://")
    if url:
        selectors = fetch_selectors_from_webpage(url)
        if selectors:
            save_to_csv = messagebox.askyesno("Save to CSV", "Do you want to save the selectors to a CSV file?")
            if save_to_csv:
                update_debugging_info(get_chrome_version())
                export_to_csv(selectors)
            else:
                update_debugging_info(get_chrome_version())
                messagebox.showinfo("Selectors", "\t".join(selectors))


def create_rounded_button_image(width, height, radius, bg_color, fg_color, text):
    # Create an image with rounded corners
    image = Image.new("RGBA", (width, height), bg_color)
    mask = Image.new("L", (width, height), 0)
    draw = ImageDraw.Draw(mask)
    draw.rounded_rectangle((0, 0, width, height), radius, fill=255)
    image.putalpha(mask)

    # Draw the text on the image
    draw = ImageDraw.Draw(image)
    font = ImageFont.truetype("impact.ttf", 10)  # Using Arial Bold font
    text_bbox = draw.textbbox((0, 0), text, font=font)
    text_width = text_bbox[2] - text_bbox[0]
    text_height = text_bbox[3] - text_bbox[1]
    text_x = (width - text_width) // 2
    text_y = (height - text_height) // 2
    draw.text((text_x, text_y), text, font=font, fill=fg_color)

    return ImageTk.PhotoImage(image)


def create_rounded_button(parent, text, command, bg_color):
    button_image = create_rounded_button_image(100, 30, 15, bg_color, "white", text)
    button = tk.Button(parent, image=button_image, command=command, borderwidth=0)
    button.image = button_image  # Keep a reference to the image to prevent garbage collection
    return button


app = tk.Tk()
app.title("The SeleBoy: Web Automation Tool")

# Disable window resizing
app.resizable(False, False)

# Fix window size
#app.geometry("1170x400")

app.grid_columnconfigure(0, weight=1)
app.grid_columnconfigure(1, weight=1)
app.grid_rowconfigure(2, weight=1)

# Adding border and title to Debugging Info and Settings sections
debugging_frame = tk.LabelFrame(app, text="Debugging Info", padx=10, pady=10, bd=2, relief=tk.GROOVE)
debugging_frame.grid(row=0, column=0, padx=10, pady=10, sticky=tk.W + tk.E)

settings_frame = tk.LabelFrame(app, text="Settings", padx=10, pady=10, bd=2, relief=tk.GROOVE)
settings_frame.grid(row=0, column=1, padx=5, pady=10, sticky=tk.W + tk.E)

# Debugging Info Section
debug_info_label = tk.Label(debugging_frame, text="Debugging Information", bg="#CCE5FF")
debug_info_label.pack()

# Settings Section
chrome_version_label = tk.Label(settings_frame, text="Chrome Version:")
chrome_version_label.grid(row=0, column=0, sticky=tk.W)
chrome_version_var = tk.StringVar()
chrome_version_entry = tk.Entry(settings_frame, textvariable=chrome_version_var)
chrome_version_entry.grid(row=0, column=1)

chrome_version_button = tk.Button(settings_frame, text="Update Chrome Version", command=change_chrome_version,
                                  bg="#E5CCFF")
chrome_version_button.grid(row=0, column=2, padx=5)

wait_time_label = tk.Label(settings_frame, text="Default Wait Time (in seconds):")
wait_time_label.grid(row=1, column=0, sticky=tk.W)
wait_time_entry = tk.Entry(settings_frame)
wait_time_entry.grid(row=1, column=1)

wait_time_button = tk.Button(settings_frame, text="Change Wait Time", command=change_wait_time, bg="#FFFF99")
wait_time_button.grid(row=1, column=2, padx=5)

buttons_frame = tk.LabelFrame(app, text="Buttons", padx=10, pady=10, bd=2, relief=tk.GROOVE)
buttons_frame.grid(row=1, column=0, padx=10, pady=10, sticky=tk.W + tk.E)

seleboy_frame = tk.LabelFrame(app, text="SeleBoy by rS", padx=10, pady=10, bd=2, relief=tk.GROOVE)
seleboy_frame.grid(row=1, column=1, padx=10, pady=10, sticky=tk.W + tk.E)

# Main Section within SeleBoy
url_label = tk.Label(seleboy_frame, text="URL:")
url_label.grid(row=0, column=0, sticky=tk.W)
url_entry = tk.Entry(seleboy_frame)
url_entry.grid(row=0, column=1)

check_type_label = tk.Label(seleboy_frame, text="Check Type:")
check_type_label.grid(row=1, column=0, sticky=tk.W)
check_type_var = tk.StringVar()
check_type_combobox = ttk.Combobox(seleboy_frame, textvariable=check_type_var,
                                   values=["Title", "Element Exists", "Element Text", "Element Click",
                                           "Element Input", "Execute JavaScript", "Perform Login Check"],
                                   state="readonly")
check_type_combobox.grid(row=1, column=1)

selector_type_label = tk.Label(seleboy_frame, text="Selector Type:")
selector_type_label.grid(row=2, column=0, sticky=tk.W)
selector_type_var = tk.StringVar()
selector_type_combobox = ttk.Combobox(seleboy_frame, textvariable=selector_type_var,
                                      values=["ID", "Name", "XPath", "CSS Selector", "Class Name",
                                              "Tag Name", "Link Text", "Partial Link Text"],
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
check_button = tk.Button(buttons_frame, text="Perform Check", command=perform_check, bg="#00CC00")
check_button.grid(row=1, column=0, padx=20, pady=10, sticky=tk.W)

help_button = tk.Button(buttons_frame, text="HELP ?", command=show_help, bg="#6666FF")
help_button.grid(row=1, column=1, padx=20, pady=10, sticky=tk.W)

fetch_selectors_button = tk.Button(buttons_frame, text="Fetch Selectors", command=fetch_selectors, bg="#99FFFF")
fetch_selectors_button.grid(row=1)

# Create a frame for the result with scrollbar inside buttons_frame
result_frame = tk.LabelFrame(buttons_frame)
result_frame.grid(row=3, column=0, columnspan=3, padx=5, pady=5, sticky="nsew")

scrollbar = tk.Scrollbar(result_frame)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

result_text = tk.Text(result_frame, height=10, bg="#FFFFFF", wrap=tk.WORD,
                      yscrollcommand=scrollbar.set)
result_text.pack(fill=tk.BOTH, expand=True)

scrollbar.config(command=result_text.yview)
result_frame.grid_propagate(False)
buttons_frame.grid_rowconfigure(3, weight=1)
buttons_frame.grid_columnconfigure(0, weight=1)

# Add a new row and column configuration for the bottom right corner
app.grid_rowconfigure(3, weight=1)
app.grid_columnconfigure(2, weight=1)

version_lable = tk.Label(app, text="V1.1 Stable")
version_lable.grid(row=3, column=2, sticky=tk.SE)
log_file = tk.Button(app, text="Show Debug logs", command=log_file, bg="#6666FF")
log_file.grid(row=3, column=0, sticky=tk.W)
update_debugging_info(get_chrome_version())

app.mainloop()
