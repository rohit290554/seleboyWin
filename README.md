About This Tool

Developer: Rohit Saxena (GitHub: Git-rohit290554)
Version: 1.1

Added a logging mechanism to track actions, errors, and results for better debugging and transparency.
Improve the layout and usability of the GUI by aligning elements and adding more user-friendly labels and tooltips.
Add logic to properly close the WebDriver instance after use to avoid resource leaks.

Version: 1.0

Description:
Welcome to the first version of the Windows tool that automates the setup of Selenium WebDriver for Google Chrome and provides basic Selenium testing functionalities. This tool is designed to help you quickly and easily perform essential web automation tasks without the need for extensive manual configuration.

Key Features:

Auto-Detect Chrome Version:

Automatically detects the installed version of Google Chrome on your system.
Downloads and installs the appropriate Selenium WebDriver for the detected Chrome version.
Basic Selenium Testing Functions:

title: Check the title of the webpage.
element_exists: Verify the existence of a specified element on the webpage.
element_text: Retrieve the text content of a specified element on the webpage.
element_click: Click on a specified element on the webpage.
element_input: Enter text into a specified input element on the webpage.
execute_js: Execute custom JavaScript code on the webpage.
login_check: Perform a login check using specified credentials and selectors.
Usage:
This tool is ideal for developers and testers who need to perform basic web automation tasks quickly. Whether you're validating webpage elements, performing login checks, or automating simple web interactions, this tool provides the essential functions you need.

Installation:
To install the tool, simply run the installer and follow the on-screen instructions. The tool will handle the detection of your Chrome version and set up the corresponding WebDriver for you.

Support and Feedback:
If you encounter any issues or have feedback, please visit the GitHub repository at Git-rohit290554 to report bugs or request features.

Thank you for using our tool. We hope it enhances your web automation experience!

License:
Copyright [2024] [Rohit Saxena] GitHub - rohit290554

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

script provides a comprehensive toolkit for performing various web automation tasks using Selenium and Tkinter. Here’s a detailed overview of what each function and part of the script does:

Helper Functions:

show_help(): Displays a help dialog with information on the tool's functionality.
get_chrome_version(): Retrieves the installed version of Google Chrome by querying the Windows Registry.
save_to_driverlog(version, url): Saves the Chrome version and download URL to a log file.
read_driverlog(): Reads the Chrome version from the log file if it exists.
download_webdriver(version, driver_download_path): Downloads and extracts the Chrome WebDriver for the given version if it hasn’t been downloaded already.
Web Interaction Functions:

test_webpage_title(driver, url): Retrieves and returns the title of the webpage.
check_element_exists(driver, url, selector_type, selector): Checks if an element exists on the webpage.
get_element_text(driver, url, selector_type, selector): Retrieves the text of an element.
click_element(driver, url, selector_type, selector): Clicks an element and waits for the URL to change.
enter_text_in_element(driver, url, selector_type, selector, text): Enters text into an element.
execute_javascript(driver, url, script): Executes JavaScript on the webpage.
login_check_function(): Performs a login check by entering credentials and checking for an error message.
Main Workflow Functions:

perform_regular_check(selected_check_type, url, selector_type, selector): Handles the main workflow for various checks (title, element existence, text retrieval, element click, text input, JavaScript execution).
perform_login_check(): Sets up a GUI for performing a login check and calls login_check_function().
GUI Setup:

app: The main Tkinter application window.
debugging_frame: Displays debugging information such as the Chrome version and default wait time.
settings_frame: Allows users to change the Chrome version and default wait time.
seleboy_frame: The main section for user input, including URL, check type, selector type, selector, text, and JavaScript script.
update_debugging_info(version): Updates the debugging information displayed in the GUI.
change_wait_time(): Changes the default wait time.
change_chrome_version(): Updates the Chrome version and downloads the appropriate WebDriver if needed.
Event Handlers:

perform_check(): Handles the main check action, determining whether to perform a regular check or a login check based on the user input.
update_debugging_info(): Updates debugging info displayed in the GUI.
