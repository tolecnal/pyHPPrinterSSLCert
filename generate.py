import os
import subprocess
import sys
import ssl
import socket
import time
import re

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support import expected_conditions as EC

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv


# Load environment variables from .envrc file
load_dotenv(".envrc")


def get_certificate_expiration(cert_path):
    """Check the certificate expiration date using OpenSSL."""
    try:
        openssl_cmd = ["openssl", "x509", "-enddate", "-noout", "-in", cert_path]
        result = subprocess.run(openssl_cmd, capture_output=True, text=True, check=True)
        end_date_str = result.stdout.strip().split("=")[1]
        expiration_date = datetime.strptime(end_date_str, "%b %d %H:%M:%S %Y %Z")
        expiration_date = expiration_date.replace(
            tzinfo=timezone.utc
        )
        return expiration_date

    except Exception as e:
        print(f"Error checking certificate expiration: {e}")
        return None


def is_certificate_valid(cert_path):
    """Check if the certificate exists and is not expiring within the next 14 days."""
    if not os.path.exists(cert_path):
        return False

    expiration_date = get_certificate_expiration(cert_path)
    if expiration_date:
        renewal_threshold = datetime.now(timezone.utc) + timedelta(days=14)
        if expiration_date > renewal_threshold:
            print(f"Certificate is valid until {expiration_date}, no need to renew.")
            return True
        else:
            print(f"Certificate is expiring soon ({expiration_date}), renewal needed.")
            return False
    else:
        return False


def get_remote_certificate(hostname):
    """Retrieve the remote SSL certificate from the specified hostname, ignoring verification."""
    context = ssl._create_unverified_context()
    with socket.create_connection((hostname, 443)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert(binary_form=True)
    return cert


def get_local_certificate(cert_path):
    """Retrieve the local SSL certificate issued by Certbot."""
    with open(cert_path, "rb") as f:
        return f.read()


def compare_certificates(printer_hostname, local_cert_path):
    """Compare the local certificate with the certificate from the printer."""
    remote_cert = get_remote_certificate(printer_hostname)
    with open(local_cert_path, "rb") as f:
        local_cert = f.read()

    # Convert both certificates to a common format (if necessary)
    remote_cert_pem = ssl.DER_cert_to_PEM_cert(remote_cert)

    # Compare the certificates
    if local_cert == remote_cert_pem.encode():  # Ensure you compare bytes
        print("The certificates match. No upload needed.")
    else:
        print("The certificates do not match. Proceeding with upload.")
        upload_headless(local_cert_path)


def generate_certificate():
    # Retrieve environment variables
    hostname = os.getenv("PRINTER_HOSTNAME")
    cloudflare_email = os.getenv("CLOUDFLARE_EMAIL")
    cloudflare_api_key = os.getenv("CLOUDFLARE_API_KEY")
    certificate_password = os.getenv("CERTIFICATE_PASSWORD")
    admin_password = os.getenv("ADMIN_PASSWORD")

    if not all(
        [
            hostname,
            cloudflare_email,
            cloudflare_api_key,
            certificate_password,
            admin_password,
        ]
    ):
        print("Error: One or more required environment variables are missing.")
        sys.exit(1)

    current_path = os.getcwd()

    cert_path = f"{current_path}/live/{hostname}/fullchain.pem"
    key_path = f"{current_path}/live/{hostname}/privkey.pem"
    pfx_output_path = f"{current_path}/live/{hostname}/cert.pfx"

    cloudflare_creds_path = "/tmp/cloudflare.ini"
    with open(cloudflare_creds_path, "w") as f:
        f.write(f"dns_cloudflare_email = {cloudflare_email}\n")
        f.write(
            f"dns_cloudflare_api_key = {cloudflare_api_key}\n"
        )

    os.chmod(cloudflare_creds_path, 0o600)

    try:
        certbot_cmd = [
            "certbot",
            "certonly",
            "--dns-cloudflare",
            "--dns-cloudflare-credentials",
            cloudflare_creds_path,
            "-d",
            hostname,
            "--non-interactive",
            "--agree-tos",
            "--logs-dir",
            f"{current_path}",
            "--work-dir",
            f"{current_path}",
            "--config-dir",
            f"{current_path}",
            "--email",
            cloudflare_email,
        ]

        subprocess.run(certbot_cmd, check=True)

        openssl_cmd = [
            "openssl",
            "pkcs12",
            "-export",
            "-out",
            pfx_output_path,
            "-inkey",
            key_path,
            "-in",
            cert_path,
            "-password",
            f"pass:{certificate_password}",
        ]

        subprocess.run(openssl_cmd, check=True)
        print(f"Certificate generated and saved at: {pfx_output_path}")

    except subprocess.CalledProcessError as e:
        print(f"Error generating certificate: {e}")
    finally:
        if os.path.exists(cloudflare_creds_path):
            os.remove(cloudflare_creds_path)


def get_certificate_thumbprint():
    printer_hostname = os.getenv("PRINTER_HOSTNAME")

    current_path = os.getcwd()
    pem_certificate_path = f"{current_path}/live/{printer_hostname}/cert.pem"

    with open(pem_certificate_path, 'rb') as pem_file:
        pem_data = pem_file.read()

    # Load the PEM certificate
    certificate = x509.load_pem_x509_certificate(pem_data, default_backend())

    # Calculate the thumbprint (SHA-1 digest)
    thumbprint = certificate.fingerprint(hashes.SHA1()).hex()

    return thumbprint


def upload_headless(certificate_path):
    hostname = os.getenv("PRINTER_HOSTNAME")
    admin_password = os.getenv("ADMIN_PASSWORD")
    certificate_password = os.getenv("CERTIFICATE_PASSWORD")
    # we can't upload the PEM certificate, so changing to PFX here, which is supported by EWS
    filename = os.path.splitext(certificate_path)[0] + ".pfx"
    certificate_thumbprint = get_certificate_thumbprint()

    # Start a headless browser session with the following options
    options = webdriver.ChromeOptions()
    options.add_argument("--ignore-certificate-errors")
    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")

    options.binary_location = (
        "/usr/bin/chromium-browser"
    )

    # Create a WebDriver instance using Chromium and Chromium ChromeDriver
    service = Service("/usr/bin/chromedriver")
    driver = webdriver.Chrome(service=service, options=options)

    # Navigate to the login page
    driver.get(f"https://{hostname}/hp/device/SignIn/Index")

    # Wait for the login form to be visible
    WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.NAME, "PasswordTextBox"))
    )

    # Select the agentId from the dropdown (if necessary)
    agent_dropdown = driver.find_element(By.NAME, "agentIdSelect")
    agent_dropdown.send_keys("hp_EmbeddedPin_v1")

    # Select the 'AdminItem' from the dropdown (if this is a select dropdown)
    pin_dropdown = driver.find_element(By.NAME, "PinDropDown")
    pin_dropdown.send_keys("AdminItem")

    # Enter the admin password
    password_field = driver.find_element(By.NAME, "PasswordTextBox")
    password_field.send_keys(f"{admin_password}")

    # Click the 'Sign In' button
    sign_in_button = driver.find_element(By.NAME, "signInOk")
    sign_in_button.click()

    # Once we find DeviceStatusHeaderSectionId in the page, we know we are logged in
    WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.ID, "DeviceStatusHeaderSectionId"))
    )

    # Load the certificates page
    driver.get(f"https://{hostname}/hp/device/CertificatesTabs")

    # We wait until the input fields are available
    WebDriverWait(driver, 10).until(
        EC.presence_of_element_located(
            (
                By.XPATH,
                "/html/body/div[2]/div/div/div[2]/div/div[2]/form/div/div[2]/div[2]/div[2]/div[8]/div[2]/div[1]/label/div/input",
            )
        )
    )

    # Here we find the input elements for the file and password
    driver.find_element(
        By.XPATH,
        "/html/body/div[2]/div/div/div[2]/div/div[2]/form/div/div[2]/div[2]/div[2]/div[8]/div[2]/div[1]/label/div/input",
    ).send_keys(filename)
    driver.find_element(
        By.XPATH,
        "/html/body/div[2]/div/div/div[2]/div/div[2]/form/div/div[2]/div[2]/div[2]/div[8]/div[2]/div[2]/input",
    ).send_keys(f"{certificate_password}")
    driver.find_element(
        By.XPATH,
        "/html/body/div[2]/div/div/div[2]/div/div[2]/form/div/div[2]/div[2]/div[2]/div[9]/span/input",
    ).click()

    WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.ID, "CaCertificatesViewSectionId"))
    )

    print("Certificate uploaded... ")

    # After the certificate has been uploaded, we have to find it in the table of certificates
    # When it's found using the regex, we know which <label> to press to select it
    # Once selected, we click the label
    thumb_upper = certificate_thumbprint.upper()
    pattern = rf'<input\s+type="radio"\s+value="ID\|{thumb_upper}".*?<label\s+for="(.*?)">'
    page_source = driver.page_source
    match = re.search(pattern, page_source, re.DOTALL)

    if match:
        label_for_value = match.group(1)  # Get the value of the "for" attribute

        label = driver.find_element(By.XPATH, f"//label[@for='{label_for_value}']")
        time.sleep(5)
        label.click()
    else:
        print(f"No match found for label {label_for_value} - we will not be able to select new certificate!")
        exit(1)

    # Now that we have selected it, activate it for the web service
    time.sleep(5)
    submit_button = driver.find_element(By.ID, "UseForNetButton")
    submit_button.click()

    # The EWS service verifies the certificate, and ask us if we want to use it
    time.sleep(10)
    submit_button = driver.find_element(By.ID, "DialogButtonYes")
    submit_button.click()
    time.sleep(10)

    print("Certificate should now be activated, EWS will automatically restart")

    # Close the Chronium session
    driver.quit()


if __name__ == "__main__":
    printer_hostname = os.getenv("PRINTER_HOSTNAME")
    current_path = os.getcwd()
    certificate_path = f"{current_path}/live/{printer_hostname}/cert.pem"
    pfx_password = os.getenv("CERTIFICATE_PASSWORD")

    if is_certificate_valid(certificate_path):
        exit
    else:
        generate_certificate()

    # Compare certificates and upload if necessary
    compare_certificates(printer_hostname, certificate_path)
