# pyHPPrinterSSLCert

This Python scripts generates a SSL certificate using Letsencrypt, Certbot and its Cloudflare provider.

When the certificate has been issued, the script makes a PFX version of the issued certificate, as HP printers, at least modern ones do not support PEM.

Once we have the PFX version, we use a headless Chromium session to log in to the HP EWS admin interface. Here we inspect for known elements in the admin interface that allows us to upload the certificate with its password.

Once the certificate has been selected, we activate it and ensure the EWS service is restart to activate the newly uploaded certificate.

## Setup

You need to create a file called `.envrc` - a simple approach would be:

 `mv envrc.example .envrc`

Once the file has been created, edit the file according to your environment.

    PRINTER_HOSTNAME

The hostname you want your printer to use in its SSL certificate.

    CLOUDFLARE_EMAIL

Your Cloudflare registered email address.

    CLOUDFLARE_API_KEY

Your Cloudflare API key

    CERTIFICATE_PASSWORD

The SSL certificate password you want the PFX certificate to use

    ADMIN_PASSWORD

The admin password used to access your HP printers EWS admin interface

## Python setup

You already need to have the Chromium browser as well as the Chromium chromedriver installed, on Debian like systems you can do this with:

`apt-get install chromium-browser chromium-chromedriver`

We can then proceed to prepare the Python environment.

- create a Python virtual environment
  - `python3 -m venv venv`
- activate the virtual environment
  - `source venv/bin/activate`
- install the Python requirements
  - `pip3 install -r requirements.txt`

## Running the script

Once you have prepared and activate the Python virtual environment, you simple run the script like this:

`python3 generate.py`

The script logs most of the required information on screen, so you know what is going on.

## Debugging

If you want to see what `chromedriver` and `selenium` is doing, you can run the script on a machine that has a monitor installed. All you need to do then, is to comment out the following line in the scirpt:

`options.add_argument("--headless")`

You will then be able to keep an eye in an actual browser session to see what the script is doing.

## Problems

Report any problems with the script to `tolecnal@tolecnal.net`.

This script was written as a sort of `Proof Of Concept` to see whether or not I could use Python and the Selenium Python module to control the web browser in such a way that I was able to log in, upload the certificate, select it, and activate it.

The fact that this script is live on Github means that this POC turned out to be succesful.

## License

MIT / BSD

## Author information

This script was created in 2024 by Jostein Elvaker Haande.
