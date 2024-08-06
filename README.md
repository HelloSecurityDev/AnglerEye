# AnglerEye

## Documentation

This script is a Python application that detects phishing emails using machine learning. It downloads the Enron dataset to train a logistic regression model for classifying emails as phishing or non-phishing. The application also fetches emails from a specified IMAP server and analyzes them for potential phishing attempts, utilizing SPF, DKIM, and DMARC email authentication protocols. If phishing emails are detected, it provides a user interface to manage these emails.

## Prerequisites

Before using the script, ensure that the following Python libraries are installed:

- `os`
- `imaplib`
- `email`
- `nltk`
- `joblib`
- `requests`
- `dns.resolver`
- `tkinter`
- `scikit-learn`
- `tarfile`

Use the following command to install the missing packages:

```bash
pip install nltk joblib requests dnspython scikit-learn
```

Additionally, ensure that you have the necessary NLTK resources:

```python
nltk.download('punkt')
nltk.download('stopwords')
```

## Script Components

Constants

- `MODEL_FILENAME`: The filename for the saved logistic regression model.
- `VECTORIZER_FILENAME`: The filename for the saved TF-IDF vectorizer.
- `ENRON_DATA_URL`: URL to download the Enron spam dataset.
- `DATA_DIR`: Directory where the dataset is stored.
- `PHISHING_LABEL`: Label indicating phishing emails in the dataset.

Utility Functions

- `preprocess_text(text)`: Cleans the text by removing HTML tags, URLs, and stop words.
- `download_and_extract_data()`: Downloads and extracts the Enron dataset.
- `load_dataset()`: Loads emails and their labels from the dataset.
- `train_model()`: Trains the logistic regression model and saves it along with the vectorizer.
- `fetch_emails(email_account, password, imap_server, folder)`: Connects to an IMAP server to fetch emails.
- `check_spf(domain)`: Retrieves the SPF record for a domain.
- `check_dkim(msg)`: Checks for a DKIM signature in an email message.
- `check_dmarc(domain)`: Retrieves the DMARC record for a domain.
- `analyze_sender(email_headers)`: Analyzes the sender's domain using SPF, DKIM, and DMARC records.
- `detect_phishing(emails, model, vectorizer)`: Detects phishing emails and analyzes sender information.
- `show_toast(email, sender_info, mail)`: Displays a user interface for handling phishing emails.

Main Function

The `main()` function coordinates the following actions:

1. Model Training: Trains the model using the Enron dataset if not already done.
2. Model Loading: Loads the pre-trained model and vectorizer.
3. Email Fetching: Retrieves emails from the specified email account.
4. Phishing Detection: Analyzes emails for phishing content.
5. User Notification: Displays a GUI notification for each detected phishing email, providing options to block, accept, delete, or archive the email.
6. Email Server Logout: Closes the connection to the email server.

## Usage Instructions

1. Set Up Email Account Details: Modify the `email_account`, `password`, and `imap_server` variables in the `main()` function with your email credentials and server details.

2. Run the Script: Execute the script using a Python interpreter. It will automatically download the dataset, train the model, fetch emails, and detect phishing attempts.

3. Handle Phishing Attempts: For each detected phishing email, a GUI will pop up allowing you to choose an action (Block & Mark Spam, Accept, Delete, or Archive).

4. Log Out: The script will automatically log out from the email server after processing emails.

## Security Note

- Ensure that email credentials and server details are stored securely. Avoid hardcoding them in the script if possible, and consider using environment variables or secure vaults for managing sensitive information.

## Troubleshooting

- Errors during NLTK downloads: Check internet connection and permissions to download resources.
- IMAP connection errors: Verify email credentials and server details, and ensure IMAP is enabled on the email account.
- Dependency errors: Ensure all required Python libraries are installed.
