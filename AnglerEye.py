import os
import imaplib
import email
from email.header import decode_header
import re
import nltk
import joblib
import requests
import dns.resolver
from email.utils import parseaddr
from tkinter import Tk, Label, Button, messagebox
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import tarfile

# Ensure NLTK resources are downloaded
nltk.download('punkt')
nltk.download('stopwords')

# Constants
MODEL_FILENAME = 'phishing_model.pkl'
VECTORIZER_FILENAME = 'vectorizer.pkl'
ENRON_DATA_URL = 'https://www2.cs.arizona.edu/projects/emailresearch/data/enron-spam/preprocessed/enron1.tar.gz'
DATA_DIR = 'enron_data'
PHISHING_LABEL = 'spam'

# Utility functions
def preprocess_text(text):
    """Preprocess text by removing HTML tags, URLs, and stop words."""
    text = re.sub(r'<.*?>', '', text)
    text = re.sub(r'http\S+', '', text)
    tokens = nltk.word_tokenize(text)
    stop_words = set(nltk.corpus.stopwords.words('english'))
    return ' '.join([word for word in tokens if word.lower() not in stop_words])

def download_and_extract_data():
    """Download and extract the Enron dataset if it does not exist."""
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)
        response = requests.get(ENRON_DATA_URL, stream=True)
        tarball_path = os.path.join(DATA_DIR, 'enron1.tar.gz')
        with open(tarball_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        with tarfile.open(tarball_path) as tar:
            tar.extractall(DATA_DIR)
        os.remove(tarball_path)  # Clean up tarball after extraction

def load_dataset():
    """Load the Enron dataset for training."""
    download_and_extract_data()
    emails = []
    labels = []
    for root, dirs, files in os.walk(DATA_DIR):
        for file in files:
            if file.endswith('.txt'):
                with open(os.path.join(root, file), 'r', encoding='latin1') as f:
                    emails.append(f.read())
                    labels.append(PHISHING_LABEL in root)
    return emails, labels

def train_model():
    """Train the phishing detection model using the Enron dataset."""
    emails, labels = load_dataset()
    emails = [preprocess_text(email) for email in emails]

    # Split the dataset
    X_train, X_test, y_train, y_test = train_test_split(emails, labels, test_size=0.2, random_state=42)

    # Vectorize the text
    vectorizer = TfidfVectorizer(max_features=3000)
    X_train_vectors = vectorizer.fit_transform(X_train)
    X_test_vectors = vectorizer.transform(X_test)

    # Train the model
    model = LogisticRegression(max_iter=1000)
    model.fit(X_train_vectors, y_train)

    # Evaluate the model
    predictions = model.predict(X_test_vectors)
    print(f"Model Accuracy: {accuracy_score(y_test, predictions):.2f}")

    # Save the model and vectorizer
    joblib.dump(model, MODEL_FILENAME)
    joblib.dump(vectorizer, VECTORIZER_FILENAME)

def fetch_emails(email_account, password, imap_server, folder="INBOX"):
    """Fetch emails from the specified IMAP server and folder."""
    # Connect to the email server
    mail = imaplib.IMAP4_SSL(imap_server)
    mail.login(email_account, password)
    mail.select(folder)

    # Search for all emails in the folder
    status, messages = mail.search(None, "ALL")
    email_list = []

    # Process each email
    for num in messages[0].split():
        status, msg_data = mail.fetch(num, "(RFC822)")
        for response_part in msg_data:
            if isinstance(response_part, tuple):
                msg = email.message_from_bytes(response_part[1])
                subject, encoding = decode_header(msg["Subject"])[0]
                if isinstance(subject, bytes):
                    subject = subject.decode(encoding if encoding else 'utf-8')
                body = ""
                if msg.is_multipart():
                    for part in msg.walk():
                        content_type = part.get_content_type()
                        content_disposition = str(part.get("Content-Disposition"))
                        if content_type == "text/plain" and "attachment" not in content_disposition:
                            body = part.get_payload(decode=True).decode(errors='replace')
                            break
                else:
                    body = msg.get_payload(decode=True).decode(errors='replace')
                email_list.append({"num": num, "subject": subject, "body": body, "headers": msg.items()})
    return email_list, mail

def check_spf(domain):
    """Check the SPF record of a domain."""
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for record in answers:
            if "v=spf1" in str(record):
                return str(record)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        return None

def check_dkim(msg):
    """Check the DKIM signature of an email message."""
    return 'DKIM-Signature' in dict(msg)

def check_dmarc(domain):
    """Check the DMARC record of a domain."""
    try:
        answers = dns.resolver.resolve('_dmarc.' + domain, 'TXT')
        for record in answers:
            if "v=DMARC1" in str(record):
                return str(record)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        return None

def analyze_sender(email_headers):
    """Analyze the sender's domain using SPF, DKIM, and DMARC records."""
    sender = parseaddr(dict(email_headers)['From'])[1]
    domain = sender.split('@')[-1]

    spf_record = check_spf(domain)
    dkim_valid = check_dkim(dict(email_headers))
    dmarc_record = check_dmarc(domain)

    sender_info = {
        "domain": domain,
        "spf": spf_record,
        "dkim": dkim_valid,
        "dmarc": dmarc_record,
    }
    return sender_info

def detect_phishing(emails, model, vectorizer):
    """Detect phishing emails and analyze the sender's authenticity."""
    phishing_attempts = []
    for email in emails:
        subject = preprocess_text(email['subject'])
        body = preprocess_text(email['body'])
        features = vectorizer.transform([subject + " " + body])
        prediction = model.predict(features)
        if prediction == 1:
            sender_info = analyze_sender(email['headers'])
            phishing_attempts.append((email, sender_info))
    return phishing_attempts

def show_toast(email, sender_info, mail):
    """Display a toast notification with options for handling phishing emails."""
    def block_and_mark_spam():
        mail.store(email['num'], '+FLAGS', '\\Deleted')
        mail.expunge()
        messagebox.showinfo("Action Taken", "Email blocked and marked as spam.")
        toast.destroy()

    def accept():
        messagebox.showinfo("Action Taken", "Email accepted and kept in inbox.")
        toast.destroy()

    def delete_email():
        mail.store(email['num'], '+FLAGS', '\\Deleted')
        mail.expunge()
        messagebox.showinfo("Action Taken", "Email deleted.")
        toast.destroy()

    def archive():
        # Move email to an "Archive" folder (ensure the folder exists)
        mail.copy(email['num'], 'Archive')
        mail.store(email['num'], '+FLAGS', '\\Deleted')
        mail.expunge()
        messagebox.showinfo("Action Taken", "Email archived.")
        toast.destroy()

    toast = Tk()
    toast.title("Phishing Email Detected")
    toast.geometry("400x300")

    Label(toast, text=f"Phishing email detected: {email['subject']}").pack(pady=5)
    Label(toast, text=f"Sender Domain: {sender_info['domain']}").pack(pady=5)
    Label(toast, text=f"SPF: {sender_info['spf']}").pack(pady=5)
    Label(toast, text=f"DKIM: {'Valid' if sender_info['dkim'] else 'Invalid'}").pack(pady=5)
    Label(toast, text=f"DMARC: {sender_info['dmarc']}").pack(pady=5)

    Button(toast, text="Block & Mark Spam", command=block_and_mark_spam).pack(pady=5)
    Button(toast, text="Accept", command=accept).pack(pady=5)
    Button(toast, text="Delete", command=delete_email).pack(pady=5)
    Button(toast, text="Archive", command=archive).pack(pady=5)

    toast.mainloop()

def main():
    # Train model if not already trained
    if not os.path.exists(MODEL_FILENAME) or not os.path.exists(VECTORIZER_FILENAME):
        train_model()

    # Load the trained model and vectorizer
    model = joblib.load(MODEL_FILENAME)
    vectorizer = joblib.load(VECTORIZER_FILENAME)

    # Fetch emails
    email_account = "your_email@example.com"
    password = "your_password"
    imap_server = "imap.example.com"

    # Replace with your actual credentials and server details
    try:
        emails, mail = fetch_emails(email_account, password, imap_server)

        # Detect phishing attempts
        phishing_attempts = detect_phishing(emails, model, vectorizer)

        # Display a toast for each phishing attempt detected
        for attempt, sender_info in phishing_attempts:
            show_toast(attempt, sender_info, mail)

        # Close the mail connection
        mail.logout()

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
