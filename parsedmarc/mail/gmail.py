import logging
from base64 import urlsafe_b64decode
from functools import lru_cache
from pathlib import Path
from time import sleep
from typing import List, Optional

from google.auth.transport.requests import Request
from google.oauth2 import service_account
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Use a standard logger. If this module is part of a larger package,
# it's better to get the logger from that package (e.g., from parsedmarc.log import logger)
logger = logging.getLogger(__name__)


def _get_creds(
    token_file: str,
    credentials_file: str,
    scopes: List[str],
    oauth2_port: int,
    service_account_file: Optional[str],
    delegated_account: Optional[str],
):
    """
    Get Google API credentials using a service account or OAuth 2.0 user flow.
    """
    # Prioritize Service Account with Domain-Wide Delegation
    if service_account_file and delegated_account:
        logger.info(
            f"Using service account credentials to act as {delegated_account}."
        )
        return service_account.Credentials.from_service_account_file(
            service_account_file, scopes=scopes
        ).with_subject(delegated_account)

    # Fallback to OAuth 2.0 user consent flow
    logger.debug("Using OAuth 2.0 user consent flow.")
    creds = None
    token_path = Path(token_file)
    if token_path.exists():
        logger.debug(f"Loading credentials from token file: {token_file}")
        creds = Credentials.from_authorized_user_file(token_file, scopes)

    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            logger.info("Credentials have expired. Refreshing token...")
            creds.refresh(Request())
        else:
            logger.info("Valid credentials not found. Starting local server for user authentication.")
            flow = InstalledAppFlow.from_client_secrets_file(credentials_file, scopes)
            creds = flow.run_local_server(open_browser=False, port=oauth2_port)
            logger.info("Authentication successful.")
        # Save the credentials for the next run
        with token_path.open("w") as token:
            token.write(creds.to_json())
            logger.info(f"Credentials saved to {token_file} for future use.")
    else:
        logger.info("Successfully loaded valid credentials.")
    return creds


class GmailConnection(MailboxConnection):
    def __init__(
        self,
        token_file: str,
        credentials_file: str,
        scopes: List[str],
        include_spam_trash: bool,
        reports_folder: str,
        oauth2_port: int,
        paginate_messages: bool,
        service_account_file: Optional[str] = None,
        delegated_account: Optional[str] = None,
    ):
        logger.info("Initializing Gmail connection...")
        creds = _get_creds(
            token_file,
            credentials_file,
            scopes,
            oauth2_port,
            service_account_file,
            delegated_account,
        )
        self.service = build("gmail", "v1", credentials=creds)
        logger.debug("Gmail API service client created successfully.")
        self.include_spam_trash = include_spam_trash
        self.paginate_messages = paginate_messages

        # Set user_id for API calls ("me" or the delegated account's email)
        self.user_id = delegated_account if delegated_account else "me"
        logger.info(f"Operating on behalf of user: {self.user_id}")
        self.reports_label_id = self._find_label_id_for_label(reports_folder)
        logger.debug(f"Reports folder '{reports_folder}' corresponds to label ID: {self.reports_label_id}")

    def create_folder(self, folder_name: str):
        # Gmail uses labels instead of folders. The name "Archive" is reserved.
        if folder_name == "Archive":
            logger.debug("Skipping creation of reserved folder/label 'Archive'.")
            return

        logger.info(f"Attempting to create label: {folder_name}")
        request_body = {"name": folder_name, "messageListVisibility": "show"}
        try:
            label = self.service.users().labels().create(
                userId=self.user_id, body=request_body
            ).execute()
            logger.info(f"Successfully created label '{folder_name}' with ID: {label['id']}")
        except HttpError as e:
            if e.status_code == 409:
                logger.debug(f"Label '{folder_name}' already exists, skipping creation.")
            else:
                logger.error(f"Failed to create label '{folder_name}': {e}")
                raise e

    def _fetch_all_message_ids(self, reports_label_id, page_token=None, since=None):
        query_parts = []
        if since:
            query_parts.append(f"after:{since}")
        query = " ".join(query_parts)

        try:
            logger.debug(f"Fetching message list with query: '{query if query else 'None'}' and page_token: '{page_token}'")
            query_params = {
                "userId": self.user_id,
                "includeSpamTrash": self.include_spam_trash,
                "labelIds": [reports_label_id],
                "pageToken": page_token,
            }
            if query:
                query_params["q"] = query

            results = self.service.users().messages().list(**query_params).execute()
        except HttpError as e:
            logger.error(f"API error while fetching message list: {e}")
            return

        messages = results.get("messages", [])
        logger.debug(f"Found {len(messages)} messages on this page.")
        for message in messages:
            yield message["id"]

        next_page_token = results.get("nextPageToken")
        if next_page_token and self.paginate_messages:
            logger.debug(f"Found next page token, continuing fetch: {next_page_token}")
            yield from self._fetch_all_message_ids(
                reports_label_id, next_page_token, since=since
            )
        else:
            logger.debug("No more pages to fetch.")

    def fetch_messages(self, reports_folder: str, **kwargs) -> List[str]:
        logger.info(f"Fetching all message IDs from folder: {reports_folder}")
        reports_label_id = self._find_label_id_for_label(reports_folder)
        since = kwargs.get("since")
        message_ids = list(self._fetch_all_message_ids(reports_label_id, since=since))
        logger.info(f"Found a total of {len(message_ids)} messages in '{reports_folder}'.")
        return message_ids

    def fetch_message(self, message_id):
        logger.debug(f"Fetching raw content for message ID: {message_id}")
        try:
            msg = (
                self.service.users()
                .messages()
                .get(userId=self.user_id, id=message_id, format="raw")
                .execute()
            )
            return urlsafe_b64decode(msg["raw"])
        except HttpError as e:
            logger.error(f"Failed to fetch message ID {message_id}: {e}")
            raise

    def delete_message(self, message_id: str):
        logger.info(f"Deleting message ID: {message_id}")
        try:
            self.service.users().messages().delete(
                userId=self.user_id, id=message_id
            ).execute()
            logger.debug(f"Successfully deleted message ID: {message_id}")
        except HttpError as e:
            logger.error(f"Failed to delete message ID {message_id}: {e}")
            raise

    def move_message(self, message_id: str, folder_name: str):
        label_id = self._find_label_id_for_label(folder_name)
        logger.info(f"Moving message ID {message_id} from reports folder to '{folder_name}' (Label ID: {label_id}).")
        request_body = {
            "addLabelIds": [label_id],
            "removeLabelIds": [self.reports_label_id],
        }
        try:
            self.service.users().messages().modify(
                userId=self.user_id, id=message_id, body=request_body
            ).execute()
            logger.debug(f"Successfully moved message ID: {message_id}")
        except HttpError as e:
            logger.error(f"Failed to move message ID {message_id}: {e}")
            raise

    def keepalive(self):
        # Not needed for the Gmail API
        logger.debug("Keepalive called, but no action is needed for Gmail API.")
        pass

    def watch(self, check_callback, check_timeout):
        """Checks the mailbox for new messages every n seconds."""
        logger.info(f"Watching mailbox for new messages. Checking every {check_timeout} seconds.")
        while True:
            try:
                sleep(check_timeout)
                logger.debug("Checking for new messages...")
                check_callback(self)
            except KeyboardInterrupt:
                logger.info("Watch interrupted by user. Exiting.")
                break
            except Exception as e:
                logger.error(f"An unexpected error occurred during watch cycle: {e}", exc_info=True)


    @lru_cache(maxsize=10)
    def _find_label_id_for_label(self, label_name: str) -> str:
        logger.debug(f"Searching for label ID for label name: '{label_name}'")
        try:
            results = self.service.users().labels().list(userId=self.user_id).execute()
            labels = results.get("labels", [])
            for label in labels:
                if label_name.upper() in (label["name"].upper(), label["id"].upper()):
                    logger.debug(f"Found matching label: Name='{label['name']}', ID='{label['id']}'")
                    return label["id"]
        except HttpError as e:
            logger.error(f"API error while listing labels: {e}")
            raise ValueError(f"Could not retrieve labels to find '{label_name}'.") from e

        logger.error(f"Label '{label_name}' not found for user {self.user_id}.")
        raise ValueError(f"Label '{label_name}' not found.")