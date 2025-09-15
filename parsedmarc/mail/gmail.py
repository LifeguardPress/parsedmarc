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

from parsedmarc.log import logger
from parsedmarc.mail.mailbox_connection import MailboxConnection


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
        logger.debug(
            f"Using service account file {service_account_file} to impersonate {delegated_account}"
        )
        return service_account.Credentials.from_service_account_file(
            service_account_file, scopes=scopes
        ).with_subject(delegated_account)

    # Fallback to OAuth 2.0 user consent flow
    logger.debug("Using OAuth 2.0 user consent flow")
    creds = None
    if Path(token_file).exists():
        creds = Credentials.from_authorized_user_file(token_file, scopes)

    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(credentials_file, scopes)
            creds = flow.run_local_server(open_browser=False, port=oauth2_port)
        # Save the credentials for the next run
        with Path(token_file).open("w") as token:
            token.write(creds.to_json())
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
        creds = _get_creds(
            token_file,
            credentials_file,
            scopes,
            oauth2_port,
            service_account_file,
            delegated_account,
        )
        self.service = build("gmail", "v1", credentials=creds)
        self.include_spam_trash = include_spam_trash
        self.paginate_messages = paginate_messages

        # Set user_id for API calls ("me" or the delegated account's email)
        self.user_id = delegated_account if delegated_account else "me"
        self.reports_label_id = self._find_label_id_for_label(reports_folder)

    def create_folder(self, folder_name: str):
        # Gmail uses labels instead of folders. The name "Archive" is reserved.
        if folder_name == "Archive":
            return

        logger.debug(f"Creating label {folder_name}")
        request_body = {"name": folder_name, "messageListVisibility": "show"}
        try:
            self.service.users().labels().create(
                userId=self.user_id, body=request_body
            ).execute()
        except HttpError as e:
            if e.status_code == 409:
                logger.debug(f"Label {folder_name} already exists, skipping creation")
            else:
                raise e

    def _fetch_all_message_ids(self, reports_label_id, page_token=None, since=None):
        query_params = {
            "userId": self.user_id,
            "includeSpamTrash": self.include_spam_trash,
            "labelIds": [reports_label_id],
            "pageToken": page_token,
        }
        if since:
            query_params["q"] = f"after:{since}"

        results = self.service.users().messages().list(**query_params).execute()
        messages = results.get("messages", [])
        for message in messages:
            yield message["id"]

        if "nextPageToken" in results and self.paginate_messages:
            yield from self._fetch_all_message_ids(
                reports_label_id, results["nextPageToken"], since=since
            )

    def fetch_messages(self, reports_folder: str, **kwargs) -> List[str]:
        reports_label_id = self._find_label_id_for_label(reports_folder)
        since = kwargs.get("since")
        return list(self._fetch_all_message_ids(reports_label_id, since=since))

    def fetch_message(self, message_id):
        msg = (
            self.service.users()
            .messages()
            .get(userId=self.user_id, id=message_id, format="raw")
            .execute()
        )
        return urlsafe_b64decode(msg["raw"])

    def delete_message(self, message_id: str):
        self.service.users().messages().delete(
            userId=self.user_id, id=message_id
        ).execute()

    def move_message(self, message_id: str, folder_name: str):
        label_id = self._find_label_id_for_label(folder_name)
        logger.debug(f"Moving message ID {message_id} to {folder_name}")
        request_body = {
            "addLabelIds": [label_id],
            "removeLabelIds": [self.reports_label_id],
        }
        self.service.users().messages().modify(
            userId=self.user_id, id=message_id, body=request_body
        ).execute()

    def keepalive(self):
        # Not needed for the Gmail API
        pass

    def watch(self, check_callback, check_timeout):
        """Checks the mailbox for new messages every n seconds."""
        while True:
            sleep(check_timeout)
            check_callback(self)

    @lru_cache(maxsize=10)
    def _find_label_id_for_label(self, label_name: str) -> str:
        results = self.service.users().labels().list(userId=self.user_id).execute()
        labels = results.get("labels", [])
        for label in labels:
            if label_name.upper() == label["name"].upper() or label_name.upper() == label["id"].upper():
                return label["id"]
        raise ValueError(f"Label '{label_name}' not found.")