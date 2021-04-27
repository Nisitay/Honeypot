import re
from urllib.parse import unquote


def get_http_content(payload: bytes) -> re.Match:
    """
    Returns a regex match for content in a
    HTTP request

    Args:
        payload (bytes): TCP payload - HTTP request

    Returns:
        re.Match: Returns the match or none if not found
    """
    pattern = b"\r\n\r\n(?P<content>(.|\s)*)"
    return re.search(pattern, payload)


def get_content_length(header: bytes) -> int:
    """
    Returns the content length found in the given
    payload.

    Args:
        header (bytes): HTTP headers

    Returns:
        int: Content length
    """
    pattern = b"Content-Length: (?P<content_length>\d*)"
    match = re.search(pattern, header)
    return int(match.group("content_length")) if match else 0


def get_login_creds(payload: bytes) -> re.Match:
    """
    Returns a regex match for login credentials in an
    HTTP request

    Args:
        payload (bytes): HTTP payload, as bytes

    Returns:
        re.Match: Returns the match or none if not found
    """
    pattern = b"email=(?P<email>.*)&password=(?P<password>.*)&submit=Log\+In"
    return re.search(pattern, payload)


def get_register_creds(payload: bytes) -> list:
    """
    Returns credentials used within the payload to register.

    Args:
        payload (bytes): HTTP payload, as bytes

    Returns:
        list: [username, email, password] used for registering
    """
    pattern = b"username=(?P<username>.*)&email=(?P<email>.*)&password=(?P<password>.*)&confirm_password=.*&submit=Sign\+Up"
    register_match = re.search(pattern, payload)
    if not register_match:
        return [None, None, None]
    return [unquote(cred.decode()) for cred in register_match.groups()]


def finished_request(payload: str, content_length: int) -> bool:
    """
    Checks whether an HTTP request is finished

    Args:
        payload (bytes): full HTTP request
        content_length (int): HTTP content Length

    Returns:
        bool: Finished/unfinished request
    """
    content_match = get_http_content(payload)
    if not content_match or len(content_match.group("content")) < content_length:
        return False
    return True
