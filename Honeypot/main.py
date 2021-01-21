from http_handler import HTTPRouter

# TODO: Move to config file
ASSET_IP = "10.0.0.12"
ASSET_PORT = 8080
FAKE_ASSET_PORT = 8000

HONEYPOT_IP = "10.0.0.12"
HONEYPOT_PORT = 8081


def main():
    http_router = HTTPRouter(ASSET_IP, ASSET_PORT,
                             HONEYPOT_IP, HONEYPOT_PORT, FAKE_ASSET_PORT)
    http_router.start()


if __name__ == "__main__":
    main()
