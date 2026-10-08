import argparse
import socket
import time

HOST = "127.0.0.1"
PORT = 8000

def generate_connections(count):
    successful = 0

    for i in range(count):
        try:
            with socket.create_connection(
                (HOST, PORT),
                timeout=5
            ) as connection:

                request = (
                    b"GET / HTTP/1.0\r\n"
                    b"Host: localhost\r\n"
                    b"Connection: close\r\n\r\n"
                )

                connection.sendall(request)
        
                while connection.recv(4096):
                    pass

                successful += 1

                print(
                    f"Connection {i + 1}/{count}: SUCCESS"
                )

            time.sleep(0.2)

        except OSError as error:
            print(
                f"Connection {i + 1}/{count}: FAILED - {error}"
            )

    print(f"\nSuccessful connections: {successful}/{count}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--count",
        type=int,
        default=15
    )

    args = parser.parse_args()

    if args.count < 1:
        parser.error("count must be at least 1")

    generate_connections(args.count)
