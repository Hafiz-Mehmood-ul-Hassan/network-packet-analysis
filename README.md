# Python Network Monitoring & Authentication Prototype

This project is a small Python-based prototype that combines two ideas:

- a Tkinter login interface that connects to a backend login endpoint
- a network monitoring script that uses Tshark to detect TLS handshakes and monitor selected hosts

It is designed as a learning and portfolio project for demonstrating Python networking, GUI development, and basic API integration.

## Features

- Desktop login form with username and password input
- Signup page redirect using the default browser
- Network interface detection
- TLS handshake monitoring
- Basic connection tracking and event reporting

## Project Files

- auth.py - Simple Tkinter login application
- connection.py - Initial network interface and packet monitoring experiments
- second.py - More advanced connection monitoring and reporting logic
- requirements.txt - Python dependencies

## Technologies Used

- Python 3
- Tkinter
- Requests
- Tshark / Wireshark

## Setup

1. Clone the repository
2. Create and activate a virtual environment
3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Install Wireshark/Tshark and make sure `tshark` is available in your PATH
5. Update interface names and API URLs in the scripts if needed

## Running the Project

Run the login application:

```bash
python auth.py
```

Run the monitoring script:

```bash
python second.py
```

## Notes

- Packet capture may require administrator privileges depending on your system
- Some values such as API URLs, interface names, and JWT tokens should be adjusted to your environment
- This project is intended as a prototype and can be expanded for a more complete security or networking tool

## License

This project is open for personal and educational use.
