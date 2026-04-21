RUN INSTRUCTIONS FOR LOCAL DEPLOYMENT OF PostGuard-WordPress

CREATED INCASE THE VM LINK IS UNAVAILABLE USED TO SET UP THE WEB APPLICATION LOCALLY

Requirements:

Docker Desktop needs to be installed and running 
[https://www.docker.com/products/docker-desktop/]

Port 80 must be free for the PostGuard-WordPress UI and port 8081 must be free for the WordPress instance.


When Docker Desktop is set up open the terminal in the project folder 
and Run:

    Copy-Item .env.example .env -Force

Then:

    docker compose up --build -d

If you've run the project previously with different environmental values and are having issues, run:

    docker compose down -v

    docker compose up --build -d


Links:

PostGuard-WordPress UI: https://localhost/

PostGuard-WordPress Dev UI: https://localhost/dev

WordPress instance to trigger events and create new incidents: http://localhost:8081/wp-admin

Link to MailHog when local testing alerts and registration invites: https://localhost:8025

Credentials:

Credentials for PostGuard-WordPress Admin User:
Email = admin@example.local
Password = change_me

Credentials for PostGuard-WordPress Analyst User:
Email = analyst@example.local
Password = change_me

Credentials for WordPress Admin User:
Username = admin
Email = admin@example.local
Password = change_me

To stop the project after running:

    docker compose down




