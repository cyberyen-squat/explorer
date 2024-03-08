## Explorer

An open-source web application for analyzing Cyberyen blockchain data metrics. This README provides detailed instructions for setting up and running the Explorer application on your system.

### Environment Setup

#### 1. Install Dependencies

- **Redis Server:**

		sudo apt-get install redis-server


- **Poetry (Python Dependency Management Tool):**

		curl -sSL https://install.python-poetry.org | python3 -


- **PostgreSQL (Database):**

		sudo apt-get install postgresql
		sudo -u postgres psql
		postgres=# create database db;
		postgres=# alter user postgres with encrypted password 'DO_NOT_USE_postgresql_db_password_DO_NOT_USE';
		postgres=# grant all privileges on database db to postgres;


#### 2. Clone Explorer Repository

*   Clone the Explorer repository:

		git clone https://github.com/cyberyen-squat/explorer


### Running Explorer

#### 1. Configure Explorer

*   Navigate to the Explorer directory:

		cd explorer


*   Edit the configuration file `app/config.py` with your text editor and add all necessary configurations. Here's how you can generate randomized keys for `app_key` or `csrf_key`:

		python

		>>> import secrets

		>>> alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
		>>> multiplier = secrets.choice(range(1, 16))
		>>> the_length = 64 * multiplier
		>>> new = [secrets.choice(alphabet) for x in range(1, the_length)]
		>>> print(''.join(new))



#### 2. Run Explorer

*   Install dependencies:

		poetry install


*   Load database:

		poetry run python app/first_run.py


*   Run Explorer using Gunicorn:

		poetry run gunicorn -w 4 app:application -b :<port>


### Setting up NGINX

#### 1. Install NGINX

		sudo apt-get install nginx


#### 2. Configure NGINX

*   Create a new NGINX configuration file:

		sudo $editor /etc/nginx/sites-available/explorer


*   Add the [provided NGINX configuration](docs/settings/explorer).


#### 3. Update NGINX Configuration

*   Edit the NGINX configuration file:

		sudo $editor /etc/nginx/nginx.conf


*   Add the additional [configurations provided](docs/settings/nginx.conf).


#### 3. Enable and Restart NGINX

		sudo ln -s /etc/nginx/sites-available/explorer /etc/nginx/sites-enabled/
		sudo systemctl restart nginx


### Setting up systemd for Production

#### 1. Create systemd Service File

		sudo $editor /etc/systemd/system/explorer.service

*   Copy and paste the [provided service configuration](docs/settings/explorer.service) into the file.


#### 2. Enable and Start Explorer Service

		sudo systemctl enable explorer
		sudo systemctl start explorer


Please ensure that you replace placeholders like `<port>`, `<user>`, `<password>`, `<group>`, and `IP_HERE` with actual values relevant to your system configuration.


### Contributing

Explorer is an open-source and community-driven software. The development process is open and publicly visible; anyone can see, discuss, and work on the software.

We welcome your feedback, questions, and suggestions! Feel free to connect with us:

- **GitHub Issues:** If you encounter any bugs or have feature requests, please open an issue on [GitHub](https://github.com/cyberyen-squat/explorer/issues).

- **Matrix:** Join our [c¥talk [Matrix]](https://matrix.to/#/#cykuza-cytalk:matrix.org) to see what's going on, meet people, discuss, learn about Cykuza & Cyberyen, give or ask for help, and share your ideas.

We value your input and strive to make Explorer a better tool for Cyberyen blockchain exploration and analysis. Don't hesitate to reach out!
