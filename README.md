# FractalAuth

![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

**FractalAuth** – A fun, secure, and visually appealing authentication solution that transforms SSH keys into unique, deterministic fractal patterns. By leveraging AES-256 encryption and advanced fractal mathematics, FractalAuth enhances security while making authentication an engaging and intuitive experience. 

Built to comply with the SSH standard, it supports all native SSH implementations, including key types, passwords, and authentication methods, ensuring seamless integration with existing workflows. FractalAuth provides additional layers of security beyond typical SSH keys by incorporating features such as error correction and offline storage, allowing users to securely access their credentials even in air-gapped environments. Users can authenticate effortlessly by scanning fractal patterns via a phone app, offering a stylish, secure, and resilient alternative to traditional authentication methods.

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Installation](#installation)
  - [Prerequisites](#prerequisites)
  - [Local Setup](#local-setup)
  - [Docker Deployment](#docker-deployment)
- [Usage](#usage)
  - [Command-Line Interface](#command-line-interface)
  - [API Interface](#api-interface)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [License](#license)
- [Continuous Integration](#continuous-integration)
- [Security Considerations](#security-considerations)

## Introduction

The Fractal Generator transforms SSH keys into unique Mandelbrot fractal images, enhancing security through visual obfuscation and error correction mechanisms.

## Features

- **SSH Key Generation:** Create secure SSH key pairs with customizable types and sizes.
- **Hashing & Encryption:** Securely hash and encrypt SSH keys using SHA-256 and AES-256 GCM.
- **Fractal Generation:** Convert encrypted hashes into high-resolution Mandelbrot fractal images.
- **Error Correction:** Integrate Reed-Solomon ECC for data integrity and key reconstruction.
- **Image Optimization:** Enhance fractal images for reliable scanning and key reconstruction.
- **Docker Support:** Easily build and deploy the application using Docker containers.

## Installation

### Prerequisites

Before proceeding, ensure you have the following installed:

- **Python 3.10+**: [Download Python](https://www.python.org/downloads/)
- **Git**: [Download Git](https://git-scm.com/downloads)
- **Docker**: [Download Docker](https://www.docker.com/get-started)
- **Docker Compose** (usually included with Docker Desktop)
- **GitHub CLI** (Optional for command-line operations): [Download GitHub CLI](https://cli.github.com/)

### Local Setup

1. **Clone the Repository:**

    ```bash
    git clone git@github.com:your-username/fractal-generator.git
    cd fractal-generator
    ```

2. **Set Up Virtual Environment:**

    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

3. **Install Dependencies:**

    ```bash
    pip install --upgrade pip
    pip install -r requirements.txt
    ```

4. **Configure Environment:**

    - Update `src/config/config.yaml` with necessary configurations.
    - Set up environment variables as needed, preferably using a `.env` file (ensure it's listed in `.gitignore`).

### Docker Deployment

Deploying the Fractal Generator using Docker simplifies the setup process and ensures consistency across different environments.

#### **a. Build the Docker Image**

Ensure you're in the root directory of the project where the `Dockerfile` is located.

```bash
docker build -t fractal-generator .
```

**Note:** Replace `fractal-generator` with your preferred image name.

#### **b. Run the Docker Container**

```bash
docker run -d \
  --name fractal-generator \
  -p 8000:8000 \
  -v $(pwd)/data/fractals/generated:/app/data/fractals/generated \
  -v $(pwd)/data/logs:/app/data/logs \
  -v $(pwd)/data/keys:/app/data/keys \
  -e ENV_VAR_NAME=value \ # Replace with actual environment variables
  fractal-generator
```

**Parameters Explained:**

- `-d`: Run the container in detached mode.
- `--name fractal-generator`: Assign a name to the container.
- `-p 8000:8000`: Map port 8000 of the container to port 8000 on the host (adjust if necessary).
- `-v`: Mount volumes for persistent storage:
  - `data/fractals/generated`: Stores generated fractal images.
  - `data/logs`: Stores application logs.
  - `data/keys`: Stores SSH keys.
- `-e ENV_VAR_NAME=value`: Set environment variables required by the application.
- `fractal-generator`: The name of the Docker image to run.

#### **c. Using Docker Compose (Optional)**

Docker Compose allows you to define and manage multi-container Docker applications. For the Fractal Generator, Docker Compose can simplify running the service with all its dependencies.

1. **Ensure `docker-compose.yml` is Present:**

    ```yaml
    version: '3.8'

    services:
      fractal-generator:
        build: .
        container_name: fractal-generator
        restart: unless-stopped
        ports:
          - "8000:8000" # Adjust based on your application
        volumes:
          - ./data/fractals/generated:/app/data/fractals/generated
          - ./data/logs:/app/data/logs
          - ./data/keys:/app/data/keys
        environment:
          - ENV_VAR_NAME=value # Replace with actual environment variables
    ```

2. **Start Services:**

    ```bash
    docker-compose up -d
    ```

3. **Stop Services:**

    ```bash
    docker-compose down
    ```

4. **Rebuild Services (if Dockerfile changes):**

    ```bash
    docker-compose up -d --build
    ```

#### **d. Managing Environment Variables**

Store sensitive configurations and environment variables securely. Consider using a `.env` file (ensure it's listed in `.dockerignore` and `.gitignore`).

**Example `.env`:**

```env
ENCRYPTION_KEY=your-encryption-key-here
DATABASE_URL=your-database-url
```

**Update `docker-compose.yml` to use `.env`:**

```yaml
version: '3.8'

services:
  fractal-generator:
    build: .
    container_name: fractal-generator
    restart: unless-stopped
    ports:
      - "8000:8000"
    volumes:
      - ./data/fractals/generated:/app/data/fractals/generated
      - ./data/logs:/app/data/logs
      - ./data/keys:/app/data/keys
    env_file:
      - .env
```

---

## Usage

### Command-Line Interface

Run the application using Python:

```bash
python src/main.py --key path/to/your/ssh_key
```

**Example:**

```bash
python src/main.py --key ~/.ssh/id_rsa
```

**Using Docker:**

If running via Docker, execute commands within the container:

```bash
docker exec -it fractal-generator python src/main.py --key /app/data/keys/private/id_rsa
```

**Note:** Ensure that the SSH key is correctly mounted to `/app/data/keys/private/id_rsa` in the container.

### API Interface

If your application exposes an API, refer to the [API Documentation](docs/api_reference.md) for endpoints and usage instructions.

**Access via Docker:**

If running via Docker, ensure you're accessing the correct port (e.g., `http://localhost:8000/api/endpoint`).

---

## Project Structure

Refer to the [Project Directory Structure](docs/architecture.md) for an overview of the codebase organization.

```plaintext
fractal-generator/
├── README.md
├── LICENSE
├── .gitignore
├── requirements.txt
├── setup.py
├── docs/
│   ├── index.md
│   ├── installation.md
│   ├── usage.md
│   ├── architecture.md
│   └── api_reference.md
├── src/
│   ├── __init__.py
│   ├── main.py
│   ├── config/
│   │   ├── __init__.py
│   │   └── config.yaml
│   ├── modules/
│   │   ├── __init__.py
│   │   ├── key_management/
│   │   │   ├── __init__.py
│   │   │   ├── key_validation.py
│   │   │   ├── key_generation.py
│   │   │   └── key_storage.py
│   │   ├── hashing/
│   │   │   ├── __init__.py
│   │   │   └── sha256_hashing.py
│   │   ├── encryption/
│   │   │   ├── __init__.py
│   │   │   └── aes256_gcm_encryption.py
│   │   ├── fractal/
│   │   │   ├── __init__.py
│   │   │   ├── mandelbrot.py
│   │   │   ├── julia.py
│   │   │   └── fractal_parameters.py
│   │   ├── ecc/
│   │   │   ├── __init__.py
│   │   │   └── reed_solomon_ecc.py
│   │   ├── image_processing/
│   │   │   ├── __init__.py
│   │   │   ├── color_correction.py
│   │   │   ├── noise_reduction.py
│   │   │   └── image_optimization.py
│   │   ├── error_handling/
│   │   │   ├── __init__.py
│   │   │   └── error_logger.py
│   │   └── utils/
│   │       ├── __init__.py
│   │       ├── file_io.py
│   │       ├── validation_utils.py
│   │       └── security_utils.py
│   ├── services/
│   │   ├── __init__.py
│   │   ├── storage_service.py
│   │   └── notification_service.py
│   └── interfaces/
│       ├── __init__.py
│       ├── api.py
│       └── cli.py
├── tests/
│   ├── __init__.py
│   ├── unit/
│   │   ├── __init__.py
│   │   ├── test_key_validation.py
│   │   ├── test_key_generation.py
│   │   ├── test_sha256_hashing.py
│   │   ├── test_aes256_gcm_encryption.py
│   │   ├── test_mandelbrot.py
│   │   ├── test_reed_solomon_ecc.py
│   │   └── test_image_optimization.py
│   ├── integration/
│   │   ├── __init__.py
│   │   ├── test_full_workflow.py
│   │   └── test_ecc_integration.py
│   └── mocks/
│       ├── __init__.py
│       ├── mock_key.py
│       └── mock_image.py
├── scripts/
│   ├── deploy.sh
│   ├── setup_env.sh
│   └── backup.sh
├── data/
│   ├── logs/
│   │   └── app.log
│   ├── fractals/
│   │   └── generated/
│   └── keys/
│       ├── private/
│       └── public/
├── config/
│   └── default_config.yaml
├── .dockerignore
├── Dockerfile
├── docker-compose.yml
└── .github/
    └── workflows/
        └── ci.yml
```

## Contributing

Contributions are welcome! Please read the [Contributing Guidelines](CONTRIBUTING.md) first.

## License

This project is licensed under the [Apache License 2.0](LICENSE).

## Continuous Integration

The project utilizes **GitHub Actions** for continuous integration to ensure code quality and reliability.

### GitHub Actions Workflow

Located at `.github/workflows/ci.yml`, the CI workflow performs the following on each push and pull request to the `main` branch:

1. **Checks Out the Repository**
2. **Sets Up Python 3.10 Environment**
3. **Installs Dependencies**
4. **Runs Unit and Integration Tests**

#### Example Workflow File (`.github/workflows/ci.yml`):

```yaml
name: CI

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  build:

    runs-on: ubuntu-latest

    steps:
    - uses: actions/checkout@v3

    - name: Set up Python 3.10
      uses: actions/setup-python@v4
      with:
        python-version: '3.10'

    - name: Install dependencies
      run: |
        python -m venv venv
        source venv/bin/activate
        pip install --upgrade pip
        pip install -r requirements.txt

    - name: Run tests
      run: |
        source venv/bin/activate
        pytest
```

## Security Considerations

Given the security-centric nature of the Fractal Generator, the following measures are implemented:

- **Data Protection:**
  - SSH keys and fractal images are stored securely with strict access controls.
  - Encryption keys and sensitive configurations are managed via environment variables.

- **Audit Logging:**
  - Comprehensive logging captures all critical actions and decisions for auditing and compliance.

- **Error Handling:**
  - Error messages do not leak sensitive information.
  - All error logs are stored securely.

- **Dependency Management:**
  - Regularly update dependencies to mitigate known vulnerabilities.
  - Use tools like **Dependabot** for automated dependency checks.

- **Static Code Analysis:**
  - Implement tools like **Bandit** to analyze Python code for security vulnerabilities.

- **Secure Docker Practices:**
  - Use minimal base images (e.g., `python:3.10-slim`) to reduce attack surface.
  - Avoid running containers as the root user.
  - Regularly update Docker images to include security patches.

---
