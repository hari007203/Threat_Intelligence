# Codebase Analysis Report

## Overview
The codebase is a **Django** web application titled "Threat Intelligence Sharing Platform Implementation using MISP". Its primary purpose is to allow employees to check whether a domain is safe to browse by classifying it using the **Maltiverse API**, and it provides administrators the ability to view and visualize these browsing activities.

## Project Structure
* **[manage.py](file:///c:/Users/Hari/OneDrive/Desktop/Threat%20Intelligence%20Sharing%20Platform%20Implementation%20using%20MISP/manage.py)**: Standard Django entry point script.
* **[test.py](file:///c:/Users/Hari/OneDrive/Desktop/Threat%20Intelligence%20Sharing%20Platform%20Implementation%20using%20MISP/test.py) & [test1.py](file:///c:/Users/Hari/OneDrive/Desktop/Threat%20Intelligence%20Sharing%20Platform%20Implementation%20using%20MISP/test1.py)**: Test scripts verifying the connection to Maltiverse API and basic functionality mapping domains to an IP address, then classifying them.
* **`ThreatSharing/`**: The core Django project directory containing [settings.py](file:///c:/Users/Hari/OneDrive/Desktop/Threat%20Intelligence%20Sharing%20Platform%20Implementation%20using%20MISP/ThreatSharing/settings.py), [urls.py](file:///c:/Users/Hari/OneDrive/Desktop/Threat%20Intelligence%20Sharing%20Platform%20Implementation%20using%20MISP/ThreatSharing/urls.py), and standard configuration.
* **`ThreatSharingApp/`**: The primary Django application where all the logic is contained.
  * **[views.py](file:///c:/Users/Hari/OneDrive/Desktop/Threat%20Intelligence%20Sharing%20Platform%20Implementation%20using%20MISP/ThreatSharingApp/views.py)**: Contains the business logic of the application.
  * **[urls.py](file:///c:/Users/Hari/OneDrive/Desktop/Threat%20Intelligence%20Sharing%20Platform%20Implementation%20using%20MISP/ThreatSharing/urls.py)**: Maps application routes to their corresponding views.
  * **[models.py](file:///c:/Users/Hari/OneDrive/Desktop/Threat%20Intelligence%20Sharing%20Platform%20Implementation%20using%20MISP/ThreatSharingApp/models.py)**: Currently empty (the app connects directly to MySQL via `pymysql` rather than using Django's ORM).

## Key Components
### 1. Authentication & Authorization
* **Admin Login**: Handles hardcoded admin authentication (`admin`/`admin`).
* **User Login**: Checks user credentials dynamically against an `employees` table in the database.

### 2. Threat Verification ([AccessPagesAction](file:///c:/Users/Hari/OneDrive/Desktop/Threat%20Intelligence%20Sharing%20Platform%20Implementation%20using%20MISP/ThreatSharingApp/views.py#106-137))
* Users submit a domain.
* The backend resolves the domain to an IP address (`socket.gethostbyname`).
* It interacts with root API queries to Maltiverse to get the classification.
* If safe, users receive a green link to proceed.
* Every interaction is logged into the `threats` database table.

### 3. Threat Visualization
* The app uses `matplotlib` to generate runtime bar charts describing employee activities. 
* The charts are converted to base64 images and rendered directly in HTML templates.

### 4. Direct Database Connection
* The platform skips the standard Django ORM mechanism ([models.py](file:///c:/Users/Hari/OneDrive/Desktop/Threat%20Intelligence%20Sharing%20Platform%20Implementation%20using%20MISP/ThreatSharingApp/models.py) is empty).
* It directly connects to a local MySQL instance (port 3306, user `root`, password `root`, database `threat`) using `pymysql`.

## Important Security Observations
While reviewing the code, several security vulnerabilities and bad practices were identified that you may want to address:
1. **Hardcoded API Token**: A `Maltiverse` API JWT token is hardcoded in [test.py](file:///c:/Users/Hari/OneDrive/Desktop/Threat%20Intelligence%20Sharing%20Platform%20Implementation%20using%20MISP/test.py) and [views.py](file:///c:/Users/Hari/OneDrive/Desktop/Threat%20Intelligence%20Sharing%20Platform%20Implementation%20using%20MISP/ThreatSharingApp/views.py). This should be moved to environment variables.
2. **Hardcoded Credentials**: The database credentials (`root`/`root`) and Admin login (`admin`/`admin`) are hardcoded.
3. **SQL Injection Vulnerabilities**: [views.py](file:///c:/Users/Hari/OneDrive/Desktop/Threat%20Intelligence%20Sharing%20Platform%20Implementation%20using%20MISP/ThreatSharingApp/views.py) executes query strings using raw string concatenation (e.g., `"select * from employees where username='"+uname+"' and password='"+password+"'"`). This makes the application highly susceptible to SQL injection attacks.
4. **No Password Hashing**: Passwords stored and checked during login appear to be stored as plaintext.

If you'd like me to help fix any of the aforementioned security issues or if you'd like me to look into a specific part of the codebase in more detail, just let me know!
