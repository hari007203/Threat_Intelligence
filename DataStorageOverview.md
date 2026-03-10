# Data Storage and Logic Overview

In your Threat Intelligence platform, data is organized into two main categories: **User Management** (who can log in) and **Threat Intelligence Logs** (what they are doing).

## 1. How Login Data is Stored

### Employee Data
Every time you use the "Add Employee" screen, a new record is saved to the **MySQL Database**.
- **Table Name**: `employees` (See [db.txt:L4-11](file:///c:/Users/Hari/OneDrive/Desktop/Threat%20Intelligence%20Sharing%20Platform%20Implementation%20using%20MISP/db.txt#L4-L11))
- **Stored Information**: Username, Password, Email, Phone, Department, etc.
- **How it works**: When an employee logs in, the platform runs a query (`SELECT * FROM employees ...`) to verify them. (See the check logic in [views.py:L284-296](file:///c:/Users/Hari/OneDrive/Desktop/Threat%20Intelligence%20Sharing%20Platform%20Implementation%20using%20MISP/ThreatSharingApp/views.py#L284-L296))

### Admin Data
For security and simplicity, the Admin account is **not** stored in the database.
- **Username**: `admin`
- **Password**: `admin`
- **How it works**: This is hardcoded directly into the `AdminLoginAction` function. (See [views.py:L331](file:///c:/Users/Hari/OneDrive/Desktop/Threat%20Intelligence%20Sharing%20Platform%20Implementation%20using%20MISP/ThreatSharingApp/views.py#L331))

---

## 2. The Threat Sharing Sheet (`ViewShareThreat`)

The page you see at `http://127.0.0.1:8000/ViewShareThreat` is the core of the "Sharing" part of your platform.

### How Data is Logged
Every time an employee enters a URL in the "Access Web Resources" page, the platform performs these steps:
1. It looks up the domain checking local lists and API. (See [views.py:L142-213](file:///c:/Users/Hari/OneDrive/Desktop/Threat%20Intelligence%20Sharing%20Platform%20Implementation%20using%20MISP/ThreatSharingApp/views.py#L142-L213))
2. It generates a **Status** (e.g., `malicious`, `whitelist`, or `safe`).
3. It automatically calls a function named `logMalware()`. (See [views.py:L99-106](file:///c:/Users/Hari/OneDrive/Desktop/Threat%20Intelligence%20Sharing%20Platform%20Implementation%20using%20MISP/ThreatSharingApp/views.py#L99-L106))
4. This function **INSERT**s a new row into the **`threats` table**. (See [db.txt:L13-17](file:///c:/Users/Hari/OneDrive/Desktop/Threat%20Intelligence%20Sharing%20Platform%20Implementation%20using%20MISP/db.txt#L13-L17))

### What you see in the Sheet
The "View Share Threat" page simply pulls everything from that `threats` table. (See [views.py:L76-97](file:///c:/Users/Hari/OneDrive/Desktop/Threat%20Intelligence%20Sharing%20Platform%20Implementation%20using%20MISP/ThreatSharingApp/views.py#L76-L97))
- **Employee Name**: The username of whoever performed the check.
- **Visiting Domain**: The URL they were investigating.
- **Classification**: The result from Maltiverse/Blocklist.
- **Activity Type**: Usually "Browsing [Domain]".
- **Activity Date**: The exact timestamp of the check.

---

## 3. Database Summary (MySQL)
Your `threat` database has these two tables:

| Table | Purpose | Main Fields |
| :--- | :--- | :--- |
| `employees` | Stores login & profiles | `username`, `password`, `department` |
| `threats` | Stores all security logs | `visiting_url`, `url_classification`, `activity_date` |

> [!TIP]
> This shared `threats` table is what allows all employees to "share" intelligence. If Employee A finds a malicious site, Employee B can see it instantly on the `ViewShareThreat` page!
---

## 4. How the Graph is Generated (`VisualizeThreat`)
The "Employee Activities Graph" you see at `http://127.0.0.1:8000/VisualizeThreat` is a dynamic data visualization.

### The Technical Process:
1. **Query Data**: The platform selects all `url_classification` values from the `threats` table. (See [views.py:L28](file:///c:/Users/Hari/OneDrive/Desktop/Threat%20Intelligence%20Sharing%20Platform%20Implementation%20using%20MISP/ThreatSharingApp/views.py#L28))
2. **Count Totals**: It uses the `numpy` library to count how many times each result (malicious, neutral, etc.) appears. (See [views.py:L34](file:///c:/Users/Hari/OneDrive/Desktop/Threat%20Intelligence%20Sharing%20Platform%20Implementation%20using%20MISP/ThreatSharingApp/views.py#L34))
3. **Draw Graph**: It uses `matplotlib` to draw a bar chart based on those counts. (See [views.py:L38-43](file:///c:/Users/Hari/OneDrive/Desktop/Threat%20Intelligence%20Sharing%20Platform%20Implementation%20using%20MISP/ThreatSharingApp/views.py#L38-L43))
4. **Convert to Image**: Instead of saving a file, the graph is converted into a **Base64 string** (a text version of an image).
5. **Display**: This text string is sent to your browser, which converts it back into the picture you see! (See [views.py:L44-50](file:///c:/Users/Hari/OneDrive/Desktop/Threat%20Intelligence%20Sharing%20Platform%20Implementation%20using%20MISP/ThreatSharingApp/views.py#L44-L50))
