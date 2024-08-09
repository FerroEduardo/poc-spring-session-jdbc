<div align="center">

# POC Spring Session JDBC

</div>

<div align="center">

[![build](https://github.com/FerroEduardo/poc-spring-session-jdbc/actions/workflows/build.yaml/badge.svg)](https://github.com/FerroEduardo/poc-spring-session-jdbc/actions/workflows/build.yaml)

</div>


This repository contains a Proof of Concept (POC) project demonstrating how to use Spring Session with JDBC for session
management. The project also includes user authentication via username/password and OAuth2 using Google.

## Features

- **Spring Boot 3.3.2**
- **Spring Session JDBC** for session management
- **Java 21**
- **PostgreSQL** as the database
- **User authentication** via:
    - Username and password
    - OAuth2 with Google

## Getting Started

### Prerequisites

Before running the project, you need to configure the following environment variables:

#### Database Configuration

- `DATABASE_URL`: The JDBC URL for your PostgreSQL database.
- `DATABASE_USERNAME`: The username for accessing your database.
- `DATABASE_PASSWORD`: The password for accessing your database.

#### Google OAuth 2.0 Configuration

- `OAUTH_GOOGLE_CLIENT_ID`: The Client ID obtained from the Google Cloud Console.
- `OAUTH_GOOGLE_CLIENT_SECRET`: The Client Secret obtained from the Google Cloud Console.

### Google OAuth 2.0 Setup

To use Google OAuth 2.0, you must first create a project in
the [Google Cloud Console](https://console.cloud.google.com/) and generate OAuth 2.0 credentials (Client ID and Client
Secret).

### Database Schema

If the database user does not have permissions to create tables, you can manually create them using
the [SQL scripts provided by Spring Session](https://github.com/spring-projects/spring-session/tree/main/spring-session-jdbc/src/main/resources/org/springframework/session/jdbc).
Note that other databases besides PostgreSQL can also be used with this project.

## Endpoints

| Endpoint                                  | Description                                                                               |
|-------------------------------------------|-------------------------------------------------------------------------------------------|
| **`/user/me`**                            | Returns information about the current session.                                            |
| **`/auth/sign-in`**                       | Allows users to log in via POST, sending a JSON with `username` and `password` fields.    |
| **`/auth/sign-out`**                      | Invalidates the current session.                                                          |
| **`/auth/sign-in/oauth/google`**          | Redirects users to the Google login page.                                                 |
| **`/auth/sign-in/oauth/google/callback`** | Callback endpoint that receives credentials from Google and uses them for authentication. |

## Customization

The default in-memory user details can be modified in
the [`AuthenticationConfig.java`](src/main/java/org/example/pocspringsessionjdbc/config/AuthenticationConfig.java) file.
You can
also [configure other `UserDetailsService`](https://www.baeldung.com/spring-security-authentication-with-a-database)
implementations to retrieve users from different sources, such as a database.

## Extensibility

Other OAuth2 providers can be easily added by creating a new filter. Additionally, better abstractions could be applied
to further improve the flexibility and maintainability of the code.

## Observations

- **Google User Token:** User information from Google could be extracted directly from the `access_token` itself,
  instead of making a call to the Google `userinfo` endpoint.
 